import os
import pty
import json
import select
import shutil
import asyncio
import datetime
from typing import Optional

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Request, BackgroundTasks,
    Form, HTTPException,
)
from fastapi.responses import HTMLResponse, FileResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

import auth

app = FastAPI()

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(_THIS_DIR, "templates"))

# sudarshan.py lives one directory UP from this file (this file is in
# web_terminal/, sudarshan.py is in the project root next to it) - confirmed
# against the actual on-disk layout, not assumed. A prior bug had this
# pointed one directory too HIGH (see FRONTEND_SESSION_HANDOFF.md fix #2);
# don't swing back to "same directory as this file" without re-checking
# `ls` first if the layout ever moves again.
SUDARSHAN_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))

RAMDISK_DIR = os.environ.get(
    "SUDARSHAN_RESULTS_DIR", os.path.join(os.path.expanduser("~"), "sudarshan-results")
)

SESSION_HISTORY_FILE = os.environ.get(
    "SUDARSHAN_SESSION_HISTORY_FILE", os.path.join(_THIS_DIR, "web_sessions.json")
)

DOWNLOAD_COUNT_FILE = os.environ.get(
    "SUDARSHAN_DOWNLOAD_COUNT_FILE", os.path.join(_THIS_DIR, "download_count.json")
)

COOKIE_NAME = "sudarshan_token"
# Disable only for local HTTP-only dev testing (no TLS yet). In any real
# deployment (behind Cloudflare Tunnel per the roadmap) this must stay
# true, or the browser will silently refuse to send the cookie at all.
COOKIE_SECURE = os.environ.get("SUDARSHAN_COOKIE_SECURE", "true").strip().lower() not in ("0", "false", "no")

# A 2 OCPU/12GB OCI box running qwen2.5:7b-instruct plus an active nmap/
# searchsploit run cannot comfortably serve many concurrent scan sessions -
# reject new connections past this cap rather than degrade silently.
MAX_CONCURRENT_SESSIONS = int(os.environ.get("SUDARSHAN_MAX_CONCURRENT_SESSIONS", "2"))

# Per-user scan quota (Phase 7, partial - full target allowlisting was
# explicitly deferred per project decision; this control stands on its
# own regardless of that). Read from the persisted session-history file
# rather than an in-memory counter, so the window survives a server
# restart instead of quietly resetting everyone's quota to zero.
RATE_LIMIT_PER_HOUR = int(os.environ.get("SUDARSHAN_RATE_LIMIT_PER_HOUR", "5"))

# session_id -> {"user": str, "started_at": iso str, "status": "running"}
# In-memory only - active-session state doesn't need to survive a restart,
# a restart kills the actual pty processes anyway.
ACTIVE_SESSIONS = {}
_session_counter = 0


# ----------------------------------------------------------------------------
# Session history (persisted JSON - survives server restarts, backs the
# Dashboard's history table via /api/sessions)
# ----------------------------------------------------------------------------


def _load_session_history():
    if not os.path.isfile(SESSION_HISTORY_FILE):
        return []
    try:
        with open(SESSION_HISTORY_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return []


def _save_session_history(history):
    try:
        with open(SESSION_HISTORY_FILE, "w") as f:
            # Cap growth - this is a rolling operational log, not a
            # permanent audit trail (Phase 7 adds a real durable audit log).
            json.dump(history[-500:], f, indent=2)
    except OSError as e:
        print(f"[Session history] Could not persist: {e}")


def _record_session_event(session_id, user, event, extra=None):
    history = _load_session_history()
    if event == "started":
        history.append({
            "id": session_id,
            "user": user,
            "started_at": datetime.datetime.now().isoformat(),
            "ended_at": None,
            "status": "running",
        })
    elif event == "ended":
        for entry in history:
            if entry["id"] == session_id and entry["ended_at"] is None:
                entry["ended_at"] = datetime.datetime.now().isoformat()
                entry["status"] = "completed"
                if extra:
                    entry.update(extra)
                break
    _save_session_history(history)


def _count_recent_sessions(user, window_hours=1):
    """How many sessions `user` has STARTED in the last `window_hours`,
    read from the persisted history file (not an in-memory counter) so a
    server restart doesn't reset everyone's quota to zero."""
    cutoff = datetime.datetime.now() - datetime.timedelta(hours=window_hours)
    count = 0
    for entry in _load_session_history():
        if entry.get("user") != user:
            continue
        started_at = entry.get("started_at")
        if not started_at:
            continue
        try:
            ts = datetime.datetime.fromisoformat(started_at)
        except ValueError:
            continue
        if ts >= cutoff:
            count += 1
    return count


def _list_completed_targets():
    """Scan RAMDISK_DIR the same way sudarshan.py's own view_results()
    does, and surface each target's metadata for the Dashboard table."""
    targets = []
    if not os.path.isdir(RAMDISK_DIR):
        return targets
    for name in sorted(os.listdir(RAMDISK_DIR)):
        tdir = os.path.join(RAMDISK_DIR, name)
        if not os.path.isdir(tdir) or name.startswith("."):
            continue
        info_path = os.path.join(tdir, "target_info.txt")
        raw_target, friendly_name, last_used = name, name, None
        if os.path.isfile(info_path):
            try:
                with open(info_path) as f:
                    for line in f:
                        if line.startswith("raw_target:"):
                            raw_target = line.split(":", 1)[1].strip()
                        elif line.startswith("friendly_name:"):
                            fn = line.split(":", 1)[1].strip()
                            if fn and not fn.startswith("(none"):
                                friendly_name = fn
                        elif line.startswith("last_used:"):
                            last_used = line.split(":", 1)[1].strip()
            except OSError:
                pass
        targets.append({
            "target_name": name,
            "raw_target": raw_target,
            "friendly_name": friendly_name,
            "last_used": last_used,
            "status": "completed",
        })
    targets.sort(key=lambda t: t["last_used"] or "", reverse=True)
    return targets


def _find_session_for_user(user):
    """A user has at most one active session at a time - keeps 'resume my
    session' unambiguous. Returns the session_id or None."""
    for sid, info in ACTIVE_SESSIONS.items():
        if info["user"] == user:
            return sid
    return None


def _load_download_count():
    if not os.path.isfile(DOWNLOAD_COUNT_FILE):
        return 0
    try:
        with open(DOWNLOAD_COUNT_FILE) as f:
            return json.load(f).get("total_downloads", 0)
    except (json.JSONDecodeError, OSError):
        return 0


def _increment_download_count():
    count = _load_download_count() + 1
    try:
        with open(DOWNLOAD_COUNT_FILE, "w") as f:
            json.dump({"total_downloads": count}, f)
    except OSError as e:
        print(f"[Download count] Could not persist: {e}")
    return count


def _compute_stats():
    """Small dashboard-widget numbers. total_scans comes from the
    persisted history (so it stays accurate even after a target's folder
    is deleted post-download) rather than counting on-disk folders."""
    return {
        "total_scans": len(_load_session_history()),
        "active_now": len(ACTIVE_SESSIONS),
        "stored_results": len(_list_completed_targets()),
        "total_downloads": _load_download_count(),
    }


def cleanup_target_data(target_name: str, zip_path: str):
    target_dir = os.path.join(RAMDISK_DIR, target_name)
    try:
        if os.path.exists(zip_path):
            os.remove(zip_path)
            print(f"[Cleanup] Deleted zip: {zip_path}")
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)
            print(f"[Cleanup] Deleted raw directory: {target_dir}")
    except Exception as e:
        print(f"[Cleanup Error] {e}")


# ----------------------------------------------------------------------------
# Auth helper
# ----------------------------------------------------------------------------


def get_current_user(request: Request) -> Optional[str]:
    token = request.cookies.get(COOKIE_NAME)
    return auth.verify_token(token)


# ----------------------------------------------------------------------------
# Auth routes
# ----------------------------------------------------------------------------


@app.get("/login", response_class=HTMLResponse)
async def get_login(request: Request):
    if get_current_user(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": None})


@app.post("/login")
async def post_login(request: Request, username: str = Form(...), password: str = Form(...)):
    try:
        ok = auth.verify_password(username, password)
    except RuntimeError as e:
        # bcrypt/pyjwt missing, or SUDARSHAN_JWT_SECRET unset - surface
        # this clearly instead of a generic 500 the operator has to dig for.
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": f"Server auth is misconfigured: {e}"},
            status_code=500,
        )
    if not ok:
        return templates.TemplateResponse(
            request=request, name="login.html",
            context={"error": "Invalid username or password."},
            status_code=401,
        )
    token = auth.create_token(username)
    response = RedirectResponse(url="/", status_code=303)
    # Deliberately NO max_age/expires - this makes it a browser "session
    # cookie", which the browser discards when the browser itself closes
    # (not on every single tab close - cookies are shared across all tabs
    # of the same browser, so closing one tab while another is still open
    # can't log the whole browser out; that's not something a cookie can
    # express). This is the closest real mechanism to "logged out next
    # time you open it" - opening a fresh browser window/session requires
    # login again, exactly like requested. The JWT itself still carries a
    # server-side expiry (auth.JWT_EXPIRY_HOURS) as a hard backstop in
    # case the cookie somehow survives longer than intended.
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="strict",
    )
    return response


@app.get("/logout")
async def get_logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(COOKIE_NAME)
    return response


# ----------------------------------------------------------------------------
# Page routes (all require auth; redirect to /login instead of erroring)
# ----------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={"username": user, "max_concurrent": MAX_CONCURRENT_SESSIONS, "active_page": "dashboard"},
    )


@app.get("/terminal", response_class=HTMLResponse)
async def get_terminal(request: Request):
    user = get_current_user(request)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        request=request, name="terminal.html", context={"username": user, "active_page": "terminal"},
    )


# ----------------------------------------------------------------------------
# Session API (backs the Dashboard's history table)
# ----------------------------------------------------------------------------


@app.get("/api/sessions")
async def api_sessions(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    # Don't leak raw fd/pid numbers to the client - only the fields the
    # frontend actually needs.
    active = [
        {"id": sid, "user": info["user"], "started_at": info["started_at"], "status": info["status"]}
        for sid, info in ACTIVE_SESSIONS.items()
    ]
    return JSONResponse({
        "active_sessions": active,
        "completed_targets": _list_completed_targets(),
        "max_concurrent": MAX_CONCURRENT_SESSIONS,
        "stats": _compute_stats(),
    })


@app.post("/api/session/end")
async def api_end_session(request: Request):
    """Explicitly kill the CURRENT user's running session, if any. This is
    the only thing that actually terminates the pty process - a plain
    websocket disconnect (tab closed, navigated to Dashboard) leaves it
    running in the background so the user can reattach later."""
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    sid = _find_session_for_user(user)
    if not sid:
        return JSONResponse({"error": "no active session"}, status_code=404)
    info = ACTIVE_SESSIONS.pop(sid)
    try:
        os.kill(info["pid"], 9)
        os.waitpid(info["pid"], 0)
    except OSError:
        pass
    try:
        os.close(info["master_fd"])
    except OSError:
        pass
    _record_session_event(sid, user, "ended")
    return JSONResponse({"ended": sid})


@app.delete("/api/sessions/{target_name}")
async def api_delete_session(target_name: str, request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)
    safe_name = os.path.basename(target_name)
    target_dir = os.path.join(RAMDISK_DIR, safe_name)
    if not os.path.isdir(target_dir):
        return JSONResponse({"error": f"Target '{safe_name}' not found."}, status_code=404)
    try:
        shutil.rmtree(target_dir)
    except OSError as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"deleted": safe_name})


# ----------------------------------------------------------------------------
# Download (protected - was previously reachable by anyone who knew a
# target name)
# ----------------------------------------------------------------------------


@app.get("/download/{target_name}")
async def download_results(target_name: str, request: Request, background_tasks: BackgroundTasks):
    user = get_current_user(request)
    if not user:
        return JSONResponse({"error": "not authenticated"}, status_code=401)

    safe_name = os.path.basename(target_name)
    target_dir = os.path.join(RAMDISK_DIR, safe_name)
    if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
        raise HTTPException(status_code=404, detail=f"Target directory for '{safe_name}' not found.")

    zip_base_path = os.path.join(RAMDISK_DIR, safe_name)
    zip_path = shutil.make_archive(zip_base_path, 'zip', target_dir)
    _increment_download_count()
    background_tasks.add_task(cleanup_target_data, safe_name, zip_path)
    return FileResponse(
        path=zip_path,
        media_type='application/zip',
        filename=f"{safe_name}_results.zip",
    )


# ----------------------------------------------------------------------------
# Terminal websocket (protected - auth is checked BEFORE pty.openpty()/
# fork() ever run, not after; an unauthenticated connection never gets a
# real shell process spun up for it)
# ----------------------------------------------------------------------------


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    token = websocket.cookies.get(COOKIE_NAME)
    user = auth.verify_token(token)
    if not user:
        await websocket.close(code=4401)  # custom close code: unauthenticated
        return

    # If this user already has a session running in the background (they
    # navigated to Dashboard or closed the tab without clicking "End
    # Session"), reattach to it instead of spawning a second one. Rate
    # limit / concurrency checks only apply to genuinely NEW sessions -
    # reattaching to your own existing session never counts against them.
    existing_id = _find_session_for_user(user)

    if existing_id:
        session_id = existing_id
        info = ACTIVE_SESSIONS[session_id]
        master_fd = info["master_fd"]
        pid = info["pid"]
        is_reattach = True
    else:
        if _count_recent_sessions(user) >= RATE_LIMIT_PER_HOUR:
            await websocket.close(code=4430)  # custom close code: per-user rate limit exceeded
            return
        if len(ACTIVE_SESSIONS) >= MAX_CONCURRENT_SESSIONS:
            await websocket.close(code=4429)  # custom close code: too many concurrent sessions
            return

        master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env["SUDARSHAN_RESULTS_DIR"] = RAMDISK_DIR
        env["SUDARSHAN_WEB_USER"] = user

        try:
            pid = os.fork()
        except OSError as e:
            os.close(master_fd)
            os.close(slave_fd)
            await websocket.accept()
            try:
                await websocket.send_text(f"\r\n[!] Server could not start a session: {e}\r\n")
            except Exception:
                pass
            await websocket.close()
            return

        if pid == 0:
            # Child process
            os.setsid()
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if master_fd > 2:
                os.close(master_fd)
            if slave_fd > 2:
                os.close(slave_fd)
            os.chdir(SUDARSHAN_DIR)
            os.execvpe("python3", ["python3", "sudarshan.py"], env)
            return  # unreachable - execvpe replaces the process

        # Parent process, new session
        os.close(slave_fd)
        global _session_counter
        _session_counter += 1
        session_id = f"sess_{_session_counter}_{int(datetime.datetime.now().timestamp())}"
        ACTIVE_SESSIONS[session_id] = {
            "user": user,
            "started_at": datetime.datetime.now().isoformat(),
            "status": "attached",
            "master_fd": master_fd,
            "pid": pid,
        }
        _record_session_event(session_id, user, "started")
        is_reattach = False

    await websocket.accept()
    ACTIVE_SESSIONS[session_id]["status"] = "attached"
    if is_reattach:
        try:
            await websocket.send_text("\r\n[i] Reattached to your running session.\r\n")
        except Exception:
            pass

    try:
        async def read_from_pty():
            loop = asyncio.get_running_loop()
            while True:
                r, _, _ = await loop.run_in_executor(
                    None, select.select, [master_fd], [], [], 0.1
                )
                if master_fd in r:
                    try:
                        data = os.read(master_fd, 10240)
                        if not data:
                            break  # EOF - the child process has exited
                        await websocket.send_bytes(data)
                    except OSError:
                        break
                else:
                    await asyncio.sleep(0.01)

        async def read_from_ws():
            while True:
                try:
                    message = await websocket.receive()
                    if message.get("type") == "websocket.disconnect":
                        break
                    if "bytes" in message and message["bytes"]:
                        os.write(master_fd, message["bytes"])
                    elif "text" in message and message["text"]:
                        os.write(master_fd, message["text"].encode("utf-8"))
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    print(f"[WS Read Error] {e}")
                    break

        task_pty = asyncio.create_task(read_from_pty())
        task_ws = asyncio.create_task(read_from_ws())
        done, pending = await asyncio.wait(
            [task_pty, task_ws],
            return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
    finally:
        # KEY BEHAVIOR: a plain websocket disconnect (tab closed, browser
        # crashed, user clicked "Back to Dashboard") does NOT kill the pty
        # process - it's left running so the user can reattach later. Only
        # /api/session/end (explicit "End Session" click) kills it on
        # purpose. The one exception: if the child process has actually
        # exited on its own (e.g. the user picked "Exit" inside the
        # sudarshan.py menu), waitpid confirms that and we clean up for
        # real instead of leaving a dead, unreattachable entry behind.
        child_exited = False
        try:
            reaped_pid, _status = os.waitpid(pid, os.WNOHANG)
            child_exited = reaped_pid == pid
        except OSError:
            child_exited = True  # already reaped elsewhere, or gone

        if child_exited:
            ACTIVE_SESSIONS.pop(session_id, None)
            _record_session_event(session_id, user, "ended")
            try:
                os.close(master_fd)
            except OSError:
                pass
        else:
            if session_id in ACTIVE_SESSIONS:
                ACTIVE_SESSIONS[session_id]["status"] = "detached"

        try:
            await websocket.close()
        except RuntimeError:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web_app:app", host="0.0.0.0", port=8000, reload=True)
