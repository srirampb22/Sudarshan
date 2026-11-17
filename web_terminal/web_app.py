import os
import pty
import glob
import hmac
import secrets
import tempfile
from urllib.parse import urlsplit, parse_qsl, urlencode
import json
import select
import shutil
import asyncio
import datetime
import resource
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import (
    FastAPI, WebSocket, WebSocketDisconnect, Request, BackgroundTasks,
    HTTPException,
)
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates

@asynccontextmanager
async def lifespan(app: FastAPI):
    reaper_task = asyncio.create_task(_reap_stale_sessions_loop())
    try:
        yield
    finally:
        reaper_task.cancel()

app = FastAPI(lifespan=lifespan)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(_THIS_DIR, "templates"))

# sudarshan.py lives one directory UP from this file (this file is in
# web_terminal/, sudarshan.py is in the project root next to it) - confirmed
# against the actual on-disk layout, not assumed. A prior bug had this
# pointed one directory too HIGH (see FRONTEND_SESSION_HANDOFF.md fix #2);
# don't swing back to "same directory as this file" without re-checking
# `ls` first if the layout ever moves again.
SUDARSHAN_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))

# Must match the default in sudarshan.py (<project root>/sudarshan-results).
RESULTS_DIR = os.environ.get(
    "SUDARSHAN_RESULTS_DIR", os.path.join(SUDARSHAN_DIR, "sudarshan-results")
)

SESSION_HISTORY_FILE = os.environ.get(
    "SUDARSHAN_SESSION_HISTORY_FILE", os.path.join(_THIS_DIR, "web_sessions.json")
)

DOWNLOAD_COUNT_FILE = os.environ.get(
    "SUDARSHAN_DOWNLOAD_COUNT_FILE", os.path.join(_THIS_DIR, "download_count.json")
)

# Local-only tool: there are no accounts. Every session belongs to this
# single local user (access control is the launch-token check, see T3).
LOCAL_USER = "local"

# ----------------------------------------------------------------------------
# Local security model (no accounts - see handoff Section 5)
#   * uvicorn binds 127.0.0.1 only (see __main__ below)
#   * a random per-launch LAUNCH_TOKEN is required on EVERY route, /ws included
#   * Host header must be loopback (blocks DNS-rebinding)
#   * Origin, when present (browsers always send it on WebSockets), must be
#     same-origin - this is what stops another web page open in the same
#     browser from opening ws://127.0.0.1:PORT/ws and getting a shell
# run.sh sets SUDARSHAN_LAUNCH_TOKEN and opens  /?token=<token>. The first
# page load swaps the query token for an HttpOnly SameSite=Strict cookie and
# redirects to the clean URL, so in-app links, fetch() and /ws just work.
# ----------------------------------------------------------------------------
LAUNCH_TOKEN = os.environ.get("SUDARSHAN_LAUNCH_TOKEN", "").strip() or secrets.token_urlsafe(32)
TOKEN_COOKIE = "sudarshan_launch"
ALLOWED_HOSTNAMES = {"127.0.0.1", "localhost", "[::1]", "::1"}


def _token_ok(candidate):
    return bool(candidate) and hmac.compare_digest(str(candidate), LAUNCH_TOKEN)


class LocalOnlyGuardMiddleware:
    """Pure-ASGI middleware so it covers http AND websocket scopes."""

    def __init__(self, app):
        self.app = app

    @staticmethod
    def _headers(scope):
        return {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])}

    async def _deny(self, scope, receive, send, reason, status=403):
        if scope["type"] == "websocket":
            # Closing before accept => HTTP 403 handshake rejection; no pty is ever created.
            await send({"type": "websocket.close", "code": 1008})
            return
        await PlainTextResponse(f"Forbidden: {reason}", status_code=status)(scope, receive, send)

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        h = self._headers(scope)
        host = h.get("host", "")
        hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host.split("]")[0] + "]"
        if hostname.lower() not in ALLOWED_HOSTNAMES:
            return await self._deny(scope, receive, send, "bad Host header")

        origin = h.get("origin")
        if origin is not None and origin != "null":
            if urlsplit(origin).netloc.lower() != host.lower():
                return await self._deny(scope, receive, send, "cross-origin request")
        elif origin == "null":
            return await self._deny(scope, receive, send, "opaque origin")
        elif scope["type"] == "websocket":
            return await self._deny(scope, receive, send, "missing Origin on websocket")

        # token: cookie first, then ?token=
        cookies = {}
        for part in h.get("cookie", "").split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        query = parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True)
        qtoken = next((v for k, v in query if k == "token"), None)

        if _token_ok(cookies.get(TOKEN_COOKIE)):
            return await self.app(scope, receive, send)
        if _token_ok(qtoken):
            if scope["type"] == "http" and scope["method"] == "GET":
                rest = [(k, v) for k, v in query if k != "token"]
                dest = scope["path"] + (("?" + urlencode(rest)) if rest else "")
                resp = RedirectResponse(url=dest, status_code=303)
                resp.set_cookie(TOKEN_COOKIE, LAUNCH_TOKEN, httponly=True, samesite="strict", secure=False, path="/")
                return await resp(scope, receive, send)
            return await self.app(scope, receive, send)
        return await self._deny(scope, receive, send, "missing or invalid launch token")


app.add_middleware(LocalOnlyGuardMiddleware)

# A laptop running a local LLM plus an active nmap/searchsploit run can't
# comfortably serve many concurrent scan sessions - reject new connections
# past this cap rather than degrade silently.
MAX_CONCURRENT_SESSIONS = int(os.environ.get("SUDARSHAN_MAX_CONCURRENT_SESSIONS", "4"))

# Optional scan-start quota per hour (0 = off; a single local user doesn't
# need one). Read from the persisted session-history file so the window
# survives a server restart.
RATE_LIMIT_PER_HOUR = int(os.environ.get("SUDARSHAN_RATE_LIMIT_PER_HOUR", "0"))  # 0 = off (single local user)

# Resource limits on the spawned scan process (Phase 7) - a runaway
# `nmap -p-` or stuck tool shouldn't be able to starve the machine (which
# is also running Ollama inference). RLIMIT_CPU is CPU *time* consumed, not wall-clock, and
# is inherited by any subprocess the child spawns (nmap, gobuster,
# searchsploit, etc.) since rlimits carry across fork/exec. Set either to
# 0/empty to disable that particular limit - some tool combinations
# (Ollama inference, chromadb) can legitimately need more memory than a
# conservative default allows, so this is deliberately tunable rather
# than hardcoded.
MAX_SCAN_CPU_SECONDS = int(os.environ.get("SUDARSHAN_MAX_CPU_SECONDS", "10800"))  # 3 hours of CPU time
MAX_SCAN_MEMORY_MB = int(os.environ.get("SUDARSHAN_MAX_MEMORY_MB", "0"))  # 0 = off (RLIMIT_AS fragile hai, opt-in)

# Wall-clock backstop for a session, regardless of activity. Sessions now
# persist across disconnects (the resume feature) so, unlike before, an
# abandoned session no longer dies on its own when the tab closes - this
# is what stops a forgotten session from permanently holding a
# MAX_CONCURRENT_SESSIONS slot forever.
MAX_SESSION_HOURS = float(os.environ.get("SUDARSHAN_MAX_SESSION_HOURS", "6"))

# How much recent pty output to keep per session and replay on reattach.
# Without this, reattaching to a detached session showed a genuinely
# blank terminal - the process had kept running and producing real
# output the whole time, but nothing was ever buffered anywhere, so
# there was nothing to show until the next new byte arrived. This is a
# ring buffer capped in bytes (not lines), trimmed from the front.
SCROLLBACK_CAP_BYTES = int(os.environ.get("SUDARSHAN_SCROLLBACK_CAP_BYTES", str(200 * 1024)))

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
    """Scan RESULTS_DIR the same way sudarshan.py's own view_results()
    does, and surface each target's metadata for the Dashboard table."""
    targets = []
    if not os.path.isdir(RESULTS_DIR):
        return targets
    for name in sorted(os.listdir(RESULTS_DIR)):
        tdir = os.path.join(RESULTS_DIR, name)
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
        # Only "completed" if the target actually has scan data; an empty
        # folder (e.g. a session that was started and abandoned) must not
        # show a green COMPLETED badge.
        has_data = os.path.isfile(os.path.join(tdir, "session.json")) or bool(
            glob.glob(os.path.join(tdir, "portscan_*"))
        )
        targets.append({
            "target_name": name,
            "raw_target": raw_target,
            "friendly_name": friendly_name,
            "last_used": last_used,
            "status": "completed" if has_data else "no_data",
        })
    targets.sort(key=lambda t: t["last_used"] or "", reverse=True)
    return targets


def _session_owned_by(session_id, user):
    """True only if session_id exists AND belongs to this user - used to
    decide whether a websocket reattach / end-session request is allowed.
    A missing or foreign session_id both return False identically, so a
    stale/guessed id never reveals whether it belongs to someone else."""
    info = ACTIVE_SESSIONS.get(session_id)
    return info is not None and info["user"] == user


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


async def _reap_stale_sessions_loop():
    """Background sweep (Phase 7): kills and cleans up any session that's
    been running for longer than MAX_SESSION_HOURS, regardless of its
    attached/detached status. Needed because sessions now survive a
    disconnect (the resume feature) - without this, a forgotten tab could
    hold a MAX_CONCURRENT_SESSIONS slot forever."""
    while True:
        await asyncio.sleep(300)  # check every 5 minutes
        cutoff = datetime.datetime.now() - datetime.timedelta(hours=MAX_SESSION_HOURS)
        for sid in list(ACTIVE_SESSIONS.keys()):
            info = ACTIVE_SESSIONS.get(sid)
            if not info:
                continue
            try:
                started = datetime.datetime.fromisoformat(info["started_at"])
            except (ValueError, TypeError):
                continue
            if started >= cutoff:
                continue
            print(f"[Session reaper] Killing stale session {sid} "
                  f"(user={info['user']}, started={info['started_at']})")
            try:
                os.kill(info["pid"], 9)
                os.waitpid(info["pid"], 0)
            except OSError:
                pass
            try:
                os.close(info["master_fd"])
            except OSError:
                pass
            ACTIVE_SESSIONS.pop(sid, None)
            _record_session_event(sid, info["user"], "ended", {"status": "reaped_stale"})


def _remove_temp_zip(zip_path: str):
    """Download packs results into a TEMP zip; only that temp zip is removed
    afterwards. The user's own scan data is never deleted by a download."""
    try:
        if os.path.exists(zip_path):
            os.remove(zip_path)
    except OSError as e:
        print(f"[Cleanup Error] {e}")


# ----------------------------------------------------------------------------
# Page routes
# ----------------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def get_dashboard(request: Request):
    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={"max_concurrent": MAX_CONCURRENT_SESSIONS, "active_page": "dashboard"},
    )


@app.get("/terminal", response_class=HTMLResponse)
async def get_terminal(request: Request):
    return templates.TemplateResponse(
        request=request, name="terminal.html", context={"active_page": "terminal"},
    )


# ----------------------------------------------------------------------------
# Session API (backs the Dashboard's history table)
# ----------------------------------------------------------------------------


@app.get("/api/sessions")
async def api_sessions(request: Request):
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
    """Explicitly kill ONE of the current user's sessions, identified by
    session_id in the JSON body (a user can now have more than one
    running at once, so "the" session is no longer well-defined). This is
    the only thing that actually terminates the pty process - a plain
    websocket disconnect (tab closed, navigated to Dashboard) leaves it
    running in the background so the user can reattach later."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    sid = body.get("session_id")
    if not sid or not _session_owned_by(sid, LOCAL_USER):
        return JSONResponse({"error": "session not found"}, status_code=404)
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
    _record_session_event(sid, LOCAL_USER, "ended")
    return JSONResponse({"ended": sid})


@app.delete("/api/sessions/{target_name}")
async def api_delete_session(target_name: str, request: Request):
    safe_name = os.path.basename(target_name)
    target_dir = os.path.join(RESULTS_DIR, safe_name)
    if not os.path.isdir(target_dir):
        return JSONResponse({"error": f"Target '{safe_name}' not found."}, status_code=404)
    try:
        shutil.rmtree(target_dir)
    except OSError as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"deleted": safe_name})


# ----------------------------------------------------------------------------
# Download
# ----------------------------------------------------------------------------


@app.get("/download/{target_name}")
async def download_results(target_name: str, request: Request, background_tasks: BackgroundTasks):

    safe_name = os.path.basename(target_name)
    target_dir = os.path.join(RESULTS_DIR, safe_name)
    if not os.path.exists(target_dir) or not os.path.isdir(target_dir):
        raise HTTPException(status_code=404, detail=f"Target directory for '{safe_name}' not found.")

    zip_base_path = os.path.join(tempfile.mkdtemp(prefix="sudarshan-dl-"), safe_name)
    zip_path = shutil.make_archive(zip_base_path, 'zip', target_dir)
    _increment_download_count()
    background_tasks.add_task(_remove_temp_zip, zip_path)
    return FileResponse(
        path=zip_path,
        media_type='application/zip',
        filename=f"{safe_name}_results.zip",
    )


# ----------------------------------------------------------------------------
# Terminal websocket (launch-token check is added in T3 and must run BEFORE
# pty.openpty()/fork())
# ----------------------------------------------------------------------------


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    user = LOCAL_USER

    # A user can now run more than one session at once (Dashboard's
    # Orchestration widget always starts a NEW one; Data Archives' per-row
    # "Resume" reattaches to one specific one by id). Reattach ONLY when
    # the client explicitly asks for a session_id it actually owns - never
    # implicitly guess "the" session, since there may be several. An
    # invalid/foreign/missing id falls through to starting a new session
    # rather than erroring, so a stale link never reveals whether an id
    # belongs to someone else.
    requested_id = websocket.query_params.get("session_id")
    existing_id = requested_id if requested_id and _session_owned_by(requested_id, user) else None

    if existing_id:
        session_id = existing_id
        info = ACTIVE_SESSIONS[session_id]
        master_fd = info["master_fd"]
        pid = info["pid"]
        is_reattach = True
    else:
        if RATE_LIMIT_PER_HOUR > 0 and _count_recent_sessions(user) >= RATE_LIMIT_PER_HOUR:
            await websocket.accept()
            await websocket.close(code=4430)  # custom close code: per-user rate limit exceeded
            return
        if len(ACTIVE_SESSIONS) >= MAX_CONCURRENT_SESSIONS:
            await websocket.accept()
            await websocket.close(code=4429)  # custom close code: too many concurrent sessions
            return

        master_fd, slave_fd = pty.openpty()
        env = os.environ.copy()
        env["SUDARSHAN_RESULTS_DIR"] = RESULTS_DIR
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
            try:
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
                # Resource limits apply to this process AND anything it forks/
                # execs (nmap, gobuster, searchsploit, ollama calls) since
                # POSIX rlimits are inherited across fork/exec. Best-effort -
                # a platform that rejects a given limit (or a 0/negative
                # config value meaning "disabled") just skips that one rather
                # than aborting the whole session.
                if MAX_SCAN_CPU_SECONDS > 0:
                    try:
                        resource.setrlimit(resource.RLIMIT_CPU, (MAX_SCAN_CPU_SECONDS, MAX_SCAN_CPU_SECONDS))
                    except (ValueError, OSError) as e:
                        print(f"[!] Could not set CPU rlimit: {e}")
                if MAX_SCAN_MEMORY_MB > 0:
                    try:
                        mem_bytes = MAX_SCAN_MEMORY_MB * 1024 * 1024
                        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
                    except (ValueError, OSError) as e:
                        print(f"[!] Could not set memory rlimit: {e}")
                os.execvpe("python3", ["python3", "sudarshan.py"], env)
            except BaseException as e:
                # exec/setup fail hua - kabhi return nahi karna, warna uvicorn ka
                # duplicate copy chalta reh jaata hai (wahi hang/lag wala symptom)
                try:
                    os.write(2, f"\r\n[!] Session failed to start: {e}\r\n".encode())
                except Exception:
                    pass
                os._exit(127)

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
            "scrollback": bytearray(),
        }
        _record_session_event(session_id, user, "started")
        is_reattach = False

    await websocket.accept()
    ACTIVE_SESSIONS[session_id]["status"] = "attached"
    # First frame is always this control message so the client knows which
    # session_id it's now attached to (needed to build the "resume this
    # exact session" URL and to tell /api/session/end which one to kill,
    # now that a user can have more than one at once). The client reads
    # this one frame manually before handing the socket to xterm's
    # AttachAddon for everything after.
    try:
        await websocket.send_text(json.dumps({"__sudarshan_session_id": session_id}))
    except Exception:
        pass
    if is_reattach:
        # Replay whatever the process printed while nobody was watching -
        # without this, reattaching showed a genuinely blank terminal even
        # though the process kept running and producing real output the
        # whole time; there was just nothing anywhere buffering it.
        scrollback = bytes(ACTIVE_SESSIONS[session_id].get("scrollback", b""))
        if scrollback:
            try:
                await websocket.send_bytes(scrollback)
            except Exception:
                pass
        try:
            await websocket.send_text("\r\n[i] Reattached to your running session.\r\n")
        except Exception:
            pass

    try:
        async def read_from_pty():
            loop = asyncio.get_running_loop()
            os.set_blocking(master_fd, False)
            while True:
                r, _, _ = await loop.run_in_executor(
                    None, select.select, [master_fd], [], [], 0.1
                )
                if master_fd in r:
                    try:
                        data = os.read(master_fd, 10240)
                        if not data:
                            break  # EOF - the child process has exited
                        session_info = ACTIVE_SESSIONS.get(session_id)
                        if session_info is not None:
                            sb = session_info["scrollback"]
                            sb.extend(data)
                            if len(sb) > SCROLLBACK_CAP_BYTES:
                                del sb[: len(sb) - SCROLLBACK_CAP_BYTES]
                        await websocket.send_bytes(data)
                    except BlockingIOError:
                        continue  # dusre reader ne data utha liya, koi baat nahi
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

        _si = ACTIVE_SESSIONS.get(session_id)
        if _si is not None:
            for _old in _si.get("tasks", []):
                _old.cancel()
        task_pty = asyncio.create_task(read_from_pty())
        task_ws = asyncio.create_task(read_from_ws())
        if _si is not None:
            _si["tasks"] = [task_pty, task_ws]
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
            _cur = ACTIVE_SESSIONS.get(session_id)
            # sirf tab detach mark karo jab yahi handler current owner ho;
            # warna purana (cancelled) handler naye attached handler ka status bigaad dega
            if _cur is not None and _cur.get("tasks", [None, None])[0] is task_pty:
                _cur["status"] = "detached"

        try:
            await websocket.close()
        except RuntimeError:
            pass


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("SUDARSHAN_PORT", "8000"))
    print("\n[Sudarshan] Local web UI (127.0.0.1 only)")
    print(f"[Sudarshan] Open: http://127.0.0.1:{port}/?token={LAUNCH_TOKEN}\n", flush=True)
    # Pass the app object (not "web_app:app") so the token generated above is
    # the one actually in use; reload stays off (it would re-import and mint a new token).
    uvicorn.run(app, host="127.0.0.1", port=port, reload=False)
