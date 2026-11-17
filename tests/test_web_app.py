"""Web UI smoke + security tests: launch-token / Origin / Host guard on every
route (including /ws), dashboard COMPLETED logic, download behaviour.

The real pty behind /ws is NOT exercised here - these tests only prove that
unauthorised connections are refused BEFORE any shell would be spawned."""
import importlib
import os
import sys

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient              # noqa: E402
from starlette.websockets import WebSocketDisconnect   # noqa: E402

TOKEN = "test-token-123"
BASE = "http://127.0.0.1:8000"
GOOD_ORIGIN = {"Origin": BASE}


@pytest.fixture(scope="module")
def web(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("web")
    results = tmp / "results"
    for name, files in {"done_json": ["session.json"], "done_scan": ["portscan_1.txt"], "empty": []}.items():
        d = results / name
        d.mkdir(parents=True)
        for fn in files:
            (d / fn).write_text("{}")
    mp = pytest.MonkeyPatch()
    mp.setenv("SUDARSHAN_LAUNCH_TOKEN", TOKEN)
    mp.setenv("SUDARSHAN_RESULTS_DIR", str(results))
    mp.setenv("SUDARSHAN_SESSION_HISTORY_FILE", str(tmp / "hist.json"))
    mp.setenv("SUDARSHAN_DOWNLOAD_COUNT_FILE", str(tmp / "dl.json"))
    sys.modules.pop("web_app", None)
    module = importlib.import_module("web_app")
    module._results = results
    yield module
    sys.modules.pop("web_app", None)
    mp.undo()


def client(web, base=BASE, cookie=False):
    c = TestClient(web.app, base_url=base)
    if cookie:
        c.cookies.set(web.TOKEN_COOKIE, TOKEN)
    return c


# ---- HTTP guard --------------------------------------------------------------

@pytest.mark.parametrize("path", ["/", "/terminal", "/api/sessions", "/download/done_json"])
def test_every_route_refuses_requests_without_token(web, path):
    assert client(web).get(path, follow_redirects=False).status_code == 403


def test_wrong_token_refused(web):
    assert client(web).get("/?token=wrong", follow_redirects=False).status_code == 403
    assert client(web).get("/?token=", follow_redirects=False).status_code == 403
    assert client(web, cookie=False).get("/", headers={"Cookie": "sudarshan_launch=wrong"}).status_code == 403


def test_token_in_url_sets_cookie_and_redirects_to_clean_url(web):
    r = client(web).get(f"/terminal?x=1&token={TOKEN}", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/terminal?x=1"                       # token stripped from URL
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_cookie_grants_access_to_pages_and_api(web):
    c = client(web, cookie=True)
    assert c.get("/").status_code == 200
    assert c.get("/terminal").status_code == 200
    assert c.get("/api/sessions").status_code == 200


def test_cross_origin_requests_refused_even_with_cookie(web):
    c = client(web, cookie=True)
    assert c.post("/api/session/end", json={}, headers={"Origin": "http://evil.example"}).status_code == 403
    assert c.get("/api/sessions", headers={"Origin": "http://127.0.0.1:9999"}).status_code == 403
    assert c.get("/api/sessions", headers={"Origin": "null"}).status_code == 403
    assert c.post("/api/session/end", json={}, headers=GOOD_ORIGIN).status_code == 404   # allowed, no such session


def test_foreign_host_header_refused_dns_rebinding(web):
    assert client(web, base="http://evil.example", cookie=True).get("/api/sessions").status_code == 403


def test_localhost_hostname_is_accepted(web):
    c = client(web, base="http://localhost:8000", cookie=True)
    assert c.get("/api/sessions").status_code == 200


# ---- websocket guard ------------------------------------------------------------

def ws_refused(web, headers, cookie):
    c = client(web, cookie=cookie)
    with pytest.raises(WebSocketDisconnect):
        with c.websocket_connect("/ws", headers=headers):
            pass
    assert len(web.ACTIVE_SESSIONS) == 0            # nothing (no pty) was spawned


def test_ws_refused_without_token(web):
    ws_refused(web, GOOD_ORIGIN, cookie=False)


def test_ws_refused_from_foreign_origin(web):
    ws_refused(web, {"Origin": "http://evil.example"}, cookie=True)


def test_ws_refused_without_origin_header(web):
    ws_refused(web, {}, cookie=True)


# ---- dashboard + download ----------------------------------------------------

def test_completed_only_when_scan_data_exists(web):
    targets = {t["target_name"]: t["status"] for t in client(web, cookie=True).get("/api/sessions").json()["completed_targets"]}
    assert targets == {"done_json": "completed", "done_scan": "completed", "empty": "no_data"}


def test_dashboard_template_has_no_login_or_logout_ui(web):
    html = client(web, cookie=True).get("/").text.lower()
    assert "/logout" not in html and "/login" not in html
    assert "no scan data" in html                    # the empty-target badge text is in the page script


def test_login_and_logout_routes_are_gone(web):
    c = client(web, cookie=True)
    assert c.get("/login").status_code == 404
    assert c.get("/logout").status_code == 404
    assert c.post("/login", data={"username": "a", "password": "b"}).status_code in (404, 405)


def test_download_returns_zip_and_keeps_user_data(web):
    r = client(web, cookie=True).get("/download/done_json")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert r.content[:2] == b"PK"
    assert (web._results / "done_json" / "session.json").exists()           # NOT deleted after download


def test_download_unknown_target_404_and_no_path_traversal(web):
    c = client(web, cookie=True)
    assert c.get("/download/nope").status_code == 404
    assert c.get("/download/..%2F..%2Fetc").status_code == 404


def test_delete_api_removes_only_the_named_target(web):
    (web._results / "tmp_target").mkdir()
    c = client(web, cookie=True)
    r = c.delete("/api/sessions/tmp_target", headers=GOOD_ORIGIN)
    assert r.status_code == 200 and not (web._results / "tmp_target").exists()
    assert c.delete("/api/sessions/..", headers=GOOD_ORIGIN).status_code in (404, 405)
    assert (web._results / "done_json").exists()


def test_server_binds_loopback_only():
    with open(os.path.join(os.path.dirname(__file__), "..", "web_terminal", "web_app.py")) as f:
        src = f.read()
    assert 'host="127.0.0.1"' in src and "reload=False" in src
    assert "0.0.0.0" not in src
