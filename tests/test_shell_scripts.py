"""setup.sh / run.sh: syntax, CLI behaviour, and the pure helper functions
(.env handling is where this project has been bitten before)."""
import os
import shutil
import subprocess

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SETUP = os.path.join(ROOT, "setup.sh")
RUN = os.path.join(ROOT, "run.sh")

pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")


def bash(script, cwd):
    return subprocess.run(["bash", "-c", script], cwd=cwd, capture_output=True, text=True)


@pytest.mark.parametrize("path", [SETUP, RUN])
def test_scripts_have_valid_bash_syntax(path):
    assert subprocess.run(["bash", "-n", path], capture_output=True, text=True).returncode == 0


@pytest.mark.parametrize("path", [SETUP, RUN])
def test_scripts_are_executable_and_use_lf_line_endings(path):
    assert os.access(path, os.X_OK)
    with open(path, "rb") as f:
        assert b"\r" not in f.read()


@pytest.mark.parametrize("path", [SETUP, RUN])
def test_help_exits_zero_and_unknown_option_exits_two(path):
    h = subprocess.run(["bash", path, "--help"], capture_output=True, text=True)
    assert h.returncode == 0 and "Sudarshan" in h.stdout
    bad = subprocess.run(["bash", path, "--definitely-not-an-option"], capture_output=True, text=True)
    assert bad.returncode == 2


def test_no_windows_launchers_shipped():
    assert not [f for f in os.listdir(ROOT) if f.lower().endswith((".bat", ".cmd", ".ps1"))]


def test_run_sh_refuses_without_venv(tmp_path):
    shutil.copy(RUN, tmp_path / "run.sh")
    r = subprocess.run(["bash", str(tmp_path / "run.sh"), "--no-browser"], capture_output=True, text=True)
    assert r.returncode == 1 and "setup.sh" in r.stdout


# ---- setup.sh .env helpers ---------------------------------------------------

def test_upsert_env_updates_in_place_without_duplicates(tmp_path):
    (tmp_path / ".env").write_text("NVD_API_KEY=abc\nFOO=1")           # note: no trailing newline
    r = bash(f'source "{SETUP}"; upsert_env SUDARSHAN_MODEL a:1; upsert_env SUDARSHAN_MODEL b:2; cat .env', tmp_path)
    assert r.returncode == 0, r.stderr
    assert r.stdout.splitlines() == ["NVD_API_KEY=abc", "FOO=1", "SUDARSHAN_MODEL=b:2"]


def test_upsert_env_creates_missing_file(tmp_path):
    r = bash(f'source "{SETUP}"; upsert_env SUDARSHAN_MODEL qwen2.5:3b-instruct; cat .env', tmp_path)
    assert r.stdout.strip() == "SUDARSHAN_MODEL=qwen2.5:3b-instruct"


def test_read_env_value_handles_quotes_crlf_and_missing(tmp_path):
    (tmp_path / ".env").write_bytes(b'SUDARSHAN_MODEL="qwen2.5:1.5b-instruct" \r\nOTHER=x\n')
    r = bash(f'source "{SETUP}"; echo "[$(read_env_value SUDARSHAN_MODEL)][$(read_env_value NOPE)]"', tmp_path)
    assert r.stdout.strip() == "[qwen2.5:1.5b-instruct][]"


def test_python_httpx_cli_is_distinguished_from_go_binary(tmp_path):
    (tmp_path / "py").write_text("#!/venv/bin/python3\nimport httpx\n")
    (tmp_path / "go").write_bytes(b"\x7fELF\x02\x01\x01binary")
    r = bash(f'source "{SETUP}"; is_python_script py && echo PY; is_python_script go || echo GO_OK', tmp_path)
    assert r.stdout.split() == ["PY", "GO_OK"]


def test_setup_creates_env_with_private_permissions(tmp_path):
    r = bash(f'source "{SETUP}"; ensure_env_file >/dev/null; stat -c %a .env; grep -c ^NVD_API_KEY= .env', tmp_path)
    assert r.stdout.split() == ["600", "1"]


# ---- run.sh .env loader -----------------------------------------------------

def test_load_env_file_never_executes_values_and_shell_wins(tmp_path):
    (tmp_path / "pwned").write_text("")
    (tmp_path / ".env").write_text(
        "# comment\n"
        'SUDARSHAN_MODEL="qwen2.5:3b-instruct"\n'
        "SUD_TEST_NAME=My Reports\n"                         # the classic `source` trap
        "EVIL=$(touch pwned)\n"
        "export FOO=bar\n"
        "BAD KEY=1\n"
        "PRESET=from_file\n"
        "SINGLE='q q'\n"
        "last=no_newline_at_end"
    )
    script = (f'source "{RUN}"; load_env_file .env; '
              'echo "$SUDARSHAN_MODEL|$SUD_TEST_NAME|$FOO|$PRESET|$SINGLE|$last|$EVIL"')
    r = subprocess.run(["bash", "-c", script], cwd=tmp_path, capture_output=True, text=True,
                       env={**os.environ, "PRESET": "from_shell"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "qwen2.5:3b-instruct|My Reports|bar|from_shell|q q|no_newline_at_end|$(touch pwned)"
    assert not (tmp_path / "pwned").exists() or (tmp_path / "pwned").read_text() == ""
    assert "touch" not in r.stderr


def test_find_free_port_skips_busy_ports(tmp_path):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    busy = s.getsockname()[1]
    try:
        r = bash(f'source "{RUN}"; find_free_port {busy}', tmp_path)
        assert r.returncode == 0 and int(r.stdout.strip()) > busy
    finally:
        s.close()
