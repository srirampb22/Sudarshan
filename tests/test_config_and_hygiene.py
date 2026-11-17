"""Config/model selection, plus repo-hygiene checks that guard a PUBLIC repo
(no hardcoded keys, no leftover OCI/auth bits)."""
import importlib
import json
import os
import re
import subprocess
import sys

import pytest

import pick_model
import sudarshan_config

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---- sudarshan_config ------------------------------------------------------

@pytest.fixture
def reload_config(monkeypatch):
    def _reload(**env):
        for k in ("SUDARSHAN_MODEL", "NVD_API_KEY", "OLLAMA_URL"):
            monkeypatch.delenv(k, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        return importlib.reload(sudarshan_config)
    yield _reload
    for k in ("SUDARSHAN_MODEL", "NVD_API_KEY", "OLLAMA_URL"):
        monkeypatch.delenv(k, raising=False)
    importlib.reload(sudarshan_config)


def test_model_defaults_when_unset_or_blank(reload_config):
    assert reload_config().REPORT_MODEL == sudarshan_config.DEFAULT_REPORT_MODEL == "qwen2.5:7b-instruct"
    assert reload_config(SUDARSHAN_MODEL="").REPORT_MODEL == "qwen2.5:7b-instruct"
    assert reload_config(SUDARSHAN_MODEL="   ").REPORT_MODEL == "qwen2.5:7b-instruct"


def test_model_comes_from_env_and_is_trimmed(reload_config):
    assert reload_config(SUDARSHAN_MODEL=" qwen2.5:3b-instruct ").REPORT_MODEL == "qwen2.5:3b-instruct"


def test_nvd_key_read_from_env_var_named_nvd_api_key(reload_config):
    assert reload_config().NVD_API_KEY is None
    assert reload_config(NVD_API_KEY="abc123").NVD_API_KEY == "abc123"


# ---- pick_model ------------------------------------------------------------

@pytest.mark.parametrize("ram,vram,cores,expected", [
    (32, 8, 16, pick_model.MODEL_7B), (8, 6, 4, pick_model.MODEL_7B), (16, 0, 8, pick_model.MODEL_7B),
    (10, 0, 4, pick_model.MODEL_7B), (9.9, 0, 8, pick_model.MODEL_3B), (8, 5.9, 8, pick_model.MODEL_3B),
    (6, 0, 4, pick_model.MODEL_3B), (5.9, 0, 4, pick_model.MODEL_1_5B), (3.5, 0, 2, pick_model.MODEL_1_5B),
    (3.4, 0, 2, pick_model.MODEL_0_5B), (None, 0, 4, pick_model.MODEL_3B),
])
def test_choose_model_tiers(ram, vram, cores, expected):
    assert pick_model.choose_model(ram, vram, cores)[0] == expected


def test_never_picks_14b_or_larger():
    for ram in (8, 16, 64, 256):
        for vram in (0, 8, 24, 80):
            assert "14b" not in pick_model.choose_model(ram, vram, 32)[0]


def test_slow_cpu_warning_mentions_cores():
    assert "slow" in pick_model.choose_model(12, 0, 2)[1]


def run_pick(*args, env_model=None):
    env = {k: v for k, v in os.environ.items() if k != "SUDARSHAN_MODEL"}
    if env_model:
        env["SUDARSHAN_MODEL"] = env_model
    return subprocess.run([sys.executable, "-I", os.path.join(ROOT, "pick_model.py"), *args],
                          capture_output=True, text=True, env=env)


def test_pick_model_cli_prints_only_the_tag_on_stdout():
    r = run_pick("--ram-gb", "8", "--vram-gb", "0", "--cores", "4")
    assert r.returncode == 0 and r.stdout.strip() == "qwen2.5:3b-instruct"
    assert "RAM" in r.stderr                                   # reasoning goes to stderr


def test_pick_model_cli_override_wins():
    assert run_pick("--model", "foo:1b", "--ram-gb", "64").stdout.strip() == "foo:1b"
    assert run_pick(env_model="bar:2b").stdout.strip() == "bar:2b"


def test_pick_model_json_output():
    data = json.loads(run_pick("--ram-gb", "16", "--vram-gb", "0", "--cores", "8", "--json").stdout)
    assert data["model"] == "qwen2.5:7b-instruct" and data["ram_gb"] == 16


# ---- repo hygiene (public repo) -----------------------------------------------

def tracked_source_files():
    skip_dirs = {"tests", "venv", ".git", "__pycache__", "sudarshan-results", "vectorstore", "node_modules"}
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fn in filenames:
            if fn.endswith((".py", ".sh", ".html", ".txt", ".md", ".example", ".cfg", ".toml", ".ini")):
                yield os.path.join(dirpath, fn)


UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def test_no_uuid_style_secrets_in_source():
    """A real NVD key once sat in sudarshan_config.py as the *name* in os.environ.get(...)."""
    hits = []
    for path in tracked_source_files():
        with open(path, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                if UUID_RE.search(line):
                    hits.append(f"{os.path.relpath(path, ROOT)}:{n}")
    assert not hits, f"UUID-like strings (possible API keys) found: {hits}"


def test_environ_get_only_takes_identifier_names():
    bad = []
    pat = re.compile(r"""environ\.get\(\s*["']([^"']+)["']""")
    for path in tracked_source_files():
        if not path.endswith(".py"):
            continue
        with open(path, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f, 1):
                for name in pat.findall(line):
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                        bad.append(f"{os.path.relpath(path, ROOT)}:{n}: {name!r}")
    assert not bad, bad


@pytest.mark.parametrize("needle", ["92.4.69.38", "/mnt/e/", "trycloudflare", "OCPU", "Ampere", "ramdisk"])
def test_no_leftover_deployment_specific_strings(needle):
    hits = []
    for path in tracked_source_files():
        if path.endswith(".md"):
            continue          # README may mention history; code/config must not
        with open(path, encoding="utf-8", errors="replace") as f:
            if needle.lower() in f.read().lower():
                hits.append(os.path.relpath(path, ROOT))
    assert not hits, f"{needle!r} still present in {hits}"


def test_auth_is_fully_removed():
    assert not os.path.exists(os.path.join(ROOT, "auth.py"))
    assert not os.path.exists(os.path.join(ROOT, "web_terminal", "templates", "login.html"))
    for rel in ("requirements.txt", os.path.join("web_terminal", "requirements_web.txt")):
        with open(os.path.join(ROOT, rel)) as f:
            text = f.read().lower()
        for dep in ("bcrypt", "pyjwt", "python-multipart"):
            assert dep not in text, f"{dep} still listed in {rel}"
    with open(os.path.join(ROOT, "web_terminal", "web_app.py")) as f:
        src = f.read()
    for needle in ("import auth", "/login", "/logout", "bcrypt", "jwt"):
        assert needle not in src.lower(), f"{needle!r} still in web_app.py"


def test_searchsploit_uses_valid_colour_flag():
    """searchsploit has no --nocolour; it errors with 'illegal option'."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    for py in root.glob("*.py"):
        assert "\"--nocolour\"" not in py.read_text(encoding="utf-8"), py.name
