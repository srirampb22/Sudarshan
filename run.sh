#!/usr/bin/env bash
# =============================================================================
# Sudarshan - start the local web UI
#
#   bash run.sh                 start, then open the browser automatically
#   bash run.sh --no-browser    start and just print the URL
#   bash run.sh --port 9000     use a different port (default 8000)
#   bash run.sh --help
#
# The server listens on 127.0.0.1 ONLY. Every launch generates a fresh random
# token; the URL printed/opened contains it (http://127.0.0.1:PORT/?token=...).
# Anything without that token - including other web pages open in your browser -
# is refused. Stop the server with Ctrl+C.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPEN_BROWSER=1
PORT_ARG=""

say()  { printf '%s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
usage() { sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------------------
# Safe .env loader. Deliberately NOT `source .env`: sourcing executes the file,
# so a value with a space or a stray word (e.g. NAME=My Reports) is run as a
# command. This only reads KEY=VALUE lines. Variables already set in your shell
# win over .env.
# ---------------------------------------------------------------------------
load_env_file() {
    local f="$1" line key val
    [ -f "$f" ] || return 0
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in ''|'#'*) continue ;; esac
        line="${line#export }"
        [[ "$line" == *=* ]] || continue
        key="${line%%=*}"; val="${line#*=}"
        key="${key//[[:space:]]/}"
        [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
        val="${val#"${val%%[![:space:]]*}"}"      # trim leading whitespace
        val="${val%"${val##*[![:space:]]}"}"      # trim trailing whitespace
        if [[ "$val" =~ ^\"(.*)\"$ ]] || [[ "$val" =~ ^\'(.*)\'$ ]]; then val="${BASH_REMATCH[1]}"; fi
        if [ -z "${!key+x}" ]; then export "$key=$val"; fi
    done < "$f"
}

# First free TCP port on 127.0.0.1 at or after $1 (tries 20 ports).
find_free_port() {
    python3 - "$1" <<'EOF'
import socket, sys
start = int(sys.argv[1])
for p in range(start, start + 20):
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", p))
        print(p)
        sys.exit(0)
    except OSError:
        pass
    finally:
        s.close()
sys.exit(1)
EOF
}

ollama_up() { curl -fsS "${OLLAMA_URL:-http://127.0.0.1:11434}/api/tags" >/dev/null 2>&1; }

main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-browser) OPEN_BROWSER=0 ;;
            --port) shift; PORT_ARG="${1:-}"; [[ "$PORT_ARG" =~ ^[0-9]+$ ]] || { say "--port needs a number"; exit 2; } ;;
            -h|--help) usage; exit 0 ;;
            *) say "Unknown option: $1"; usage; exit 2 ;;
        esac
        shift
    done

    cd "$SCRIPT_DIR"

    if [ ! -x venv/bin/python ]; then
        say "[x] No Python environment found (venv/). Run setup first:  bash setup.sh"
        exit 1
    fi
    load_env_file .env
    # shellcheck disable=SC1091
    source venv/bin/activate          # puts venv/bin (incl. Go httpx/subfinder/naabu) first on PATH

    if ! python -c "import fastapi, uvicorn" >/dev/null 2>&1; then
        say "[x] Web dependencies are missing from venv/. Re-run:  bash setup.sh"
        exit 1
    fi

    # --- Ollama (needed for AI reports; scans work without it) --------------
    if ! ollama_up; then
        if command -v ollama >/dev/null 2>&1; then
            say "Starting Ollama in the background..."
            nohup ollama serve > "${TMPDIR:-/tmp}/sudarshan-ollama.log" 2>&1 &
            disown || true
            for _ in $(seq 1 15); do ollama_up && break; sleep 1; done
        fi
        ollama_up || warn "Ollama is not responding - scans will work, but option [12] AI reports will not. (bash setup.sh installs it)"
    fi

    # --- port + fresh per-launch token ------------------------------------
    local want_port port token
    want_port="${PORT_ARG:-${SUDARSHAN_PORT:-8000}}"
    port="$(find_free_port "$want_port")" || { say "[x] No free port found near $want_port. Use --port N."; exit 1; }
    [ "$port" = "$want_port" ] || say "Port $want_port is busy - using $port instead."
    token="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
    export SUDARSHAN_PORT="$port" SUDARSHAN_LAUNCH_TOKEN="$token"
    local url="http://127.0.0.1:${port}/?token=${token}"

    # --- open the browser once the server answers (best effort) ------------
    local opener_pid=""
    if [ "$OPEN_BROWSER" -eq 1 ]; then
        if command -v xdg-open >/dev/null 2>&1 && { [ -n "${DISPLAY:-}" ] || [ -n "${WAYLAND_DISPLAY:-}" ]; }; then
            (
                for _ in $(seq 1 40); do
                    curl -s -o /dev/null "http://127.0.0.1:${port}/" && break
                    sleep 0.5
                done
                xdg-open "$url" >/dev/null 2>&1 || true
            ) &
            opener_pid=$!
        else
            say "(No desktop/browser opener found - open the URL below yourself.)"
        fi
    fi
    # shellcheck disable=SC2064
    trap "[ -n '$opener_pid' ] && kill $opener_pid 2>/dev/null || true" EXIT

    say "Model: ${SUDARSHAN_MODEL:-<default>}   |   Results: ${SUDARSHAN_RESULTS_DIR:-$SCRIPT_DIR/sudarshan-results}"
    say "Press Ctrl+C to stop."
    # web_app.py prints the same URL; it also reads SUDARSHAN_PORT / SUDARSHAN_LAUNCH_TOKEN.
    python web_terminal/web_app.py
}

# run main only when executed, not when sourced (lets tests source the helpers)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
