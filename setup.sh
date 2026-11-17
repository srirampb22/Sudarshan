#!/usr/bin/env bash
# =============================================================================
# Sudarshan - local setup (Linux only: Debian / Ubuntu / Kali)
#
#   bash setup.sh                 full setup
#   bash setup.sh --no-pdf        skip pandoc + LaTeX (saves ~500 MB; PDF export
#                                 then falls back to a plainer built-in renderer)
#   bash setup.sh --model NAME    use this Ollama model instead of auto-picking
#   bash setup.sh --help
#
# Safe to re-run: every step checks what is already there.
# Everything installs on THIS machine; nothing is sent anywhere except package
# / model / tool downloads. Your scan targets never leave your machine.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE=".env"
WITH_PDF=1
MODEL_OVERRIDE=""
MISSING_TOOLS=()

say()  { printf '%s\n' "$*"; }
warn() { printf '  [!] %s\n' "$*" >&2; }
step() { printf '\n[%s] %s\n' "$1" "$2"; }

usage() { sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# ---------------------------------------------------------------------------
# .env helpers (plain KEY=VALUE lines; values never need quoting here)
# ---------------------------------------------------------------------------
read_env_value() {   # read_env_value KEY  -> prints value (quotes/spaces stripped) or nothing
    [ -f "$ENV_FILE" ] || return 0
    grep -E "^$1=" "$ENV_FILE" | tail -n 1 | cut -d= -f2- | tr -d "\"' \r" || true
}

upsert_env() {       # upsert_env KEY VALUE
    local key="$1" val="$2"
    touch "$ENV_FILE"
    if grep -qE "^${key}=" "$ENV_FILE"; then
        # use a delimiter that cannot appear in model tags / simple values
        sed -i "s#^${key}=.*#${key}=${val}#" "$ENV_FILE"
    else
        # make sure the file ends with a newline before appending
        if [ -s "$ENV_FILE" ] && [ -n "$(tail -c1 "$ENV_FILE")" ]; then echo >> "$ENV_FILE"; fi
        printf '%s=%s\n' "$key" "$val" >> "$ENV_FILE"
    fi
}

ensure_env_file() {
    if [ -f "$ENV_FILE" ]; then
        say "  $ENV_FILE found - keeping your existing values."
    elif [ -f ".env.example" ]; then
        cp .env.example "$ENV_FILE"
        say "  Created $ENV_FILE from .env.example."
    else
        cat > "$ENV_FILE" <<'EOF'
# Sudarshan local settings. Plain KEY=VALUE lines, no spaces around '='.
# NVD_API_KEY is optional (free from https://nvd.nist.gov/developers/request-an-api-key):
# without it NVD lookups work but are limited to 5 requests / 30 s.
NVD_API_KEY=
EOF
        say "  Created $ENV_FILE."
    fi
    chmod 600 "$ENV_FILE" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# privilege + package helpers
# ---------------------------------------------------------------------------
setup_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        say "[x] Need root for apt, and 'sudo' is not installed. Re-run as root or install sudo."
        exit 1
    fi
    export DEBIAN_FRONTEND=noninteractive
}

apt_required() { $SUDO apt-get install -y "$@"; }

apt_optional() {     # apt_optional PKG...  - one at a time so a missing package never aborts setup
    local p
    for p in "$@"; do
        say "  installing: $p (quiet - big packages like LaTeX can take several minutes)..."
        $SUDO apt-get install -y "$p" >/dev/null 2>&1 && say "  installed: $p" || warn "could not install '$p' via apt (continuing)"
    done
}

# ---------------------------------------------------------------------------
# ProjectDiscovery single-binary tools (httpx / subfinder / naabu)
# They go into venv/bin so that, with the venv active (run.sh does this), they
# come first on PATH. This also fixes the known shadowing bug: the *Python*
# 'httpx' package ships its own 'httpx' CLI which would otherwise hide the Go
# tool of the same name.
# ---------------------------------------------------------------------------
is_python_script() { [ -f "$1" ] && [ "$(head -c 2 "$1")" = "#!" ] && head -n 1 "$1" | grep -q python; }

install_pd_tool() {  # install_pd_tool NAME
    local name="$1" arch pdarch dest="venv/bin/$1" url tmp tag
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64)  pdarch="amd64" ;;
        aarch64|arm64) pdarch="arm64" ;;
        *) warn "$name: unsupported CPU architecture '$arch' - skipping"; MISSING_TOOLS+=("$name"); return 0 ;;
    esac

    if [ -x "$dest" ] && ! is_python_script "$dest"; then
        say "  $name already installed."
        return 0
    fi
    is_python_script "$dest" && rm -f "$dest"   # Python httpx CLI shadowing the Go tool

    # Resolve the latest version from the github.com redirect (the REST API is
    # rate-limited and blocked on some networks; github.com itself is not).
    tag="$(curl -fsSIL -o /dev/null -w '%{url_effective}' "https://github.com/projectdiscovery/${name}/releases/latest" 2>/dev/null | sed -n 's#.*/tag/##p')" || tag=""
    url=""
    if [ -n "$tag" ]; then
        url="https://github.com/projectdiscovery/${name}/releases/download/${tag}/${name}_${tag#v}_linux_${pdarch}.zip"
    fi
    if [ -z "$url" ]; then
        warn "$name: could not resolve a release download from github.com (offline or blocked) - skipping"
        MISSING_TOOLS+=("$name"); return 0
    fi
    tmp="$(mktemp -d)"
    if curl -fsSL "$url" -o "$tmp/$name.zip" && unzip -oq "$tmp/$name.zip" -d "$tmp" && [ -f "$tmp/$name" ]; then
        install -m 0755 "$tmp/$name" "$dest"
        say "  installed: $name ($pdarch)"
    else
        warn "$name: download/unpack failed - skipping"
        MISSING_TOOLS+=("$name")
    fi
    rm -rf "$tmp"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
main() {
    while [ $# -gt 0 ]; do
        case "$1" in
            --no-pdf) WITH_PDF=0 ;;
            --model)  shift; MODEL_OVERRIDE="${1:-}"; [ -n "$MODEL_OVERRIDE" ] || { say "--model needs a value"; exit 2; } ;;
            -h|--help) usage; exit 0 ;;
            *) say "Unknown option: $1"; usage; exit 2 ;;
        esac
        shift
    done

    cd "$SCRIPT_DIR"

    say "============================================"
    say "  Sudarshan - Setup"
    say "============================================"

    if [ "$(uname -s)" != "Linux" ]; then
        say "[x] Sudarshan is a Linux-only tool (Debian / Ubuntu / Kali)."
        exit 1
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        say "[x] apt-get not found. setup.sh supports Debian-based distros (Debian / Ubuntu / Kali)."
        say "    On other distros install manually: python3 + venv, nmap, gobuster, git, curl, jq, unzip,"
        say "    pandoc, Ollama, and searchsploit - then create the venv and run: pip install -r requirements.txt"
        exit 1
    fi
    setup_sudo

    # ---- 1. system packages ------------------------------------------------
    step "1/8" "Installing system packages (needs sudo)..."
    $SUDO apt-get update
    apt_required python3 python3-venv python3-pip nmap gobuster git curl jq unzip libpcap-dev ca-certificates
    apt_optional ffuf dirb
    if [ "$WITH_PDF" -eq 1 ]; then
        say "  Installing pandoc + LaTeX for PDF reports (large download; skip with --no-pdf)..."
        apt_optional pandoc texlive-latex-base texlive-latex-recommended texlive-fonts-recommended lmodern
    else
        say "  --no-pdf given: skipping pandoc/LaTeX."
    fi
    # sudarshan.py's web-dir enumeration defaults to /usr/share/wordlists/dirb/common.txt
    if [ ! -e /usr/share/wordlists/dirb/common.txt ] && [ -d /usr/share/dirb/wordlists ]; then
        $SUDO mkdir -p /usr/share/wordlists
        $SUDO ln -sfn /usr/share/dirb/wordlists /usr/share/wordlists/dirb
        say "  linked dirb wordlists to /usr/share/wordlists/dirb"
    fi

    # ---- 2. Ollama ---------------------------------------------------------
    step "2/8" "Checking Ollama..."
    if ! command -v ollama >/dev/null 2>&1; then
        say "  Installing Ollama with its official installer (https://ollama.com/install.sh)..."
        if ! curl -fsSL https://ollama.com/install.sh | sh; then
            say "[x] Could not download/install Ollama (is ollama.com reachable from this network?)."
            say "    Try another network (e.g. a phone hotspot) and re-run setup.sh, or install it by hand:"
            say "    download https://ollama.com/download/ollama-linux-amd64.tgz, then"
            say "    sudo tar -C /usr -xzf ollama-linux-amd64.tgz   and re-run setup.sh."
            exit 1
        fi
    else
        say "  Ollama already installed."
    fi
    if ! curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
        say "  Starting Ollama in the background..."
        nohup ollama serve > "${TMPDIR:-/tmp}/sudarshan-ollama.log" 2>&1 &
        disown || true
    fi
    say "  Waiting for Ollama to respond..."
    local up=0 i
    for i in $(seq 1 30); do
        if curl -fsS http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then up=1; break; fi
        sleep 2
    done
    if [ "$up" -ne 1 ]; then
        say "[x] Ollama did not start. Log: ${TMPDIR:-/tmp}/sudarshan-ollama.log"
        say "    Try running 'ollama serve' in another terminal, then re-run setup.sh."
        exit 1
    fi
    say "  Ollama is up."

    # ---- 3. choose + pull model --------------------------------------------
    step "3/8" "Choosing a model for this machine..."
    ensure_env_file
    local model existing
    existing="$(read_env_value SUDARSHAN_MODEL)"
    if [ -n "$MODEL_OVERRIDE" ]; then
        model="$MODEL_OVERRIDE"; say "  Using --model: $model"
    elif [ -n "${SUDARSHAN_MODEL:-}" ]; then
        model="$SUDARSHAN_MODEL"; say "  Using SUDARSHAN_MODEL from your environment: $model"
    elif [ -n "$existing" ]; then
        model="$existing"; say "  Keeping the model already set in $ENV_FILE: $model"
    else
        model="$(python3 pick_model.py)"
    fi
    upsert_env SUDARSHAN_MODEL "$model"
    say "  SUDARSHAN_MODEL=$model  (written to $ENV_FILE - edit it any time to change)"
    say "  Pulling $model and nomic-embed-text (first time can take a while)..."
    ollama pull "$model"
    ollama pull nomic-embed-text

    # ---- 4. searchsploit ---------------------------------------------------
    step "4/8" "Setting up searchsploit (ExploitDB)..."
    if ! command -v searchsploit >/dev/null 2>&1; then
        if [ ! -d /opt/exploitdb ]; then
            $SUDO git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb \
              || $SUDO git clone --depth 1 https://github.com/offensive-security/exploitdb.git /opt/exploitdb
        fi
        $SUDO ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
        say "  searchsploit installed."
    else
        say "  searchsploit already installed."
    fi
    if searchsploit -j --disable-colour "test" >/dev/null 2>&1; then
        say "  OK - '-j --disable-colour' supported."
    else
        warn "'searchsploit -j --disable-colour' failed - check 'searchsploit --help' and the flags in cve_lookup.py"
    fi

    # ---- 5. python environment --------------------------------------------
    step "5/8" "Setting up the Python environment..."
    python3 - <<'EOF'
import sys
if sys.version_info < (3, 9):
    sys.exit("[x] Python 3.9+ is required (found %d.%d)." % sys.version_info[:2])
EOF
    [ -d venv ] || python3 -m venv venv
    # shellcheck disable=SC1091
    source venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
    pip install --quiet -r web_terminal/requirements_web.txt

    # ---- 6. ProjectDiscovery tools ----------------------------------------
    step "6/8" "Installing httpx, subfinder, naabu (ProjectDiscovery)..."
    install_pd_tool httpx
    install_pd_tool subfinder
    install_pd_tool naabu
    if [ -x venv/bin/httpx ] && ! venv/bin/httpx -version 2>&1 | grep -qi "current version"; then
        warn "venv/bin/httpx does not look like the ProjectDiscovery tool - web probing option may not work"
    fi

    # ---- 7. NVD key hint ---------------------------------------------------
    step "7/8" "Checking NVD API key..."
    if [ -z "$(read_env_value NVD_API_KEY)" ]; then
        say "  No NVD_API_KEY in $ENV_FILE. Optional, but recommended (free): without it NVD lookups"
        say "  are limited to 5 requests / 30 s. Add it as a line:  NVD_API_KEY=your-key-here"
    else
        say "  NVD_API_KEY is set."
    fi

    # ---- 8. RAG seed -------------------------------------------------------
    step "8/8" "Seeding the starter RAG vector store..."
    SUDARSHAN_MODEL="$model" python report_generator.py --seed-rag \
        || warn "RAG seed skipped/failed - check the chromadb install. Reports still work without RAG."

    say
    say "============================================"
    say "  Setup complete."
    say "============================================"
    if [ "${#MISSING_TOOLS[@]}" -gt 0 ]; then
        say "  Not installed (menu options using them will say so): ${MISSING_TOOLS[*]}"
    fi
    say
    say "Start Sudarshan with:   bash run.sh"
    say "Model in use:           $model   (change SUDARSHAN_MODEL in $ENV_FILE)"
    say "RAG context: only a tiny starter seed is included. To add your own pentest-report PDFs:"
    say "   python report_generator.py --ingest-context /path/to/folder"
    say "Only scan systems you own or are explicitly authorized to test."
}

# run main only when executed, not when sourced (lets tests source the helpers)
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    main "$@"
fi
