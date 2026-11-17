#!/usr/bin/env bash
# =============================================================================
# check_secrets_hygiene.sh - run before every push to the public repo.
#   bash check_secrets_hygiene.sh
# Exits 0 when clean, 1 when something needs fixing. Read-only: changes nothing.
# =============================================================================
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

FAIL=0
bad()  { printf '  [FAIL] %s\n' "$*"; FAIL=1; }
ok()   { printf '  [ ok ] %s\n' "$*"; }

# files worth scanning (never venv, results, vectorstore, caches, .git, the real .env)
mapfile -t FILES < <(find . -type f \
    \( -name '*.py' -o -name '*.sh' -o -name '*.html' -o -name '*.md' -o -name '*.txt' \
       -o -name '*.example' -o -name '*.ini' -o -name '*.toml' -o -name '*.cfg' -o -name '*.json' \) \
    -not -path './venv/*' -not -path './.git/*' -not -path './sudarshan-results/*' \
    -not -path './vectorstore/*' -not -path '*/__pycache__/*' -not -path './.pytest_cache/*' \
    -not -name 'check_secrets_hygiene.sh' | sort)

echo "Scanning ${#FILES[@]} files..."

echo "1. .gitignore covers the sensitive paths"
for pat in '.env' 'venv/' 'sudarshan-results/' 'vectorstore/' '__pycache__/'; do
    if [ -f .gitignore ] && grep -qxF "$pat" .gitignore; then ok "$pat ignored"; else bad "'$pat' missing from .gitignore"; fi
done

echo "2. nothing sensitive is tracked by git"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    tracked_bad="$(git ls-files | grep -E '(^|/)\.env$|(^|/)venv/|(^|/)sudarshan-results/|(^|/)vectorstore/|\.pem$|\.key$|web_sessions\.json$|download_count\.json$|auth\.py$|login\.html$' || true)"
    if [ -z "$tracked_bad" ]; then ok "no .env / venv / results / keys tracked"; else bad "tracked but must not be:"; printf '       %s\n' $tracked_bad; fi
else
    ok "not a git repo yet - skipped (run again after 'git init')"
fi

echo "3. no UUID- or token-shaped strings in source (an API key once hid in an os.environ.get() name)"
hits="$(grep -nIE '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}' "${FILES[@]}" 2>/dev/null || true)"
if [ -z "$hits" ]; then ok "no UUID-like strings"; else bad "UUID-like strings (possible API keys):"; printf '       %s\n' "$hits"; fi
hits="$(grep -nIE '(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9]{32,}|xox[baprs]-[A-Za-z0-9-]{10,})' "${FILES[@]}" 2>/dev/null || true)"
if [ -z "$hits" ]; then ok "no well-known token formats"; else bad "token-shaped strings:"; printf '       %s\n' "$hits"; fi

echo "4. no private keys"
hits="$(grep -nI 'BEGIN [A-Z ]*PRIVATE KEY' "${FILES[@]}" 2>/dev/null || true)"
if [ -z "$hits" ]; then ok "no private key blocks"; else bad "private key found:"; printf '       %s\n' "$hits"; fi

echo "5. no secret assigned a literal value"
hits="$(grep -nIE '^[[:space:]]*(export[[:space:]]+)?(NVD_API_KEY|API_KEY|SECRET|TOKEN|PASSWORD)[[:space:]]*=[[:space:]]*["'\'']?[A-Za-z0-9._-]{8,}' "${FILES[@]}" 2>/dev/null | grep -vE '\.env\.example|^\./tests/|environ|\$' || true)"
if [ -z "$hits" ]; then ok "no literal secret assignments"; else bad "literal secret-looking assignments:"; printf '       %s\n' "$hits"; fi

echo "6. python code only reads env vars by identifier name"
hits="$(grep -nE 'environ\.get\(["'\''][^"'\'']*[^A-Za-z0-9_"'\''][^"'\'']*["'\'']' ./*.py web_terminal/*.py 2>/dev/null || true)"
if [ -z "$hits" ]; then ok "all os.environ.get() names look like variable names"; else bad "odd os.environ.get() names:"; printf '       %s\n' "$hits"; fi

echo "7. local .env (if present) is private"
if [ -f .env ]; then
    perm="$(stat -c %a .env 2>/dev/null || echo '?')"
    if [ "$perm" = "600" ] || [ "$perm" = "400" ]; then ok ".env permissions $perm"; else bad ".env permissions are $perm - run: chmod 600 .env"; fi
else
    ok "no .env present"
fi

echo
if [ "$FAIL" -eq 0 ]; then echo "Hygiene check PASSED."; else echo "Hygiene check FAILED - fix the items above before pushing."; fi
exit "$FAIL"
