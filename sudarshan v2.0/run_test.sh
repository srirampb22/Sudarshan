#!/usr/bin/env bash
# Usage: ./run_test.sh <target-folder-name> [model]
set -e

TARGET="${1:?Usage: ./run_test.sh <target-folder-name> [model]}"
MODEL="${2:-qwen2.5:7b-instruct}"
SESSION="sudarshan-results/${TARGET}/session.json"

if [ ! -f "$SESSION" ]; then
    echo "[!] No session.json found at $SESSION"
    exit 1
fi

DATE=$(date +%Y-%m-%d)
OUTDIR="report-tests/${TARGET}/${DATE}_$(date +%H%M%S)"
mkdir -p "$OUTDIR"

echo "[*] Generating report -> $OUTDIR/report.md (model: $MODEL)"
python3 report_generator.py --session "$SESSION" --out "$OUTDIR/report.md" --model "$MODEL"

echo "[+] Done: $OUTDIR/report.md"
