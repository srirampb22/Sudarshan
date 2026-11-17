#!/usr/bin/env python3
"""
pick_model.py - choose an Ollama report model that fits THIS machine.

Used by setup.sh (stdlib only, so it runs before the venv exists). Prints the
chosen model tag on stdout and the reasoning on stderr, so setup.sh can do:

    MODEL="$(python3 pick_model.py)"

Policy (Qwen2.5-Instruct family; 14B+ is deliberately never chosen - the
project decided larger models don't pay off for this pipeline):

    GPU with >= 6 GB VRAM            -> qwen2.5:7b-instruct
    no usable GPU, RAM >= 10 GB      -> qwen2.5:7b-instruct   (slow on few cores)
    RAM >= 6 GB                      -> qwen2.5:3b-instruct
    RAM >= 3.5 GB                    -> qwen2.5:1.5b-instruct
    below that                       -> qwen2.5:0.5b-instruct (quality warning)

An explicit override always wins: --model NAME, or SUDARSHAN_MODEL in the
environment. (setup.sh also keeps an existing SUDARSHAN_MODEL from .env.)

Flags (for testing): --ram-gb N, --vram-gb N, --cores N override detection;
--json prints a machine-readable result instead of just the tag.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

MODEL_7B = "qwen2.5:7b-instruct"
MODEL_3B = "qwen2.5:3b-instruct"
MODEL_1_5B = "qwen2.5:1.5b-instruct"
MODEL_0_5B = "qwen2.5:0.5b-instruct"


def detect_ram_gb():
    """Total RAM in GiB from /proc/meminfo (inside WSL2 this reflects the
    WSL memory limit, which is what Ollama can actually use). None if
    it can't be read."""
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) / (1024 * 1024)
    except (OSError, ValueError, IndexError):
        pass
    return None


def detect_vram_gb():
    """Largest single NVIDIA GPU's VRAM in GiB via nvidia-smi, or 0.0 when
    there is no usable NVIDIA GPU. (AMD/Intel GPUs are treated as 'no GPU'
    here - Ollama support varies, so we size for CPU to stay safe.)"""
    exe = shutil.which("nvidia-smi")
    if not exe:
        return 0.0
    try:
        out = subprocess.run(
            [exe, "--query-gpu=memory.total", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return 0.0
        vals = [float(x) for x in out.stdout.split() if x.strip().replace(".", "", 1).isdigit()]
        return (max(vals) / 1024) if vals else 0.0  # MiB -> GiB
    except (OSError, subprocess.SubprocessError, ValueError):
        return 0.0


def choose_model(ram_gb, vram_gb, cores):
    """Return (model, reason). Pure function - no I/O, easy to unit test."""
    cores = cores or 1
    if vram_gb is not None and vram_gb >= 6:
        return MODEL_7B, f"GPU with {vram_gb:.1f} GB VRAM can run the 7B model fully"
    if ram_gb is None:
        return MODEL_3B, ("could not read RAM size; picking the middle option "
                          "(override with SUDARSHAN_MODEL in .env)")
    if ram_gb >= 10:
        note = ""
        if cores < 4:
            note = f" (only {cores} CPU core(s): generation will be slow - consider a smaller model)"
        return MODEL_7B, f"{ram_gb:.1f} GB RAM is enough for the 7B model on CPU{note}"
    if ram_gb >= 6:
        return MODEL_3B, f"{ram_gb:.1f} GB RAM: 7B would swap, using the 3B model"
    if ram_gb >= 3.5:
        return MODEL_1_5B, f"{ram_gb:.1f} GB RAM: using the 1.5B model (reports will be less detailed)"
    return MODEL_0_5B, (f"only {ram_gb:.1f} GB RAM: using the 0.5B model - output quality will be poor; "
                        "the grounding checks will flag more claims")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--model", help="force this model tag (skips detection)")
    ap.add_argument("--ram-gb", type=float, help="override detected RAM (GiB)")
    ap.add_argument("--vram-gb", type=float, help="override detected GPU VRAM (GiB)")
    ap.add_argument("--cores", type=int, help="override detected CPU core count")
    ap.add_argument("--json", action="store_true", help="print a JSON object instead of just the tag")
    args = ap.parse_args(argv)

    forced = (args.model or os.environ.get("SUDARSHAN_MODEL", "")).strip()
    if forced:
        model, reason, ram, vram, cores = forced, "set explicitly (--model / SUDARSHAN_MODEL)", None, None, None
    else:
        ram = args.ram_gb if args.ram_gb is not None else detect_ram_gb()
        vram = args.vram_gb if args.vram_gb is not None else detect_vram_gb()
        cores = args.cores if args.cores is not None else (os.cpu_count() or 1)
        model, reason = choose_model(ram, vram, cores)

    if args.json:
        print(json.dumps({"model": model, "reason": reason, "ram_gb": ram, "vram_gb": vram, "cores": cores}))
    else:
        print(f"[pick_model] {reason}", file=sys.stderr)
        print(model)
    return 0


if __name__ == "__main__":
    sys.exit(main())
