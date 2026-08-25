#!/usr/bin/env python3
"""
Sudarshan :: Session / Findings Builder   (session_builder.py)
Phase 2 of the Sudarshan -> AI report pipeline.

WHAT THIS IS
------------
Takes everything sitting in one target's sudarshan-results folder (raw text
output from host discovery, port scan, vuln scan, subdomain enum, live
host probe, web dir enum) plus the CVE/exploit data from cve_lookup.py
(Phase 1), and merges it all into ONE structured JSON file:

    Sudarshan scan  ->  CVE + exploit lookup  ->  Structured findings (this)

This is the exact "Structured findings: Facts + CVEs as JSON" box in the
pipeline diagram - the artifact that later gets fed into the local vector
store / fine-tuned model. Still zero AI involved here; this is purely
"turn five different raw text files into one machine-readable fact sheet".

This does NOT re-run any scans. It reads whatever sudarshan.py already wrote
to disk for a target and structures it. Run sudarshan.py first (or point it
at an existing results folder), then run this.

USAGE
-----
  # List available target folders (same folders sudarshan.py's [9] shows):
  python3 session_builder.py --list

  # Build the session JSON for one target:
  python3 session_builder.py --target-dir ~/sudarshan-results/metasploitable2 \\
                              --out session.json --summary

  # Skip live NVD lookups (e.g. offline / already have cached findings):
  python3 session_builder.py --target-dir ~/sudarshan-results/metasploitable2 \\
                              --exploitdb-only

CHANGELOG
---------
v1 (phase 2) - initial version. Parses host discovery, port scan,
               nmap vuln script output, subdomains, live host probe
               (httpx), and web dir enum (gobuster) into structured
               lists, then calls cve_lookup.build_findings_for_services()
               for the CVE/exploit layer. Falls back to raw text for any
               section it can't confidently parse, rather than dropping
               data on the floor.
"""

import argparse
import json
import os
import re
import sys
import datetime

import cve_lookup as cl  # Phase 1 module - must be in the same folder

# ----------------------------------------------------------------------------
# Config (kept identical to sudarshan.py so folder paths line up)
# ----------------------------------------------------------------------------

BASE_DIR = os.path.join(os.path.expanduser("~"), "sudarshan-results")
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# ----------------------------------------------------------------------------
# Generic file helpers (same pattern as sudarshan.py's generate_report)
# ----------------------------------------------------------------------------


def _read_if_exists(path):
    if not path:
        return ""
    try:
        with open(path) as f:
            return f.read()
    except (FileNotFoundError, IsADirectoryError):
        return ""


def _latest_file(out_dir, prefix):
    if not os.path.isdir(out_dir):
        return None
    matches = sorted(f for f in os.listdir(out_dir) if f.startswith(prefix))
    return os.path.join(out_dir, matches[-1]) if matches else None


def _read_target_info(out_dir):
    info_text = _read_if_exists(os.path.join(out_dir, "target_info.txt"))
    raw_target, friendly_name = "unknown", "unknown"
    for line in info_text.splitlines():
        if line.startswith("raw_target:"):
            raw_target = line.split(":", 1)[1].strip()
        if line.startswith("friendly_name:"):
            friendly_name = line.split(":", 1)[1].strip()
    return raw_target, friendly_name


# ----------------------------------------------------------------------------
# Per-module parsers - each is best-effort: if the format doesn't match,
# the section still comes back with an empty list + the raw text preserved,
# rather than raising and killing the whole build.
# ----------------------------------------------------------------------------


def parse_host_discovery(text):
    """nmap -sn output: 'Nmap scan report for X (IP)' + 'Host is up ...'"""
    hosts = []
    report_re = re.compile(r"^Nmap scan report for (.+)$")
    lines = text.splitlines()
    for i, line in enumerate(lines):
        m = report_re.match(line.strip())
        if m:
            host = m.group(1).strip()
            up = i + 1 < len(lines) and "Host is up" in lines[i + 1]
            hosts.append({"host": host, "up": up})
    return hosts


def parse_vuln_scan(text):
    """
    nmap --script vuln output. We don't try to fully structure every NSE
    script's freeform text (too many formats) - we count VULNERABLE
    flags and pull any CVE IDs mentioned, and keep the raw text so nothing
    is lost.
    """
    vulnerable_count = text.count("VULNERABLE")
    cves = sorted(set(CVE_PATTERN.findall(text)))
    return {"vulnerable_flags": vulnerable_count, "cves_referenced": cves}


def parse_subdomains(text):
    return [line.strip() for line in text.splitlines() if line.strip()]


def parse_live_hosts(text):
    """
    httpx -status-code -title -tech-detect output, one host per line:
      https://example.com [200] [Example Domain] [nginx,PHP]
    """
    results = []
    line_re = re.compile(
        r"^(\S+)\s*(?:\[(\d+)\])?\s*(?:\[([^\]]*)\])?\s*(?:\[([^\]]*)\])?"
    )
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        m = line_re.match(line)
        if not m:
            continue
        url, status, title, tech = m.groups()
        results.append(
            {
                "url": url,
                "status_code": int(status) if status else None,
                "title": title or None,
                "tech": [t.strip() for t in tech.split(",")] if tech else [],
            }
        )
    return results


def parse_webdir(text):
    """
    gobuster dir -q output, one hit per line:
      /admin (Status: 301) [Size: 234]
    """
    results = []
    line_re = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?")
    for line in text.splitlines():
        m = line_re.match(line.strip())
        if m:
            path, status, size = m.groups()
            results.append(
                {
                    "path": path,
                    "status_code": int(status),
                    "size": int(size) if size else None,
                }
            )
    return results


# ----------------------------------------------------------------------------
# Session builder
# ----------------------------------------------------------------------------


def build_session(
    out_dir,
    api_key=None,
    use_nvd=True,
    use_exploitdb=True,
    use_cache=True,
    max_cves=cl.DEFAULT_MAX_CVES,
):
    if not os.path.isdir(out_dir):
        raise FileNotFoundError(f"No such results folder: {out_dir}")

    raw_target, friendly_name = _read_target_info(out_dir)

    hostdisc_text = _read_if_exists(_latest_file(out_dir, "hostdisc_"))
    portscan_file = _latest_file(out_dir, "portscan_")
    portscan_text = _read_if_exists(portscan_file)
    vuln_text = _read_if_exists(_latest_file(out_dir, "vulnassess_"))
    subdomains_text = _read_if_exists(_latest_file(out_dir, "subdomains_"))
    live_text = _read_if_exists(_latest_file(out_dir, "live_hosts_"))
    webdir_text = _read_if_exists(_latest_file(out_dir, "webdir_"))

    # --- structured parses of each raw output file ---
    host_discovery = parse_host_discovery(hostdisc_text)
    services = cl.parse_services_from_nmap(portscan_file) if portscan_file else []
    vuln_summary = parse_vuln_scan(vuln_text)
    subdomains = parse_subdomains(subdomains_text)
    live_hosts = parse_live_hosts(live_text)
    web_paths = parse_webdir(webdir_text)

    # --- Phase 1: CVE + exploit lookup for every discovered service ---
    cve_findings = []
    if services:
        print(f"[*] Running CVE/exploit lookup for {len(services)} service(s)...")
        cve_findings = cl.build_findings_for_services(
            services,
            api_key=api_key,
            use_nvd=use_nvd,
            use_exploitdb=use_exploitdb,
            use_cache=use_cache,
            max_cves=max_cves,
        )
    else:
        print("[i] No parsed services from a port scan - skipping CVE/exploit lookup. "
              "Run sudarshan.py option [3] (Port Scanning) with nmap -sV first.")

    total_cves = sum(len(f["cves"]) for f in cve_findings)
    total_exploits = sum(len(f["exploits"]) for f in cve_findings)

    session = {
        "target": raw_target,
        "friendly_name": friendly_name,
        "results_dir": out_dir,
        "generated_at": datetime.datetime.now().isoformat(),
        "host_discovery": {
            "hosts": host_discovery,
            "raw": hostdisc_text.strip() or None,
        },
        "port_scan": {
            "services": services,
            "raw": portscan_text.strip() or None,
        },
        "vulnerability_scan": {
            "vulnerable_flags": vuln_summary["vulnerable_flags"],
            "cves_referenced_in_scan": vuln_summary["cves_referenced"],
            "raw": vuln_text.strip() or None,
        },
        "cve_exploit_findings": cve_findings,
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "web_paths": web_paths,
        "totals": {
            "services_discovered": len(services),
            "cves_found": total_cves,
            "exploits_found": total_exploits,
            "subdomains_found": len(subdomains),
            "live_hosts_found": len(live_hosts),
            "web_paths_found": len(web_paths),
        },
    }
    return session


def print_summary(session):
    t = session["totals"]
    print("\n" + "=" * 60)
    print(f"SESSION SUMMARY - {session['target']} ({session['friendly_name']})")
    print("=" * 60)
    print(f"  Services discovered : {t['services_discovered']}")
    print(f"  CVEs found          : {t['cves_found']}")
    print(f"  Exploits found      : {t['exploits_found']}")
    print(f"  Subdomains found    : {t['subdomains_found']}")
    print(f"  Live hosts found    : {t['live_hosts_found']}")
    print(f"  Web paths found     : {t['web_paths_found']}")
    print("=" * 60)


def list_targets():
    if not os.path.isdir(BASE_DIR):
        print("[!] No results yet.")
        return
    targets = sorted(
        d for d in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, d)) and d != ".cache"
    )
    if not targets:
        print("[!] No results yet.")
        return
    print("\nAvailable target folders:")
    for t in targets:
        print(f"  - {os.path.join(BASE_DIR, t)}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Sudarshan Phase 2: merge all scan output + CVE/exploit data into one session JSON.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target-dir", help="Path to a target's results folder (e.g. ~/sudarshan-results/<name>)")
    p.add_argument("--list", action="store_true", help="List available target folders and exit")
    p.add_argument("--out", default=None, help="Output JSON path (default: <target-dir>/session.json)")
    p.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                    help="NVD API key (or set $NVD_API_KEY)")
    p.add_argument("--max-cves", type=int, default=cl.DEFAULT_MAX_CVES,
                    help=f"Max CVEs to keep per service (default {cl.DEFAULT_MAX_CVES})")
    p.add_argument("--no-cache", action="store_true", help="Ignore/skip the local NVD cache")
    p.add_argument("--nvd-only", action="store_true", help="Skip searchsploit, NVD only")
    p.add_argument("--exploitdb-only", action="store_true", help="Skip NVD, searchsploit only")
    p.add_argument("--summary", action="store_true", help="Print a human-readable summary after building")
    return p


def main():
    args = build_arg_parser().parse_args()

    if args.list:
        list_targets()
        return

    if not args.target_dir:
        eprint("[!] --target-dir is required (or use --list to see available folders).")
        sys.exit(1)

    if args.nvd_only and args.exploitdb_only:
        eprint("[!] --nvd-only and --exploitdb-only are mutually exclusive.")
        sys.exit(1)

    target_dir = os.path.expanduser(args.target_dir)

    try:
        session = build_session(
            target_dir,
            api_key=args.api_key,
            use_nvd=not args.exploitdb_only,
            use_exploitdb=not args.nvd_only,
            use_cache=not args.no_cache,
            max_cves=args.max_cves,
        )
    except FileNotFoundError as e:
        eprint(f"[!] {e}")
        sys.exit(1)

    out_path = args.out or os.path.join(target_dir, "session.json")
    with open(out_path, "w") as f:
        json.dump(session, f, indent=2)
    print(f"\n[+] Session findings saved to {out_path}")

    if args.summary:
        print_summary(session)


if __name__ == "__main__":
    main()
