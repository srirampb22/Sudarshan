#!/usr/bin/env python3
"""
Sudarshan - Unified Enumeration Console (v3)
A menu-driven wrapper around standard, publicly available pentesting tools
(nmap, gobuster, ffuf, subfinder, httpx, naabu, searchsploit, crackmapexec, etc).

IMPORTANT: This tool only orchestrates already-installed third-party binaries.
It does not perform any scanning itself and does not bypass authorization,
rate limits, or WAFs. Only use against targets you own or are explicitly
authorized to test.

v2 changes:
  - Vulnerability assessment + exploit suggestion module (nmap --script vuln
    + searchsploit lookups against discovered service versions)
  - Markdown (and PDF, if pandoc is installed) report generator that
    summarizes every scan in a target folder with a heuristic risk rating
  - Friendly target naming so result folders/reports are identifiable
  - Per-target activity log (activity.log) recording every action taken

v3 changes (AI report pipeline, phases 1-3 - see cve_lookup.py,
session_builder.py, report_generator.py):
  - [11] Build Structured Findings: runs NVD + searchsploit lookups against
    the latest port scan and writes session.json (facts + CVEs, one JSON
    per target - this is the "Structured findings" artifact the rest of
    the pipeline consumes)
  - [12] Generate AI Report: sends session.json to a local Ollama model to
    write the narrative sections of a report, grounded in those facts
    (the model never invents the facts themselves - see report_generator.py)
  - Full Auto Chain - Network ([8]) now offers to run both of the above
    at the end, on top of the existing heuristic markdown report
  - These three are optional add-ons: if cve_lookup.py / session_builder.py /
    report_generator.py aren't sitting next to this file, sudarshan.py still
    runs exactly as before, just without options 11/12
"""

import os
import re
import sys
import json
import shutil
import subprocess
import datetime
import shlex
import logging

# Phase 1-3 AI pipeline modules - optional. If any is missing, the
# corresponding menu option degrades gracefully instead of crashing.
try:
    import cve_lookup
except ImportError:
    cve_lookup = None

try:
    import session_builder
except ImportError:
    session_builder = None

try:
    import report_generator
except ImportError:
    report_generator = None

# ----------------------------------------------------------------------------
# Config / paths
# ----------------------------------------------------------------------------

BASE_DIR = os.environ.get(
    "SUDARSHAN_RESULTS_DIR",
    os.path.join(os.path.expanduser("~"), "sudarshan-results"),
)

BANNER = r"""
+---------------------------------------------------+
|                  S U D A R S H A N                 |
|         Unified Enumeration Console v2             |
|               authorized use only                  |
+---------------------------------------------------+
"""

MENU = """
=========================================
   SUDARSHAN | Unified Enumeration Console
=========================================
[1] Web / Directory Enumeration      (gobuster, ffuf)
[2] Host Discovery                   (nmap -sn)
[3] Port Scanning                    (nmap, naabu)
[4] Subdomain Enumeration            (subfinder)
[5] Live Host / Service Probe        (httpx, nmap -sV)
[6] Active Directory Enumeration     (stub - see module notes)
[7] Full Auto Chain - Web            (4 -> 1 -> 5 -> report)
[8] Full Auto Chain - Network        (2 -> 3 -> vuln+exploit -> 5 -> report)
[9] View Past Scan Results
[10] Generate / Regenerate Report    (heuristic, from existing results)
[11] Build Structured Findings       (CVE+exploit JSON - NVD/searchsploit)
[12] Generate AI Report              (Ollama narrative, needs session.json)
[13] Add RAG Context                 (past reports, CVE notes, exploit notes)
[0] Exit
"""

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

# ----------------------------------------------------------------------------
# Utility helpers
# ----------------------------------------------------------------------------


def tool_available(name):
    """Check if a binary is on PATH."""
    return shutil.which(name) is not None


def sanitize(s):
    return re.sub(r"[^A-Za-z0-9._-]", "_", s)


def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")


def setup_target(target, friendly_name=None):
    """
    Create (if needed) the results directory for a target, using the
    friendly name if given, otherwise a sanitized version of the target.
    Writes/updates target_info.txt with metadata and returns
    (out_dir, logger).
    """
    folder_name = sanitize(friendly_name) if friendly_name else sanitize(target)
    out_dir = os.path.join(BASE_DIR, folder_name)
    os.makedirs(out_dir, exist_ok=True)

    info_file = os.path.join(out_dir, "target_info.txt")
    first_seen = datetime.datetime.now().isoformat()
    if os.path.isfile(info_file):
        with open(info_file) as f:
            for line in f:
                if line.startswith("first_seen:"):
                    first_seen = line.split(":", 1)[1].strip()
                    break

    with open(info_file, "w") as f:
        f.write(f"raw_target: {target}\n")
        f.write(f"friendly_name: {friendly_name or '(none - using sanitized target)'}\n")
        f.write(f"folder: {folder_name}\n")
        f.write(f"first_seen: {first_seen}\n")
        f.write(f"last_used: {datetime.datetime.now().isoformat()}\n")

    logger = get_logger(out_dir)
    return out_dir, logger


def get_logger(out_dir):
    """Create/attach a logger that appends to activity.log in out_dir."""
    log_path = os.path.join(out_dir, "activity.log")
    logger_name = f"sudarshan.{out_dir}"
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        fh = logging.FileHandler(log_path)
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(fh)

    return logger


def run_command(cmd, outfile=None, description="", logger=None):
    """
    Run a shell command, streaming output to console and optionally to a
    file. cmd: list of args (preferred) - target values are inserted as
    single list items, never string-concatenated into a shell string.
    """
    print(f"\n[*] {description or ' '.join(cmd)}")
    printable_cmd = " ".join(shlex.quote(c) for c in cmd)
    print(f"[*] Command: {printable_cmd}")

    if logger:
        logger.info(f"START | {description} | cmd: {printable_cmd}")

    try:
        with subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        ) as proc:
            lines = []
            for line in proc.stdout:
                print(line, end="")
                lines.append(line)
            proc.wait()

        if outfile:
            with open(outfile, "w") as f:
                f.writelines(lines)
            print(f"[+] Output saved to {outfile}")

        if proc.returncode != 0:
            print(f"[!] Command exited with code {proc.returncode}")
            if logger:
                logger.warning(f"END | {description} | exit_code={proc.returncode}")
        else:
            if logger:
                logger.info(f"END | {description} | exit_code=0 | output={outfile or 'stdout only'}")

        return "".join(lines)

    except FileNotFoundError:
        msg = f"Tool not found: {cmd[0]}. Install it and ensure it's on PATH."
        print(f"[!] {msg}")
        if logger:
            logger.error(f"FAILED | {description} | {msg}")
        return ""
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        if logger:
            logger.warning(f"INTERRUPTED | {description}")
        return ""


def prompt_target(label="target"):
    val = input(f"\n{label} > ").strip()
    if not val:
        print("[!] No target provided.")
        return None
    return val


def prompt_friendly_name():
    val = input(
        "friendly name for this target/engagement (optional, enter to skip) > "
    ).strip()
    return val or None


def confirm_authorization(target, logger=None):
    print(f"\n[!] You are about to run scans against: {target}")
    ans = input("    Confirm you are authorized to test this target [y/N]: ").strip().lower()
    confirmed = ans == "y"
    if logger:
        who = os.environ.get("USER", "unknown")
        logger.info(
            f"AUTHORIZATION | target={target} | confirmed={confirmed} | user={who}"
        )
    return confirmed


# ----------------------------------------------------------------------------
# Module 1: Web / Directory Enumeration
# ----------------------------------------------------------------------------


def module_web_dir_enum(target, out_dir, logger=None):
    print("\n--- Web / Directory Enumeration ---")
    print("[a] gobuster dir")
    print("[b] ffuf")
    choice = input("select tool > ").strip().lower()

    wordlist = input(
        "wordlist path [/usr/share/wordlists/dirb/common.txt] > "
    ).strip() or "/usr/share/wordlists/dirb/common.txt"

    if not os.path.isfile(wordlist):
        print(f"[!] Wordlist not found at {wordlist}. Update the path and retry.")
        if logger:
            logger.warning(f"Web dir enum skipped - wordlist not found: {wordlist}")
        return

    url = target if target.startswith("http") else f"http://{target}"
    out_file = os.path.join(out_dir, f"webdir_{timestamp()}.txt")

    if choice == "a" and tool_available("gobuster"):
        cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q"]
        run_command(cmd, out_file, "Running gobuster directory brute force", logger)
    elif choice == "b" and tool_available("ffuf"):
        cmd = ["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-of", "csv", "-o", out_file]
        run_command(cmd, None, "Running ffuf directory fuzzing", logger)
    else:
        print("[!] Selected tool not available or not installed.")
        if logger:
            logger.warning("Web dir enum skipped - selected tool unavailable")


# ----------------------------------------------------------------------------
# Module 2: Host Discovery
# ----------------------------------------------------------------------------


def module_host_discovery(target, out_dir, logger=None):
    print("\n--- Host Discovery ---")
    if not tool_available("nmap"):
        print("[!] nmap not found. Install nmap to use this module.")
        return

    out_file = os.path.join(out_dir, f"hostdisc_{timestamp()}.txt")
    cmd = ["nmap", "-sn", target, "-oN", out_file]
    run_command(cmd, None, "Running nmap ping sweep (host discovery)", logger)


# ----------------------------------------------------------------------------
# Module 3: Port Scanning
# ----------------------------------------------------------------------------


def _extract_open_ports_from_gnmap(gnmap_file):
    """
    Pull open TCP port numbers out of an nmap -oG discovery file, e.g. a
    line like:
      Host: 10.10.10.10 ()   Ports: 22/open/tcp//ssh///, 80/open/tcp//http///
    Returns a sorted list of port number strings, deduplicated.
    """
    ports = set()
    port_re = re.compile(r"(\d+)/open/tcp")
    if not gnmap_file or not os.path.isfile(gnmap_file):
        return []
    with open(gnmap_file) as f:
        for line in f:
            ports.update(port_re.findall(line))
    return sorted(ports, key=int)


def module_port_scan(target, out_dir, logger=None):
    """
    Port scanning module. Option [a] is a two-step fast scan: a
    default-top-1000-port discovery pass with no version detection (the
    actual time sink in a combined '-sV' scan is -sV probing every port,
    not the port sweep itself), followed by a targeted -sV pass against
    only the ports found open. Deliberately NOT using -p- (all 65535
    ports) here - on a VPN-based lab connection (THM/HTB) the full range
    adds several minutes for very little marginal benefit on typical
    lab boxes, which mostly expose common ports; drop to option [b] or
    manually add -p- back in if a target is suspected of hiding services
    on high/uncommon ports. Final -oN output format is identical either
    way, so nothing downstream (cve_lookup.py / session_builder.py's
    parse_services_from_nmap - both regex on '^(\\d+)/(tcp|udp)\\s+open...')
    needs to change. Option [b] keeps the old single-pass scan available,
    also scoped to the default top-1000 ports rather than -p- for the
    same reason.
    """
    print("\n--- Port Scanning ---")
    print("[a] nmap fast two-step (top-1000 discovery, then -sV on open ports only - recommended)")
    print("[b] nmap single-pass (top-1000 + service/version detection in one pass, slower)")
    choice = input("select tool > ").strip().lower()

    out_file = os.path.join(out_dir, f"portscan_{timestamp()}.txt")

    if choice == "a" and tool_available("nmap"):
        gnmap_file = os.path.join(out_dir, f".discovery_{timestamp()}.gnmap")
        discover_cmd = [
            "nmap", "--min-rate=5000", "-T4", "-Pn",
            target, "-oG", gnmap_file,
        ]
        run_command(
            discover_cmd, None,
            "Running fast top-1000-port discovery pass (no version detection)",
            logger,
        )

        open_ports = _extract_open_ports_from_gnmap(gnmap_file)
        if not open_ports:
            print("[!] No open ports found in the discovery pass - nothing to "
                  "run -sV against. If this seems wrong, the target may be "
                  "dropping the higher packet rate, or expose services "
                  "outside the default top-1000 ports; re-run with option "
                  "[b] to compare, or add -p- back manually if needed.")
            if logger:
                logger.warning("Fast port scan found zero open ports in discovery pass")
            return None

        print(f"[*] Discovery found {len(open_ports)} open port(s): "
              f"{','.join(open_ports)}")
        sv_cmd = [
            "nmap", "-sV", "-Pn", "-p", ",".join(open_ports),
            target, "-oN", out_file,
        ]
        run_command(
            sv_cmd, None,
            "Running targeted service/version detection on open ports only",
            logger,
        )
        return out_file

    elif choice == "b" and tool_available("nmap"):
        cmd = ["nmap", "-sV", "-T4", target, "-oN", out_file]
        run_command(cmd, None, "Running top-1000-port nmap scan with service detection", logger)
        return out_file
    else:
        print("[!] Selected tool not available or not installed.")
        return None


# ----------------------------------------------------------------------------
# Module 3b (new): Vulnerability Assessment + Exploit Suggestion
# ----------------------------------------------------------------------------


def parse_services_from_nmap(port_scan_file):
    """
    Parse an nmap -sV normal-output file for lines like:
      80/tcp   open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2)
    Returns a list of (port, proto, service, version_string) tuples.
    """
    services = []
    if not port_scan_file or not os.path.isfile(port_scan_file):
        return services

    line_re = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s+(.*)$")
    with open(port_scan_file) as f:
        for line in f:
            m = line_re.match(line.strip())
            if m:
                port, proto, service, version = m.groups()
                services.append((port, proto, service, version.strip()))
    return services


def module_vuln_and_exploit(target, out_dir, port_scan_file=None, logger=None):
    """
    Runs nmap's built-in vuln NSE script category against the target, then
    searches the local ExploitDB (via searchsploit) for each discovered
    service/version to suggest known exploits.

    The vuln script pass is scoped to ONLY the ports already found open by
    the earlier port scan (parsed from port_scan_file), instead of nmap's
    default ~1000-port list. Running '--script vuln' with no -p filter was
    the actual source of long/stuck runs - most NSE vuln scripts carry
    their own per-port timeout and probe behavior, so blindly running the
    full vuln script category against hundreds of closed/filtered default
    ports multiplies that cost for zero benefit, since a closed port has
    nothing for a vuln script to find anyway. A hard --script-timeout is
    also added so a single misbehaving script (observed cause of the
    worst hangs) can't stall the whole scan indefinitely.
    """
    print("\n--- Vulnerability Assessment + Exploit Suggestion ---")

    vuln_out = os.path.join(out_dir, f"vulnassess_{timestamp()}.txt")
    exploit_out = os.path.join(out_dir, f"exploits_{timestamp()}.txt")

    services = parse_services_from_nmap(port_scan_file)
    open_ports = sorted({s[0] for s in services}, key=int) if services else []

    if not open_ports:
        print("[!] No open ports available from the port scan - run Port "
              "Scanning first (option [3], or [a]/[b] in that menu) so "
              "vuln assessment knows which ports to target. Skipping vuln "
              "script scan and exploit lookup. (Note: naabu's -o output "
              "isn't in nmap -oN format and won't parse here - use nmap "
              "option [a] or [b] for the port scan if you plan to run this.)")
        if logger:
            logger.warning("Vuln+exploit skipped - no open ports parsed from port_scan_file")
        return

    if tool_available("nmap"):
        cmd = [
            "nmap", "-sV", "-Pn",
            "-p", ",".join(open_ports),
            "--script", "vuln",
            "--script-timeout", "60s",
            target, "-oN", vuln_out,
        ]
        run_command(
            cmd, None,
            f"Running nmap NSE vuln scripts against {len(open_ports)} "
            f"known-open port(s) only (60s script timeout)",
            logger,
        )
    else:
        print("[!] nmap not found - skipping vuln script scan.")
        if logger:
            logger.warning("Vuln scan skipped - nmap not available")

    if not tool_available("searchsploit"):
        print("[!] searchsploit not found - skipping exploit lookup. "
              "Install exploitdb (usually preinstalled on Kali).")
        if logger:
            logger.warning("Exploit lookup skipped - searchsploit not available")
        return

    def _format_searchsploit_json(raw_output):
        """-j gives JSON, not the human-readable table --nocolour used to.
        Parse it back into a short readable listing for this module's
        plain-text exploits file; fall back to the raw text (e.g. an error
        message) if it isn't valid JSON."""
        try:
            data = json.loads(raw_output)
        except (json.JSONDecodeError, TypeError):
            return raw_output
        entries = data.get("RESULTS_EXPLOIT", [])
        if not entries:
            return "  (no matching exploits found)"
        lines = []
        for e in entries:
            title = e.get("Title", "?")
            edb_id = e.get("EDB-ID", "?")
            lines.append(f"  [EDB-ID {edb_id}] {title}")
        return "\n".join(lines)

    results = []
    for port, proto, service, version in services:
        query = version if version else service
        print(f"\n[*] searchsploit lookup: {query}")
        # NOTE: '--nocolour' alone is not a valid flag on all real
        # searchsploit builds ("illegal option --" observed live) - use the
        # same short-flag combo already confirmed working in cve_lookup.py's
        # query_searchsploit(): '-j --disable-colour'.
        cmd = ["searchsploit", "-j", "--disable-colour", query]
        raw_output = run_command(cmd, None, f"searchsploit query for {port}/{proto} ({query})", logger)
        output = _format_searchsploit_json(raw_output)
        results.append(f"### {port}/{proto} - {service} - {version}\n{output}\n")

    with open(exploit_out, "w") as f:
        f.write("\n".join(results))
    print(f"[+] Exploit suggestions saved to {exploit_out}")


# ----------------------------------------------------------------------------
# Module 3c (v3): Build Structured Findings (phases 1+2 - session.json)
# ----------------------------------------------------------------------------


def module_structured_findings(out_dir, logger=None):
    """
    Runs NVD + searchsploit lookups against the latest port scan in out_dir
    and writes session.json - the merged, structured "facts + CVEs" file
    that report generation (module_ai_report) and the eventual RAG/vector
    store step both consume. Delegates all the actual lookup work to
    session_builder.py / cve_lookup.py so this stays a thin menu wrapper.
    """
    print("\n--- Build Structured Findings (session.json) ---")
    if session_builder is None:
        print("[!] session_builder.py not found next to sudarshan.py - skipping. "
              "Copy it into the same folder to enable this option.")
        if logger:
            logger.warning("Structured findings skipped - session_builder.py not available")
        return None

    api_key = os.environ.get("NVD_API_KEY")
    if not api_key:
        print("[i] No $NVD_API_KEY set - NVD lookups will use the slower "
              "unauthenticated rate limit. That's fine, just slower.")

    try:
        session = session_builder.build_session(out_dir, api_key=api_key)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        if logger:
            logger.error(f"Structured findings failed | {e}")
        return None

    out_path = os.path.join(out_dir, "session.json")
    with open(out_path, "w") as f:
        json.dump(session, f, indent=2)

    print(f"[+] Structured findings saved to {out_path}")
    session_builder.print_summary(session)

    if logger:
        logger.info(f"SESSION BUILT | {out_path} | totals={session['totals']}")

    return out_path


# ----------------------------------------------------------------------------
# Module 3d (v3): Generate AI Report (phase 3 - Ollama narrative)
# ----------------------------------------------------------------------------


def module_ai_report(out_dir, logger=None):
    """
    Generates the narrative sections of a report from session.json using a
    local Ollama model, then assembles them with the deterministic facts
    table into a markdown report. Builds session.json first if it doesn't
    exist yet. All actual generation/grounding-check logic lives in
    report_generator.py.
    """
    print("\n--- Generate AI Report (Ollama) ---")
    if report_generator is None:
        print("[!] report_generator.py not found next to sudarshan.py - skipping. "
              "Copy it into the same folder to enable this option.")
        if logger:
            logger.warning("AI report skipped - report_generator.py not available")
        return None

    session_path = os.path.join(out_dir, "session.json")
    if not os.path.isfile(session_path):
        print("[i] No session.json yet for this target - building it first...")
        session_path = module_structured_findings(out_dir, logger)
        if not session_path:
            print("[!] Could not build structured findings - aborting AI report.")
            return None

    with open(session_path) as f:
        session = json.load(f)

    default_model = report_generator.DEFAULT_MODEL
    print("[i] On low-RAM / CPU-only machines, a smaller model (e.g. "
          "qwen2.5:3b-instruct) avoids swapping and section-generation "
          "timeouts. Type it explicitly - just pressing Enter accepts the "
          "bracketed default shown below.")
    model = input(f"Ollama model [{default_model}] > ").strip() or default_model
    ollama_url = input(
        f"Ollama URL [{report_generator.OLLAMA_DEFAULT_URL}] > "
    ).strip() or report_generator.OLLAMA_DEFAULT_URL
    use_rag = input(
        "Use local RAG/vector-store context if available? [Y/n] > "
    ).strip().lower() not in ("n", "no")

    generated, warnings, _ = report_generator.generate_report(
        session, model=model, url=ollama_url, use_rag=use_rag
    )
    report_md = report_generator.render_markdown(session, generated, warnings)

    ts = timestamp()
    base_name = f"ai_report_{ts}"
    out_path = os.path.join(out_dir, f"{base_name}.md")
    with open(out_path, "w") as f:
        f.write(report_md)

    print(f"[+] AI report saved to {out_path}")
    if warnings:
        print(f"[!] {len(warnings)} grounding warning(s) flagged - review the "
              f"Appendix in the report before sending it to anyone.")

    if logger:
        logger.info(f"AI REPORT GENERATED | {out_path} | model={model} | "
                     f"grounding_warnings={len(warnings)}")

    print("\nExport as: [1] Markdown only  [2] + Word (.docx)  "
          "[3] + PDF  [4] Both Word and PDF")
    export_choice = input("select option [1] > ").strip() or "1"
    export_formats = {
        "2": ["docx"],
        "3": ["pdf"],
        "4": ["docx", "pdf"],
    }.get(export_choice, [])

    if export_formats:
        export_results = report_generator.export_report(
            report_md, out_dir, base_name=base_name, formats=export_formats
        )
        for fmt, res in export_results.items():
            if res.get("ok"):
                print(f"[+] {fmt.upper()} report saved to {res['path']}")
                if logger:
                    logger.info(f"AI REPORT EXPORTED | {res['path']} | format={fmt}")
            else:
                print(f"[!] {fmt.upper()} export failed: {res.get('error')}")
                if logger:
                    logger.warning(f"AI REPORT EXPORT FAILED | format={fmt} | "
                                    f"{res.get('error')}")

    return out_path


# ----------------------------------------------------------------------------
# Module 3e (v3): Add reusable RAG context
# ----------------------------------------------------------------------------


def module_rag_context(logger=None):
    """
    Adds user-provided reference material to the local vector store used by
    report_generator.py. This is for past reports, CVE notes, exploit notes,
    remediation language, and other reusable reporting context.
    """
    print("\n--- Add RAG Context ---")
    if report_generator is None:
        print("[!] report_generator.py not found next to sudarshan.py - skipping.")
        if logger:
            logger.warning("RAG context ingest skipped - report_generator.py not available")
        return None

    print("[a] Seed starter context")
    print("[b] Ingest context file (.txt, .md, .json, .pdf, .docx)")
    choice = input("select action > ").strip().lower()

    ollama_url = input(
        f"Ollama URL [{report_generator.OLLAMA_DEFAULT_URL}] > "
    ).strip() or report_generator.OLLAMA_DEFAULT_URL

    if choice == "a":
        try:
            added = report_generator.seed_example_context(url=ollama_url)
        except RuntimeError as e:
            print(f"[!] Could not seed RAG context: {e}")
            if logger:
                logger.error(f"RAG seed failed | {e}")
            return None
        print(f"[+] Seeded {added} starter context chunk(s).")
        if logger:
            logger.info(f"RAG SEED | chunks={added}")
        return added

    if choice == "b":
        path = input("context file path > ").strip().strip('"')
        if not path:
            print("[!] No file path provided.")
            return None
        source_label = input("source label (optional) > ").strip() or None
        try:
            result = report_generator.ingest_context_file(
                path,
                source_label=source_label,
                url=ollama_url,
            )
        except (RuntimeError, FileNotFoundError) as e:
            print(f"[!] Could not ingest context: {e}")
            if logger:
                logger.error(f"RAG ingest failed | path={path} | {e}")
            return None
        print(f"[+] Ingested {result['chunks']} context chunk(s) from {result['path']}")
        if logger:
            logger.info(f"RAG INGEST | path={result['path']} | chunks={result['chunks']}")
        return result

    print("[!] Invalid selection.")
    return None


# ----------------------------------------------------------------------------
# Module 4: Subdomain Enumeration
# ----------------------------------------------------------------------------


def module_subdomain_enum(target, out_dir, logger=None):
    print("\n--- Subdomain Enumeration ---")
    if not tool_available("subfinder"):
        print("[!] subfinder not found. Install it (ProjectDiscovery) to use this module.")
        return None

    out_file = os.path.join(out_dir, f"subdomains_{timestamp()}.txt")
    cmd = ["subfinder", "-d", target, "-all", "-silent", "-o", out_file]
    run_command(cmd, None, "Running subfinder passive subdomain enumeration", logger)
    return out_file


# ----------------------------------------------------------------------------
# Module 5: Live Host / Service Probe
# ----------------------------------------------------------------------------


def resolve_projectdiscovery_httpx():
    """
    Resolve the ProjectDiscovery 'httpx' recon binary explicitly instead
    of trusting whatever 'httpx' resolves to via PATH. The Python
    'httpx[cli]' package (often pulled in transitively by other
    dependencies, e.g. an SDK that uses httpx as its HTTP client) installs
    its OWN 'httpx' command with a completely different, incompatible CLI
    (Click-based - 'Usage: httpx [OPTIONS] URL', 'Error: No such option
    ...'). If that ends up on PATH ahead of the real Go binary - which
    happens automatically the moment a venv is activated, since venv/bin
    is prepended to PATH by design - it silently shadows the real tool
    with no indication other than a confusing CLI error at scan time.
    Checking the known Go install location directly sidesteps re-fighting
    this every time PATH ordering changes (new shell, venv re-activation,
    etc), rather than relying on the user's PATH being in the right order.
    """
    known_path = os.path.join(os.path.expanduser("~"), "go", "bin", "httpx")
    if os.path.isfile(known_path) and os.access(known_path, os.X_OK):
        return known_path
    # Fall back to PATH lookup if it's not in the standard Go bin location -
    # better than refusing to run at all, just less guaranteed correct.
    return shutil.which("httpx")


def module_live_probe(target_or_file, out_dir, is_file=False, logger=None):
    print("\n--- Live Host / Service Probe ---")
    httpx_bin = resolve_projectdiscovery_httpx()
    if not httpx_bin:
        print("[!] httpx (ProjectDiscovery) not found. Install it to use this module.")
        return

    out_file = os.path.join(out_dir, f"live_hosts_{timestamp()}.txt")

    if is_file and os.path.isfile(target_or_file):
        cmd = [httpx_bin, "-l", target_or_file, "-status-code", "-title", "-tech-detect", "-o", out_file]
    else:
        cmd = [httpx_bin, "-u", target_or_file, "-status-code", "-title", "-tech-detect", "-o", out_file]

    run_command(cmd, None, "Running httpx live host / service probe", logger)


# ----------------------------------------------------------------------------
# Module 6: Active Directory Enumeration (stub)
# ----------------------------------------------------------------------------


def module_ad_enum(target, out_dir, logger=None):
    print("\n--- Active Directory Enumeration ---")
    print("This module is a stub. Recommended tools to wire in next:")
    print("  - crackmapexec smb <target> --shares / --users / --groups")
    print("  - enum4linux-ng <target>")
    print("  - ldapsearch -x -H ldap://<target> -b 'dc=domain,dc=com'")
    print("  - bloodhound-python -u <user> -p <pass> -d <domain> -c All -ns <dc_ip>")
    print("These require valid domain-context credentials or an authenticated")
    print("foothold in almost all cases — do not attempt against AD you do not")
    print("own or have explicit written authorization to test.")
    if logger:
        logger.info("AD enum module viewed (stub, no scan executed)")


# ----------------------------------------------------------------------------
# Report generation
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
    matches = sorted([f for f in os.listdir(out_dir) if f.startswith(prefix)])
    return os.path.join(out_dir, matches[-1]) if matches else None


def compute_risk_rating(vuln_text, exploit_text):
    vulnerable_findings = vuln_text.count("VULNERABLE")
    cves = sorted(set(CVE_PATTERN.findall(vuln_text)))
    exploit_hits = exploit_text.count("Exploit Title")

    score = 2 * vulnerable_findings + 3 * len(cves) + 1 * exploit_hits

    if score == 0:
        rating = "Low"
    elif score <= 5:
        rating = "Medium"
    elif score <= 15:
        rating = "High"
    else:
        rating = "Critical"

    return rating, score, vulnerable_findings, cves, exploit_hits


def generate_report(out_dir, logger=None):
    print("\n--- Generating Report ---")

    info_text = _read_if_exists(os.path.join(out_dir, "target_info.txt"))
    raw_target = "unknown"
    friendly_name = "unknown"
    for line in info_text.splitlines():
        if line.startswith("raw_target:"):
            raw_target = line.split(":", 1)[1].strip()
        if line.startswith("friendly_name:"):
            friendly_name = line.split(":", 1)[1].strip()

    hostdisc_text = _read_if_exists(_latest_file(out_dir, "hostdisc_"))
    portscan_text = _read_if_exists(_latest_file(out_dir, "portscan_"))
    vuln_text = _read_if_exists(_latest_file(out_dir, "vulnassess_"))
    exploit_text = _read_if_exists(_latest_file(out_dir, "exploits_"))
    live_text = _read_if_exists(_latest_file(out_dir, "live_hosts_"))
    webdir_text = _read_if_exists(_latest_file(out_dir, "webdir_"))
    subdomains_text = _read_if_exists(_latest_file(out_dir, "subdomains_"))

    rating, score, vulnerable_findings, cves, exploit_hits = compute_risk_rating(
        vuln_text, exploit_text
    )

    report_path = os.path.join(out_dir, f"report_{timestamp()}.md")
    generated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    lines = []
    lines.append("# Sudarshan Assessment Report")
    lines.append("")
    lines.append(f"**Target:** {raw_target}  ")
    lines.append(f"**Friendly name:** {friendly_name}  ")
    lines.append(f"**Generated:** {generated_at}")
    lines.append("")
    lines.append("> Heuristic report auto-generated from local scan output. "
                  "Risk rating is a weighted heuristic, not a CVSS-grade "
                  "assessment - verify all findings manually before reporting "
                  "them to a client or stakeholder.")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"- **Heuristic risk rating:** **{rating}** (score: {score})")
    lines.append(f"- Vulnerable findings flagged by nmap NSE: {vulnerable_findings}")
    lines.append(f"- Distinct CVEs referenced: {len(cves)}")
    lines.append(f"- Services with a matching local ExploitDB entry: {exploit_hits}")
    lines.append("")

    if cves:
        lines.append("## CVEs Identified")
        lines.append("")
        for cve in cves:
            lines.append(f"- {cve}")
        lines.append("")

    lines.append("## Host Discovery")
    lines.append("")
    lines.append("```")
    lines.append(hostdisc_text.strip() or "(no host discovery data)")
    lines.append("```")
    lines.append("")

    lines.append("## Port Scan")
    lines.append("")
    lines.append("```")
    lines.append(portscan_text.strip() or "(no port scan data)")
    lines.append("```")
    lines.append("")

    lines.append("## Vulnerability Assessment (nmap NSE vuln scripts)")
    lines.append("")
    lines.append("```")
    lines.append(vuln_text.strip() or "(no vulnerability scan data)")
    lines.append("```")
    lines.append("")

    lines.append("## Suggested Exploits (local ExploitDB via searchsploit)")
    lines.append("")
    lines.append("```")
    lines.append(exploit_text.strip() or "(no exploit lookup data)")
    lines.append("```")
    lines.append("")

    if subdomains_text:
        lines.append("## Subdomain Enumeration")
        lines.append("")
        lines.append("```")
        lines.append(subdomains_text.strip())
        lines.append("```")
        lines.append("")

    if webdir_text:
        lines.append("## Web / Directory Enumeration")
        lines.append("")
        lines.append("```")
        lines.append(webdir_text.strip())
        lines.append("```")
        lines.append("")

    if live_text:
        lines.append("## Live Host / Service Probe")
        lines.append("")
        lines.append("```")
        lines.append(live_text.strip())
        lines.append("```")
        lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    if rating in ("High", "Critical"):
        lines.append("- Prioritize patching services tied to the CVEs listed above.")
        lines.append("- Validate each ExploitDB match manually before assuming exploitability.")
        lines.append("- Re-scan after remediation to confirm findings are closed.")
    elif rating == "Medium":
        lines.append("- Review flagged NSE findings and confirm exposure/impact.")
        lines.append("- Track and schedule remediation for outdated service versions.")
    else:
        lines.append("- No high-signal findings from this pass. Consider deeper manual "
                      "testing (auth flows, business logic, AD if applicable).")
    lines.append("")

    with open(report_path, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Markdown report saved to {report_path}")
    if logger:
        logger.info(f"REPORT GENERATED | {report_path} | rating={rating} | score={score}")

    if tool_available("pandoc"):
        pdf_path = report_path.replace(".md", ".pdf")
        cmd = ["pandoc", report_path, "-o", pdf_path]
        run_command(cmd, None, "Converting report to PDF via pandoc", logger)
        if os.path.isfile(pdf_path):
            print(f"[+] PDF report saved to {pdf_path}")
    else:
        print("[i] pandoc not found - skipping PDF conversion. "
              "Install with: sudo apt install pandoc")

    return report_path


# ----------------------------------------------------------------------------
# Auto chains
# ----------------------------------------------------------------------------


def auto_chain_web(target, out_dir, logger=None):
    print("\n=== Full Auto Chain: Web ===")
    subs_file = module_subdomain_enum(target, out_dir, logger)
    module_web_dir_enum(target, out_dir, logger)
    if subs_file and os.path.isfile(subs_file):
        module_live_probe(subs_file, out_dir, is_file=True, logger=logger)
    else:
        module_live_probe(target, out_dir, is_file=False, logger=logger)
    generate_report(out_dir, logger)


def auto_chain_network(target, out_dir, logger=None):
    print("\n=== Full Auto Chain: Network ===")
    module_host_discovery(target, out_dir, logger)
    port_scan_file = module_port_scan(target, out_dir, logger)
    module_vuln_and_exploit(target, out_dir, port_scan_file, logger)
    module_live_probe(target, out_dir, is_file=False, logger=logger)
    generate_report(out_dir, logger)

    if session_builder is not None:
        print("\n[*] Auto chain: building structured findings (session.json)...")
        module_structured_findings(out_dir, logger)

        if report_generator is not None:
            ans = input(
                "\nGenerate an AI narrative report now via Ollama? [y/N] > "
            ).strip().lower()
            if ans == "y":
                module_ai_report(out_dir, logger)
            else:
                print("[i] Skipped. Run option [12] any time to generate it "
                      "from the saved session.json.")


# ----------------------------------------------------------------------------
# Results viewer
# ----------------------------------------------------------------------------


def view_results():
    if not os.path.isdir(BASE_DIR):
        print("[!] No results yet.")
        return None
    targets = sorted(
        d for d in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, d)) and not d.startswith(".")
    )
    if not targets:
        print("[!] No results yet.")
        return None

    print("\nSaved targets:")
    for i, t in enumerate(targets, 1):
        print(f"  [{i}] {t}")

    choice = input("select target number to view files > ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(targets)):
        print("[!] Invalid selection.")
        return None

    tdir = os.path.join(BASE_DIR, targets[int(choice) - 1])
    for f in sorted(os.listdir(tdir)):
        print(f"  - {os.path.join(tdir, f)}")
    return tdir


# ----------------------------------------------------------------------------
# Main loop
# ----------------------------------------------------------------------------


def main():
    os.makedirs(BASE_DIR, exist_ok=True)
    print(BANNER)

    print("[i] AI pipeline modules: "
          f"cve_lookup={'loaded' if cve_lookup else 'MISSING'}, "
          f"session_builder={'loaded' if session_builder else 'MISSING'}, "
          f"report_generator={'loaded' if report_generator else 'MISSING'}"
          + ("" if (cve_lookup and session_builder and report_generator)
             else "  -> options [11]/[12] will be limited/disabled until "
                  "those files sit next to sudarshan.py"))

    valid_choices = {str(n) for n in range(14)}

    while True:
        print(MENU)
        choice = input("sudarshan > ").strip()

        if choice == "0":
            print("Exiting. Stay authorized.")
            sys.exit(0)

        if choice == "9":
            view_results()
            continue

        if choice == "10":
            tdir = view_results()
            if tdir:
                logger = get_logger(tdir)
                generate_report(tdir, logger)
            continue

        if choice == "11":
            tdir = view_results()
            if tdir:
                logger = get_logger(tdir)
                module_structured_findings(tdir, logger)
            continue

        if choice == "12":
            tdir = view_results()
            if tdir:
                logger = get_logger(tdir)
                module_ai_report(tdir, logger)
            continue

        if choice == "13":
            module_rag_context()
            continue

        if choice not in valid_choices:
            print("[!] Invalid option.")
            continue

        target = prompt_target()
        if not target:
            continue

        friendly_name = prompt_friendly_name()
        out_dir, logger = setup_target(target, friendly_name)

        if not confirm_authorization(target, logger):
            print("[!] Authorization not confirmed. Aborting.")
            continue

        if choice == "1":
            module_web_dir_enum(target, out_dir, logger)
        elif choice == "2":
            module_host_discovery(target, out_dir, logger)
        elif choice == "3":
            module_port_scan(target, out_dir, logger)
        elif choice == "4":
            module_subdomain_enum(target, out_dir, logger)
        elif choice == "5":
            module_live_probe(target, out_dir, logger=logger)
        elif choice == "6":
            module_ad_enum(target, out_dir, logger)
        elif choice == "7":
            auto_chain_web(target, out_dir, logger)
        elif choice == "8":
            auto_chain_network(target, out_dir, logger)


if __name__ == "__main__":
    main()
