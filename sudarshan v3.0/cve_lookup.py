#!/usr/bin/env python3
"""
Sudarshan :: CVE + Exploit Lookup Engine   (cve_lookup.py)
Phase 1 of the Sudarshan -> AI report pipeline.

WHAT THIS IS
------------
A standalone, no-AI module that turns raw service/version data (from an
nmap -sV scan, or typed in manually) into ONE structured JSON file of
facts: confirmed CVEs (from the live NVD database) + confirmed local
exploits (from searchsploit / ExploitDB). Nothing here is generated or
guessed - every record is either an NVD hit or a searchsploit hit.

This is intentionally decoupled from sudarshan.py so it can be built,
tested, and iterated on by itself. Once it's solid, module_vuln_and_exploit()
in sudarshan.py can import build_findings_for_services() directly instead of
just dumping raw searchsploit text to a file.

TWO INDEPENDENT SOURCES
------------------------
  1. NVD REST API v2.0 (services.nvd.nist.gov) - live, needs internet
  2. searchsploit --json (local ExploitDB mirror) - offline, needs the
     exploitdb package installed (default on Kali)
Each is queried independently and failures in one don't kill the other -
if you're offline you'll still get exploitdb hits, if searchsploit isn't
installed you'll still get NVD hits.

USAGE
-----
  # From an existing nmap -sV normal-output scan file:
  python3 cve_lookup.py --nmap-file portscan.txt --out findings.json

  # Manual service entries, no nmap file needed:
  python3 cve_lookup.py --service "22/tcp:ssh:OpenSSH 7.2p2" \\
                         --service "80/tcp:http:Apache httpd 2.4.49" \\
                         --out findings.json

  # One-off ad hoc lookup, prints to stdout, no file needed:
  python3 cve_lookup.py --query "Apache httpd 2.4.49"

  # Skip one of the two sources:
  python3 cve_lookup.py --nmap-file portscan.txt --nvd-only
  python3 cve_lookup.py --nmap-file portscan.txt --exploitdb-only

FLAGS OF NOTE
-------------
  --api-key / $NVD_API_KEY   Free key = 50 req/30s instead of 5 req/30s.
                              Get one: https://nvd.nist.gov/developers/request-an-api-key
  --no-cache                 Force fresh NVD lookups, ignore the local cache.
  --max-cves N                Cap CVEs stored per service (default 8).
  --summary                  Print a quick human-readable table after the run.

CHANGELOG
---------
v1 (phase 1) - initial standalone NVD + searchsploit lookup, JSON output,
               response caching, nmap-file parsing (kept in sync with the
               parser in sudarshan.py so results line up).
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import datetime

try:
    import requests
except ImportError:
    requests = None

# ----------------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------------

BASE_DIR = os.environ.get(
    "SUDARSHAN_RESULTS_DIR",
    os.path.join(os.path.expanduser("~"), "sudarshan-results"),
)
CACHE_DIR = os.path.join(BASE_DIR, ".cache")
NVD_CACHE_FILE = os.path.join(CACHE_DIR, "nvd_cache.json")
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days - version/CVE data doesn't churn hourly

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD public rate limit: 5 req/30s (no key) or 50 req/30s (with key).
# Sleep this long *between* calls to stay safely under it.
NVD_SLEEP_NO_KEY = 6.5
NVD_SLEEP_WITH_KEY = 0.7

DEFAULT_MAX_CVES = 8


# ----------------------------------------------------------------------------
# Small utilities
# ----------------------------------------------------------------------------


def tool_available(name):
    return shutil.which(name) is not None


def now_iso():
    return datetime.datetime.now().isoformat()


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# ----------------------------------------------------------------------------
# nmap parsing (kept in sync with sudarshan.py's parse_services_from_nmap)
# ----------------------------------------------------------------------------


def parse_services_from_nmap(port_scan_file):
    """
    Parse an nmap -sV normal-output file for lines like:
      80/tcp   open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2)
    Returns a list of dicts: {port, proto, service, version_raw}.
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
                services.append(
                    {
                        "port": port,
                        "proto": proto,
                        "service": service,
                        "version_raw": version.strip(),
                    }
                )
    return services


def parse_service_arg(raw):
    """
    Parse a manually-typed --service value: 'port/proto:service:version'
    e.g. '22/tcp:ssh:OpenSSH 7.2p2'. proto/service can be blank
    ('22::OpenSSH 7.2p2' works too).
    """
    m = re.match(r"^(\d+)(?:/(tcp|udp))?:([^:]*):(.*)$", raw.strip())
    if not m:
        raise ValueError(
            f"Bad --service value: {raw!r}. Expected 'port/proto:service:version', "
            f"e.g. '80/tcp:http:Apache httpd 2.4.49'"
        )
    port, proto, service, version = m.groups()
    return {
        "port": port,
        "proto": proto or "tcp",
        "service": service or "unknown",
        "version_raw": version.strip(),
    }


def simplify_query(version_raw):
    """
    Strip parenthetical noise nmap tends to append (OS hints, extra module
    info) so the search query is cleaner for both NVD keyword search and
    searchsploit, e.g.:
      'Apache httpd 2.2.8 ((Ubuntu) DAV/2)' -> 'Apache httpd 2.2.8'
    """
    cleaned = version_raw
    # nmap sometimes nests parens e.g. '((Ubuntu) DAV/2)' - strip repeatedly
    # until stable so nested groups don't leave stray characters behind.
    prev = None
    while prev != cleaned:
        prev = cleaned
        cleaned = re.sub(r"\([^()]*\)", "", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned or version_raw.strip()


NO_LETTERS_RE = re.compile(r"^[\d\s.\-#/]*$")


def is_low_signal_query(text):
    """
    A cleaned version string with no letters at all - e.g. an RPC service
    like 'nlockmgr' whose version_raw is '1-4 (RPC #100021)' reduces, after
    simplify_query() strips the parenthetical RPC number, to just '1-4' -
    carries essentially zero product-identifying information.

    Sending a bare number/dash string to NVD's keywordSearch doesn't return
    "no results", it returns whatever CVEs happen to contain that character
    sequence anywhere in their text - effectively random, unrelated CVEs
    that look exactly like confirmed matches once they're in findings.json.
    Better to skip the lookup and say so honestly than store a fake match.
    """
    return not text or bool(NO_LETTERS_RE.match(text))


# ----------------------------------------------------------------------------
# Local NVD response cache (keeps repeated dev runs fast + off the rate limit)
# ----------------------------------------------------------------------------


def _cache_key(query):
    return hashlib.sha256(query.strip().lower().encode()).hexdigest()


def _load_cache():
    if not os.path.isfile(NVD_CACHE_FILE):
        return {}
    try:
        with open(NVD_CACHE_FILE) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_cache(cache):
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(NVD_CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def _cache_get(cache, query):
    entry = cache.get(_cache_key(query))
    if not entry:
        return None
    if time.time() - entry.get("cached_at", 0) > CACHE_TTL_SECONDS:
        return None
    return entry.get("cves")


def _cache_put(cache, query, cves):
    cache[_cache_key(query)] = {
        "query": query,
        "cached_at": time.time(),
        "cves": cves,
    }


# ----------------------------------------------------------------------------
# NVD lookup
# ----------------------------------------------------------------------------


def _extract_cve_record(vuln_entry):
    """Pull the fields we actually use out of one NVD 'vulnerabilities[]' item."""
    cve = vuln_entry.get("cve", {})
    cve_id = cve.get("id", "UNKNOWN")

    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break

    cvss_score = None
    severity = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get("cvssData", {})
            cvss_score = data.get("baseScore")
            severity = data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
            break

    return {
        "id": cve_id,
        "description": description[:400],  # keep findings.json readable/portable
        "cvss_score": cvss_score,
        "severity": severity,
        "published": cve.get("published"),
    }


def query_nvd(query, api_key=None, cache=None, max_results=8, use_cache=True):
    """
    Query NVD keywordSearch for a service/version string. Returns a list of
    CVE dicts (possibly empty). Uses/updates the on-disk cache when given.
    """
    if use_cache and cache is not None:
        cached = _cache_get(cache, query)
        if cached is not None:
            return cached[:max_results]

    if requests is None:
        eprint("[!] 'requests' library not installed - skipping NVD lookups. "
               "Install with: pip install requests")
        return []

    params = {"keywordSearch": query, "resultsPerPage": max_results}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_ENDPOINT, params=params, headers=headers, timeout=20)
    except requests.exceptions.RequestException as e:
        eprint(f"[!] NVD request failed for {query!r}: {e}")
        return []

    if resp.status_code == 403:
        eprint(f"[!] NVD returned 403 for {query!r} - likely rate-limited. "
               f"Consider setting NVD_API_KEY.")
        return []
    if resp.status_code != 200:
        eprint(f"[!] NVD returned HTTP {resp.status_code} for {query!r}")
        return []

    try:
        data = resp.json()
    except ValueError:
        eprint(f"[!] NVD returned non-JSON response for {query!r}")
        return []

    cves = [_extract_cve_record(v) for v in data.get("vulnerabilities", [])]

    if cache is not None:
        _cache_put(cache, query, cves)

    return cves[:max_results]


# ----------------------------------------------------------------------------
# searchsploit (ExploitDB) lookup
# ----------------------------------------------------------------------------


def query_searchsploit(query):
    """
    Run `searchsploit -j <query>` and return a list of exploit dicts.
    Returns [] if searchsploit isn't installed or nothing matches.
    """
    if not tool_available("searchsploit"):
        return []

    # NOTE: searchsploit's long-form flags aren't universal across versions -
    # some builds (confirmed on a real Kali install) only accept the short
    # forms and error out on '--json'/'--nocolour' with "illegal option",
    # which silently produced zero exploits for every single lookup. -j and
    # --disable-colour are the flags that actually work.
    cmd = ["searchsploit", "-j", "--disable-colour", query]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError) as e:
        eprint(f"[!] searchsploit failed for {query!r}: {e}")
        return []

    if proc.returncode != 0 or not proc.stdout.strip():
        if proc.stderr.strip():
            eprint(f"[!] searchsploit error for {query!r}: {proc.stderr.strip()[:200]}")
        return []

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        eprint(f"[!] searchsploit returned non-JSON output for {query!r}")
        return []

    results = []
    for entry in data.get("RESULTS_EXPLOIT", []):
        results.append(
            {
                "title": entry.get("Title"),
                "edb_id": entry.get("EDB-ID"),
                "path": entry.get("Path"),
                "type": entry.get("Type"),
                "platform": entry.get("Platform"),
                "date": entry.get("Date_Published"),
            }
        )
    return results


# ----------------------------------------------------------------------------
# Building findings
# ----------------------------------------------------------------------------


HAS_DIGIT_RE = re.compile(r"\d")

# A small, curated set of services where nmap's banner text reliably fails
# to match NVD's actual CVE-description phrasing, missing well-known,
# high-severity CVEs entirely (observed: 'microsoft-ds' with a banner like
# 'Microsoft Windows Server 2008 R2 - 2012 microsoft-ds' returns ZERO CVEs
# via NVD keyword search - including missing MS17-010/EternalBlue, arguably
# the single most famous Windows SMB CVE set, because NVD's real CVE-2017-
# 014x descriptions talk about 'the SMBv1 server' and 'Windows SMB Remote
# Code Execution Vulnerability', not 'microsoft-ds'). This is a silent
# false-negative, not noise - worse than the low-signal-query problem,
# since it looks identical to 'genuinely nothing found'. For each of these
# service names, also try a second, better-targeted query and merge
# results (deduplicated by CVE ID) rather than relying on the raw banner
# alone. This is intentionally a short, named list - not a general fix for
# NVD recall, just a patch for specific, high-value known gaps.
SERVICE_QUERY_ALIASES = {
    "microsoft-ds": ["Windows SMB Remote Code Execution", "SMBv1 server"],
    "netbios-ssn": ["Windows SMB"],
}


def build_finding_for_service(
    service_entry,
    api_key=None,
    cache=None,
    use_nvd=True,
    use_exploitdb=True,
    max_cves=DEFAULT_MAX_CVES,
    sleep_between_nvd_calls=None,
):
    """
    Takes one {port, proto, service, version_raw} dict, queries NVD and/or
    searchsploit, and returns the fully populated finding dict.
    """
    cleaned_version = simplify_query(service_entry["version_raw"])
    query = cleaned_version or service_entry["service"]

    cves = []
    skip_reason = None
    precision_note = None
    low_signal = is_low_signal_query(cleaned_version)

    if use_nvd:
        if low_signal:
            # e.g. RPC services (nlockmgr, mountd, status, rpcbind) whose
            # version_raw is just an RPC program number in parens - after
            # cleanup there's no product name left to search on. Skip
            # rather than send a bare digit/dash string to NVD and get
            # back an unrelated CVE that happens to match on nothing more
            # than a stray number.
            skip_reason = (
                f"No identifying product/version text to search NVD with "
                f"(version reduced to {cleaned_version!r} after removing RPC/"
                f"parenthetical noise) - lookup skipped rather than risk an "
                f"unreliable keyword match."
            )
            eprint(f"    [!] {service_entry['service']} "
                   f"({service_entry['port']}/{service_entry['proto']}): {skip_reason}")
        else:
            cves = query_nvd(query, api_key=api_key, cache=cache, max_results=max_cves)

            alias_queries = SERVICE_QUERY_ALIASES.get(service_entry["service"].lower(), [])
            for alias_query in alias_queries:
                if sleep_between_nvd_calls:
                    time.sleep(sleep_between_nvd_calls)
                alias_results = query_nvd(alias_query, api_key=api_key, cache=cache, max_results=max_cves)
                if alias_results:
                    eprint(f"    [+] {service_entry['service']} "
                           f"({service_entry['port']}/{service_entry['proto']}): "
                           f"alias query {alias_query!r} found "
                           f"{len(alias_results)} additional CVE(s)")
                existing_ids = {c["id"] for c in cves}
                for c in alias_results:
                    if c["id"] not in existing_ids:
                        cves.append(c)
                        existing_ids.add(c["id"])
                cves = cves[:max_cves]

            if not HAS_DIGIT_RE.search(cleaned_version):
                # e.g. nmap couldn't fingerprint a version for this service
                # (query ended up as just 'Linux telnetd' - a bare product
                # category, no version number to anchor the match). NVD's
                # keyword search still runs and can return real CVEs, but
                # with no version to narrow it, it can also match unrelated
                # products that just happen to share the same generic name
                # (observed: a Linux telnetd query pulling in an unrelated
                # FiberHome router CVE). Not skipped - genuinely useful
                # matches are common here too - but flagged so it's visibly
                # lower-confidence for manual review rather than presented
                # with the same certainty as a version-anchored match.
                precision_note = (
                    f"NVD query {query!r} has no version number, only a "
                    f"product/service name - results may include CVEs for "
                    f"unrelated products that happen to share this name. "
                    f"Worth a quick manual sanity check on these CVEs."
                )
                eprint(f"    [!] {service_entry['service']} "
                       f"({service_entry['port']}/{service_entry['proto']}): {precision_note}")
        if sleep_between_nvd_calls:
            time.sleep(sleep_between_nvd_calls)

    exploits = []
    if use_exploitdb:
        if low_signal:
            # Same reasoning as the NVD skip above, but this bug bit twice:
            # searchsploit's fuzzy matching on a bare '1-4'/'1'/'2' query
            # doesn't return nothing, it returns a flood of near-random
            # matches (observed: 95,461 "exploits" for one Metasploitable2
            # scan) since almost every exploit title contains a stray digit
            # somewhere. Skip here too rather than treat that flood as real.
            if not skip_reason:
                eprint(f"    [!] {service_entry['service']} "
                       f"({service_entry['port']}/{service_entry['proto']}): "
                       f"skipping searchsploit too - same low-signal query "
                       f"{cleaned_version!r} would return a flood of unrelated "
                       f"matches, not a real 'no exploits found' result.")
        else:
            exploits = query_searchsploit(query)

            # Same alias mechanism as the NVD lookup above, and for the same
            # reason: searchsploit's title/path matching on the raw nmap
            # banner ('Microsoft Windows Server 2008 R2 - 2012 microsoft-ds')
            # doesn't hit ExploitDB entries titled things like 'MS17-010'
            # or 'EternalBlue' - the wording just doesn't overlap. Without
            # this, a service could correctly show real CVEs (via the NVD
            # alias fix) while still showing zero exploits, which looks
            # like 'no public exploit exists' for one of the most famous
            # exploited vulnerabilities in Windows history. Merge/dedupe
            # by EDB-ID so the same exploit isn't listed twice.
            alias_queries = SERVICE_QUERY_ALIASES.get(service_entry["service"].lower(), [])
            existing_edb_ids = {e.get("edb_id") for e in exploits if e.get("edb_id")}
            for alias_query in alias_queries:
                alias_exploits = query_searchsploit(alias_query)
                if alias_exploits:
                    eprint(f"    [+] {service_entry['service']} "
                           f"({service_entry['port']}/{service_entry['proto']}): "
                           f"alias query {alias_query!r} found "
                           f"{len(alias_exploits)} additional exploit(s)")
                for e in alias_exploits:
                    edb_id = e.get("edb_id")
                    if edb_id and edb_id in existing_edb_ids:
                        continue
                    exploits.append(e)
                    if edb_id:
                        existing_edb_ids.add(edb_id)

    result = {
        "port": service_entry["port"],
        "proto": service_entry["proto"],
        "service": service_entry["service"],
        "version_raw": service_entry["version_raw"],
        "query_used": query,
        "cves": cves,
        "exploits": exploits,
    }
    if skip_reason:
        result["nvd_lookup_skipped_reason"] = skip_reason
    if precision_note:
        result["nvd_query_precision_note"] = precision_note
    return result


def build_findings_for_services(
    services,
    api_key=None,
    use_nvd=True,
    use_exploitdb=True,
    use_cache=True,
    max_cves=DEFAULT_MAX_CVES,
):
    """
    Runs build_finding_for_service() over a list of service dicts and
    returns the list of findings. Handles cache load/save and NVD rate
    limiting so callers (CLI or sudarshan.py) don't have to think about it.
    """
    cache = _load_cache() if use_cache else None
    sleep_time = NVD_SLEEP_WITH_KEY if api_key else NVD_SLEEP_NO_KEY

    findings = []
    for i, svc in enumerate(services, 1):
        label = f"{svc['port']}/{svc['proto']} {svc['service']}"
        print(f"[*] ({i}/{len(services)}) Looking up: {label} - {svc['version_raw']}")
        finding = build_finding_for_service(
            svc,
            api_key=api_key,
            cache=cache,
            use_nvd=use_nvd,
            use_exploitdb=use_exploitdb,
            max_cves=max_cves,
            # don't sleep after the very last NVD call, no point
            sleep_between_nvd_calls=sleep_time if use_nvd and i < len(services) else None,
        )
        print(f"    -> {len(finding['cves'])} CVE(s), {len(finding['exploits'])} exploit(s)")
        findings.append(finding)

    if use_cache and cache is not None:
        _save_cache(cache)

    return findings


# ----------------------------------------------------------------------------
# Output helpers
# ----------------------------------------------------------------------------


def print_summary(findings):
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    total_cves, total_exploits = 0, 0
    for f in findings:
        n_cves, n_exp = len(f["cves"]), len(f["exploits"])
        total_cves += n_cves
        total_exploits += n_exp
        flag = "  <-- attention" if (n_cves or n_exp) else ""
        print(f"  {f['port']}/{f['proto']:<3} {f['service']:<10} "
              f"{n_cves:>2} CVEs  {n_exp:>2} exploits{flag}")
    print("-" * 60)
    print(f"  TOTAL: {total_cves} CVEs, {total_exploits} exploits across "
          f"{len(findings)} service(s)")
    print("=" * 60)


def save_findings(findings, out_path, target="unknown", source_nmap_file=None):
    payload = {
        "target": target,
        "generated_at": now_iso(),
        "source_nmap_file": source_nmap_file,
        "findings": findings,
    }
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)
    print(f"\n[+] Structured findings saved to {out_path}")
    return out_path


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Sudarshan Phase 1: NVD + searchsploit lookup -> structured JSON findings.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = p.add_mutually_exclusive_group()
    src.add_argument("--nmap-file", help="Path to an nmap -sV normal-output (-oN) file")
    src.add_argument("--query", help="One-off ad hoc lookup, prints result, no service context")

    p.add_argument(
        "--service",
        action="append",
        default=[],
        help="Manual service entry 'port/proto:service:version' (repeatable)",
    )
    p.add_argument("--target", default=None, help="Label for the 'target' field in the output JSON")
    p.add_argument("--out", default=None, help="Output JSON path (default: ./findings_<timestamp>.json)")
    p.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"),
                    help="NVD API key (or set $NVD_API_KEY)")
    p.add_argument("--max-cves", type=int, default=DEFAULT_MAX_CVES,
                    help=f"Max CVEs to keep per service (default {DEFAULT_MAX_CVES})")
    p.add_argument("--no-cache", action="store_true", help="Ignore/skip the local NVD cache")
    p.add_argument("--nvd-only", action="store_true", help="Skip searchsploit, NVD only")
    p.add_argument("--exploitdb-only", action="store_true", help="Skip NVD, searchsploit only")
    p.add_argument("--summary", action="store_true", help="Print a human-readable summary table")
    return p


def main():
    args = build_arg_parser().parse_args()

    if args.nvd_only and args.exploitdb_only:
        eprint("[!] --nvd-only and --exploitdb-only are mutually exclusive.")
        sys.exit(1)

    use_nvd = not args.exploitdb_only
    use_exploitdb = not args.nvd_only
    use_cache = not args.no_cache

    # --- Ad hoc single query mode: just print, don't require --out ---
    if args.query:
        cache = _load_cache() if use_cache else None
        cves = query_nvd(args.query, api_key=args.api_key, cache=cache,
                          max_results=args.max_cves) if use_nvd else []
        exploits = query_searchsploit(args.query) if use_exploitdb else []
        if use_cache and cache is not None:
            _save_cache(cache)

        result = {"query": args.query, "cves": cves, "exploits": exploits}
        print(json.dumps(result, indent=2))
        if args.out:
            save_findings([result], args.out, target=args.target or args.query)
        return

    # --- Gather services from nmap file and/or manual --service entries ---
    services = []
    if args.nmap_file:
        services = parse_services_from_nmap(args.nmap_file)
        if not services:
            eprint(f"[!] No open services parsed from {args.nmap_file}. "
                   f"Make sure it's an nmap -sV normal-output (-oN) file.")
    for raw in args.service:
        try:
            services.append(parse_service_arg(raw))
        except ValueError as e:
            eprint(f"[!] {e}")
            sys.exit(1)

    if not services:
        eprint("[!] No services to look up. Use --nmap-file, --service, or --query. "
               "Run with -h for examples.")
        sys.exit(1)

    findings = build_findings_for_services(
        services,
        api_key=args.api_key,
        use_nvd=use_nvd,
        use_exploitdb=use_exploitdb,
        use_cache=use_cache,
        max_cves=args.max_cves,
    )

    out_path = args.out or f"findings_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    save_findings(findings, out_path, target=args.target or "unknown",
                  source_nmap_file=args.nmap_file)

    if args.summary:
        print_summary(findings)


if __name__ == "__main__":
    main()
