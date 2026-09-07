#!/usr/bin/env python3
"""Quick check: print the real CVE descriptions for a given port's finding
from cve_exploit_findings (NOT port_scan.services, which never has CVEs).

Usage: python3 check_finding_cves.py <session.json path> <port>
Example: python3 check_finding_cves.py session.json 53
"""
import json
import sys

if len(sys.argv) < 3:
    print("Usage: python3 check_finding_cves.py <session.json path> <port>")
    sys.exit(1)

path = sys.argv[1]
port = sys.argv[2]

with open(path) as f:
    session = json.load(f)

for finding in session.get("cve_exploit_findings", []):
    if finding.get("port") == port:
        print(f"Service: {finding['service']} - {finding['version_raw']}")
        print(f"CVE count: {len(finding.get('cves', []))}")
        print()
        for cve in finding.get("cves", []):
            print(f"{cve['id']} (CVSS {cve.get('cvss_score')}, {cve.get('severity')}):")
            print(f"  {cve.get('description')}")
            print()
        break
else:
    print(f"No finding with port {port} found in cve_exploit_findings.")
