"""Shared pytest setup: make the project importable and provide a small,
realistic session.json-shaped fixture used by the grounding/grouping tests."""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (ROOT, os.path.join(ROOT, "web_terminal")):
    if p not in sys.path:
        sys.path.insert(0, p)


def cve(cve_id, score=None, desc="", severity="HIGH"):
    d = {"id": cve_id, "description": desc, "severity": severity}
    if score is not None:
        d["cvss_score"] = score
    return d


def finding(port, service, version, cves=(), exploits=(), proto="tcp"):
    return {
        "port": str(port), "proto": proto, "service": service, "version_raw": version,
        "cves": list(cves), "exploits": list(exploits),
    }


@pytest.fixture
def make_cve():
    return cve


@pytest.fixture
def make_finding():
    return finding


@pytest.fixture
def session():
    """vsftpd backdoor (9.8) + a Samba pair on 139/445 sharing the same CVEs
    + OpenSSH with a medium CVE + a service with no evidence."""
    samba = [cve("CVE-2017-7494", 7.5, "Samba allows remote attackers to execute arbitrary code")]
    return {
        "target": "10.0.0.5",
        "cve_exploit_findings": [
            finding(21, "ftp", "vsftpd 2.3.4",
                    [cve("CVE-2011-2523", 9.8, "vsftpd 2.3.4 contains a backdoor which opens a shell on port 6200/tcp")],
                    [{"title": "vsftpd 2.3.4 - Backdoor Command Execution", "edb_id": "17491"}]),
            finding(22, "ssh", "OpenSSH 7.2p2", [cve("CVE-2016-6210", 5.9, "user enumeration via timing", "MEDIUM")]),
            finding(139, "netbios-ssn", "Samba smbd 3.X", samba),
            finding(445, "microsoft-ds", "Samba smbd 3.X", samba),
            finding(80, "http", "nginx 1.18"),
        ],
        "vulnerability_scan": {"cves_referenced_in_scan": ["CVE-2008-4250"]},
    }
