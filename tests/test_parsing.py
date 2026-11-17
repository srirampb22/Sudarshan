"""nmap / service parsing (cve_lookup + session_builder)."""
import cve_lookup
import session_builder

NMAP_SV = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-27 10:00 IST
Nmap scan report for 10.0.0.5
Host is up (0.0010s latency).
PORT     STATE  SERVICE     VERSION
21/tcp   open   ftp         vsftpd 2.3.4
22/tcp   open   ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
80/tcp   open   http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
139/tcp  open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
53/udp   open   domain      ISC BIND 9.4.2
23/tcp   closed telnet
25/tcp   filtered smtp
Service detection performed.
"""


def test_parse_services_from_nmap(tmp_path):
    f = tmp_path / "portscan.txt"
    f.write_text(NMAP_SV)
    services = cve_lookup.parse_services_from_nmap(str(f))
    assert [(s["port"], s["proto"], s["service"]) for s in services] == [
        ("21", "tcp", "ftp"), ("22", "tcp", "ssh"), ("80", "tcp", "http"),
        ("139", "tcp", "netbios-ssn"), ("53", "udp", "domain"),
    ]                                                      # closed/filtered ports are NOT services
    assert services[0]["version_raw"] == "vsftpd 2.3.4"
    assert services[2]["version_raw"] == "Apache httpd 2.2.8 ((Ubuntu) DAV/2)"


def test_parse_services_missing_or_empty_file(tmp_path):
    assert cve_lookup.parse_services_from_nmap(None) == []
    assert cve_lookup.parse_services_from_nmap(str(tmp_path / "nope.txt")) == []
    empty = tmp_path / "e.txt"
    empty.write_text("")
    assert cve_lookup.parse_services_from_nmap(str(empty)) == []


def test_simplify_query_strips_nested_parentheses():
    assert cve_lookup.simplify_query("Apache httpd 2.2.8 ((Ubuntu) DAV/2)") == "Apache httpd 2.2.8"
    assert cve_lookup.simplify_query("OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)") == "OpenSSH 4.7p1 Debian 8ubuntu1"
    assert cve_lookup.simplify_query("vsftpd 2.3.4") == "vsftpd 2.3.4"
    assert cve_lookup.simplify_query("(only parens)") == "(only parens)"      # never returns empty


def test_parse_service_arg():
    assert cve_lookup.parse_service_arg("22/tcp:ssh:OpenSSH 7.2p2") == {
        "port": "22", "proto": "tcp", "service": "ssh", "version_raw": "OpenSSH 7.2p2"}
    assert cve_lookup.parse_service_arg("22::OpenSSH 7.2p2") == {
        "port": "22", "proto": "tcp", "service": "unknown", "version_raw": "OpenSSH 7.2p2"}
    assert cve_lookup.parse_service_arg("53/udp:domain:BIND 9")["proto"] == "udp"


def test_parse_service_arg_rejects_garbage():
    import pytest
    for bad in ("ssh", "abc:ssh:x", "22/tcp"):
        with pytest.raises(ValueError):
            cve_lookup.parse_service_arg(bad)


def test_low_signal_query_detection():
    assert cve_lookup.is_low_signal_query("2.3.4")
    assert cve_lookup.is_low_signal_query("")
    assert not cve_lookup.is_low_signal_query("vsftpd 2.3.4")


def test_parse_host_discovery():
    text = ("Nmap scan report for 10.0.0.1\nHost is up (0.001s latency).\n"
            "Nmap scan report for web.lab (10.0.0.2)\nHost is up.\n"
            "Nmap scan report for 10.0.0.3\n")
    assert session_builder.parse_host_discovery(text) == [
        {"host": "10.0.0.1", "up": True},
        {"host": "web.lab (10.0.0.2)", "up": True},
        {"host": "10.0.0.3", "up": False},
    ]
    assert session_builder.parse_host_discovery("") == []


def test_parse_vuln_scan_counts_flags_and_cves():
    text = "|   VULNERABLE:\n| CVE-2011-2523\n| VULNERABLE:\nsee CVE-2011-2523 and CVE-2007-2447\n"
    out = session_builder.parse_vuln_scan(text)
    assert out["vulnerable_flags"] == 2
    assert out["cves_referenced"] == ["CVE-2007-2447", "CVE-2011-2523"]
    assert session_builder.parse_vuln_scan("") == {"vulnerable_flags": 0, "cves_referenced": []}
