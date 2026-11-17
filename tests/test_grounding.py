"""The anti-hallucination checks: fake CVEs, fake ports, unsupported
vulnerability-class claims, and wrong-script output."""
import report_generator as rg


def test_known_cve_ids_include_scan_references(session):
    assert rg.known_cve_ids(session) == {"CVE-2011-2523", "CVE-2016-6210", "CVE-2017-7494", "CVE-2008-4250"}


def test_check_grounding_flags_only_unknown_cves(session):
    known = rg.known_cve_ids(session)
    text = "Real: CVE-2011-2523. Fake: CVE-2099-12345 and CVE-2020-0001."
    assert rg.check_grounding(text, known) == ["CVE-2020-0001", "CVE-2099-12345"]
    assert rg.check_grounding("nothing here", known) == []


def test_known_ports_are_strings_from_findings(session):
    assert rg.known_ports(session) == {"21", "22", "139", "445", "80"}


def test_port_grounding_flags_fabricated_ports(session):
    known = rg.known_ports(session)
    text = "Port 443 (HTTPS) is exposed, and 3389/tcp RDP, TCP/8080 too. Port 22 is fine."
    assert rg.check_port_grounding(text, known) == ["443", "3389", "8080"]


def test_port_grounding_allows_ports_from_real_cve_text(session):
    # 6200 appears in the real CVE description, so it is a fact, not a fabrication
    known = rg.known_ports(session)
    described = rg.build_described_port_mentions(session)
    assert "6200" in described
    assert rg.check_port_grounding("backdoor opens a shell on port 6200/tcp", known, described) == []
    assert rg.check_port_grounding("backdoor opens a shell on port 6200/tcp", known) == ["6200"]


def test_port_grounding_noop_without_known_ports():
    assert rg.check_port_grounding("port 443", set()) == []


def test_vuln_class_flags_unsupported_claims(session):
    evidence = rg.build_vuln_class_evidence(session)
    flagged = rg.check_vuln_class_grounding("Nginx is vulnerable to SQL injection and XSS.", evidence)
    assert "sql injection" in flagged and "xss" in flagged


def test_vuln_class_accepts_paraphrase_of_real_description(session):
    # real text says "execute arbitrary code"; "remote code execution" is the same fact
    evidence = rg.build_vuln_class_evidence(session)
    assert rg.check_vuln_class_grounding("Samba is open to remote code execution.", evidence) == []
    # real text says "contains a backdoor"
    assert rg.check_vuln_class_grounding("vsftpd ships a backdoor.", evidence) == []


def test_vuln_class_noop_without_evidence():
    assert rg.check_vuln_class_grounding("SQL injection everywhere", "") == []


def test_split_findings_by_evidence(session):
    with_ev, without_ev = rg.split_findings_by_evidence(session)
    assert [f["port"] for f in without_ev] == ["80"]
    assert len(with_ev) == 4


def test_no_evidence_list_is_deterministic_and_empty_safe(session):
    _, without_ev = rg.split_findings_by_evidence(session)
    out = rg.render_no_evidence_list(without_ev)
    assert "80/tcp http - nginx 1.18" in out
    assert rg.render_no_evidence_list([]) == ""


# ---- script drift --------------------------------------------------------

def test_script_drift_detects_foreign_scripts():
    assert rg.has_script_drift("The server is 漏洞 exposed")           # CJK
    assert rg.has_script_drift("Это уязвимость")                        # Cyrillic
    assert rg.has_script_drift("यह सर्वर असुरक्षित है")                   # Devanagari
    assert rg.has_script_drift("مرحبا")                                 # Arabic
    assert rg.has_script_drift("한국어")                                 # Hangul


def test_script_drift_ignores_normal_english_and_accents():
    assert not rg.has_script_drift("The vsftpd 2.3.4 service on port 21 is vulnerable. Café résumé naïve.")
    assert not rg.has_script_drift("")


def test_strip_duplicate_heading():
    assert rg.strip_duplicate_heading("### Executive Summary\n\nBody text", "Executive Summary") == "Body text"
    assert rg.strip_duplicate_heading("Executive Summary is below", "Executive Summary") == "Executive Summary is below"
    assert rg.strip_duplicate_heading("## Other Title\nBody", "Executive Summary") == "## Other Title\nBody"
