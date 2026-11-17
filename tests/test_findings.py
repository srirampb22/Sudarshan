"""Duplicate-finding grouping, top-finding selection, and priority tiers."""
import copy

import report_generator as rg


def test_identical_signature_findings_are_merged(session):
    grouped = rg.group_duplicate_findings(session["cve_exploit_findings"])
    ports = [g["port"] for g in grouped]
    assert ports == ["21", "22", "139", "80"]          # 445 folded into 139, order preserved
    samba = next(g for g in grouped if g["port"] == "139")
    assert samba["_grouped_endpoints"] == ["445/tcp"]
    assert rg.format_finding_port_label(samba) == "139/tcp (+1 identical endpoint(s): 445/tcp)"


def test_grouping_does_not_mutate_input(session):
    before = copy.deepcopy(session["cve_exploit_findings"])
    rg.group_duplicate_findings(session["cve_exploit_findings"])
    assert session["cve_exploit_findings"] == before
    assert all("_grouped_endpoints" not in f for f in session["cve_exploit_findings"])


def test_no_evidence_findings_are_never_merged(make_finding):
    fs = [make_finding(80, "http", "a"), make_finding(8080, "http", "b"), make_finding(9000, "x", "c")]
    assert len(rg.group_duplicate_findings(fs)) == 3


def test_different_cves_same_service_are_not_merged(make_finding, make_cve):
    a = make_finding(80, "http", "Apache", [make_cve("CVE-2020-0001", 5.0)])
    b = make_finding(8080, "http", "Apache", [make_cve("CVE-2020-0002", 5.0)])
    assert len(rg.group_duplicate_findings([a, b])) == 2


def test_exploit_only_findings_group_by_edb_id(make_finding):
    ex = [{"title": "t", "edb_id": "1"}]
    a, b = make_finding(1, "s", "v", exploits=ex), make_finding(2, "s", "v", exploits=ex)
    assert len(rg.group_duplicate_findings([a, b])) == 1


def test_top_finding_is_highest_cvss(session):
    with_ev, _ = rg.split_findings_by_evidence(session)
    top = rg.top_finding_identifiers(with_ev)
    assert top == {"port": "21", "proto": "tcp", "service": "ftp", "cve_id": "CVE-2011-2523", "cvss_score": 9.8}


def test_top_finding_none_without_scores(make_finding, make_cve):
    f = make_finding(80, "http", "x", [make_cve("CVE-2020-0001")])    # no cvss_score
    assert rg.top_finding_identifiers([f]) is None
    assert rg.top_finding_identifiers([]) is None


def test_top_findings_summary_is_ranked_and_capped(session):
    with_ev, _ = rg.split_findings_by_evidence(session)
    grouped = rg.group_duplicate_findings(with_ev)
    lines = rg.build_top_findings_summary(grouped, max_items=2).splitlines()
    assert lines[0].startswith("Findings ranked by highest CVSS")
    assert len(lines) == 3
    assert "CVSS 9.8" in lines[1] and "CVE-2011-2523" in lines[1]
    assert "CVSS 7.5" in lines[2] and "139/tcp" in lines[2]


def test_exec_summary_must_name_top_finding(session):
    with_ev, _ = rg.split_findings_by_evidence(session)
    top = rg.top_finding_identifiers(with_ev)
    assert rg.exec_summary_names_top_finding("Most critical: CVE-2011-2523.", top)
    assert rg.exec_summary_names_top_finding("The FTP service on 21 is the worst.", top)
    assert not rg.exec_summary_names_top_finding("SSH is the main concern.", top)
    assert rg.exec_summary_names_top_finding("anything", None)          # nothing to check against


def test_priority_tier_boundaries():
    assert rg.priority_tier(10.0) == "Immediate"
    assert rg.priority_tier(9.0) == "Immediate"
    assert rg.priority_tier(8.9) == "Short-term"
    assert rg.priority_tier(7.0) == "Short-term"
    assert rg.priority_tier(6.9) == "Long-term"
    assert rg.priority_tier(0) == "Long-term"


def test_finding_max_cvss(make_finding, make_cve):
    f = make_finding(1, "s", "v", [make_cve("CVE-2020-0001", 3.1), make_cve("CVE-2020-0002", 8.2), make_cve("CVE-2020-0003")])
    assert rg.finding_max_cvss(f) == 8.2
    assert rg.finding_max_cvss(make_finding(1, "s", "v")) == 0.0


def test_single_finding_facts_only_contains_that_finding(session):
    samba = session["cve_exploit_findings"][2]
    facts = rg.build_single_finding_facts(samba)
    assert "CVE-2017-7494" in facts and "CVE-2011-2523" not in facts
    assert facts.splitlines()[0].startswith("139/tcp netbios-ssn")
