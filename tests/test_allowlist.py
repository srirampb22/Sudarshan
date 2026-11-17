"""check_target_allowed(): default-deny, RFC1918 only, hard-denied ranges,
env-based extra allow/deny, and hostname resolution (every address must pass).
DNS is faked so these tests never touch the network."""
import socket

import pytest

import sudarshan


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("SUDARSHAN_ALLOWED_TARGETS", raising=False)
    monkeypatch.delenv("SUDARSHAN_DENIED_TARGETS", raising=False)


def fake_dns(monkeypatch, mapping):
    def fake(host, *a, **k):
        if host not in mapping:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in mapping[host]]
    monkeypatch.setattr(sudarshan.socket, "getaddrinfo", fake)


@pytest.mark.parametrize("target", [
    "10.0.0.5", "10.255.255.254", "172.16.0.1", "172.31.255.1", "192.168.1.10",
    "192.168.0.0/24", "10.1.0.0/16", "http://10.0.0.5:8080/path", "10.0.0.5:22",
])
def test_private_ranges_allowed(target):
    ok, reason = sudarshan.check_target_allowed(target)
    assert ok, reason


@pytest.mark.parametrize("target", [
    "8.8.8.8", "1.1.1.1", "172.32.0.1", "172.15.255.255", "192.169.0.1", "11.0.0.1",
    "10.0.0.0/7",            # bigger than RFC1918 /8: not wholly inside an allowed range
    "0.0.0.0/0",
])
def test_public_or_oversized_targets_denied(target):
    assert sudarshan.check_target_allowed(target)[0] is False


@pytest.mark.parametrize("target", [
    "127.1.2.3", "127.0.0.1", "169.254.169.254", "169.254.0.1",
    "0.0.0.0", "224.0.0.1", "::1", "fe80::1",
])
def test_loopback_linklocal_metadata_always_denied(target):
    assert sudarshan.check_target_allowed(target)[0] is False


def test_metadata_address_denied_even_if_user_allowlists_it(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_ALLOWED_TARGETS", "169.254.169.254,127.0.0.1")
    assert sudarshan.check_target_allowed("169.254.169.254")[0] is False
    assert sudarshan.check_target_allowed("127.0.0.1")[0] is False


@pytest.mark.parametrize("target", [
    "", "   ", None, "-oN /tmp/x", "10.0.0.5; rm -rf /", "10.0.0.5 && id", "$(id)", "`id`",
    "10.0.0.5|nc", "a b", "10.0.0.5\n8.8.8.8", "10.0.0.5,8.8.8.8", "'10.0.0.5'", "10.0.0.5>out",
])
def test_shell_metacharacters_and_option_injection_rejected(target):
    ok, reason = sudarshan.check_target_allowed(target)
    assert ok is False
    assert "invalid" in reason or "could not parse" in reason


def test_surrounding_whitespace_is_stripped_not_rejected():
    assert sudarshan.check_target_allowed("  10.0.0.5\n")[0] is True


def test_extra_allowed_public_ip_via_env(monkeypatch):
    assert sudarshan.check_target_allowed("203.0.113.7")[0] is False
    monkeypatch.setenv("SUDARSHAN_ALLOWED_TARGETS", "203.0.113.0/24")
    assert sudarshan.check_target_allowed("203.0.113.7")[0] is True


def test_denied_env_overrides_default_allow(monkeypatch):
    monkeypatch.setenv("SUDARSHAN_DENIED_TARGETS", "192.168.1.0/24")
    assert sudarshan.check_target_allowed("192.168.1.5")[0] is False
    assert sudarshan.check_target_allowed("192.168.2.5")[0] is True


def test_hostname_resolving_to_private_ip_allowed(monkeypatch):
    fake_dns(monkeypatch, {"lab.local": ["10.0.0.9"]})
    assert sudarshan.check_target_allowed("lab.local")[0] is True
    assert sudarshan.check_target_allowed("http://lab.local:8080/x")[0] is True


def test_hostname_resolving_to_loopback_or_public_denied(monkeypatch):
    fake_dns(monkeypatch, {"evil.test": ["127.0.0.1"], "pub.test": ["8.8.8.8"]})
    assert sudarshan.check_target_allowed("evil.test")[0] is False
    assert sudarshan.check_target_allowed("pub.test")[0] is False


def test_every_resolved_address_must_pass(monkeypatch):
    fake_dns(monkeypatch, {"mixed.test": ["10.0.0.9", "169.254.169.254"]})
    assert sudarshan.check_target_allowed("mixed.test")[0] is False


def test_unresolvable_host_denied(monkeypatch):
    fake_dns(monkeypatch, {})
    ok, reason = sudarshan.check_target_allowed("nope.invalid")
    assert ok is False and "resolve" in reason


def test_allowlisted_domain_and_subdomains(monkeypatch):
    fake_dns(monkeypatch, {"example.com": ["203.0.113.5"], "a.example.com": ["203.0.113.6"],
                           "notexample.com": ["203.0.113.7"], "loop.example.com": ["127.0.0.1"]})
    monkeypatch.setenv("SUDARSHAN_ALLOWED_TARGETS", "example.com")
    assert sudarshan.check_target_allowed("example.com")[0] is True
    assert sudarshan.check_target_allowed("a.example.com")[0] is True
    assert sudarshan.check_target_allowed("notexample.com")[0] is False     # suffix must be a label boundary
    assert sudarshan.check_target_allowed("loop.example.com")[0] is False   # hard deny still wins
