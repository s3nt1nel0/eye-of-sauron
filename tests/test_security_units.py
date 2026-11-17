import ipaddress

import pytest

from app import netguard
from app.api.content import fts_query
from app.rules import compile_keywords
from app.sanitize import sanitize_html, to_text


# ------------------------------------------------------------------ SSRF guard
@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "gopher://example.com/",
    "ftp://example.com/feed",
    "javascript:alert(1)",
    "http://user:pass@example.com/",
    "http://exa mple.com/",
    "http://example.com/\r\nX-Injected: 1",
    "http:///nohost",
    "http://example.com:99999/",
    "",
    "http://" + "a" * 3000 + ".com/",
])
def test_normalize_rejects_bad_urls(url):
    with pytest.raises(netguard.UnsafeURLError):
        netguard.normalize_url(url)


def test_normalize_canonicalises():
    assert netguard.normalize_url("HTTPS://Example.COM/feed?x=1#frag") == "https://example.com/feed?x=1"
    assert netguard.normalize_url("http://[::1]:8080/a") == "http://[::1]:8080/a"


@pytest.mark.parametrize("addr", [
    "127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.10", "169.254.169.254",  # cloud metadata
    "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "224.0.0.1",
])
def test_private_addresses_blocked(addr):
    assert not netguard.ip_allowed(ipaddress.ip_address(addr), allow_private=False)


def test_public_address_allowed():
    assert netguard.ip_allowed(ipaddress.ip_address("1.1.1.1"), allow_private=False)


def test_private_mode_still_blocks_unspecified_and_multicast():
    assert netguard.ip_allowed(ipaddress.ip_address("192.168.1.10"), allow_private=True)
    assert not netguard.ip_allowed(ipaddress.ip_address("0.0.0.0"), allow_private=True)
    assert not netguard.ip_allowed(ipaddress.ip_address("224.0.0.1"), allow_private=True)
    assert not netguard.ip_allowed(ipaddress.ip_address("::"), allow_private=True)
    assert not netguard.ip_allowed(ipaddress.ip_address("ff02::1"), allow_private=True)


def test_private_mode_allows_localhost_on_ipv4_and_ipv6():
    """Regression: "localhost" resolves to 127.0.0.1 *and* ::1; Python marks ::1 as reserved, which used to
    block FreshRSS on localhost even though private targets were allowed. Still blocked in normal mode."""
    for addr in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
        assert netguard.ip_allowed(ipaddress.ip_address(addr), allow_private=True)
        assert not netguard.ip_allowed(ipaddress.ip_address(addr), allow_private=False)
    assert netguard.resolve_host("localhost", 8080, allow_private=True)


def test_request_refuses_loopback_literal():
    with pytest.raises(netguard.UnsafeURLError):
        netguard.request("GET", "http://127.0.0.1:1/")


def test_request_refuses_localhost_name():
    with pytest.raises(netguard.UnsafeURLError):
        netguard.request("GET", "http://localhost:1/")


# ------------------------------------------------------------------ sanitiser
@pytest.mark.parametrize("payload, forbidden", [
    ("<script>alert(1)</script><p>x</p>", "<script"),
    ('<img src=x onerror="alert(1)">', "onerror"),
    ('<a href="javascript:alert(1)">x</a>', "javascript:"),
    ('<a href="data:text/html,<script>alert(1)</script>">x</a>', "data:"),
    ('<iframe src="https://evil.example"></iframe>', "<iframe"),
    ('<svg onload="alert(1)"><circle/></svg>', "<svg"),
    ('<p style="background:url(https://track.example)">x</p>', "style="),
    ('<form action="https://evil.example"><input name=p></form>', "<form"),
    ('<math><mi xlink:href="javascript:alert(1)">x</mi></math>', "javascript:"),
    ('<a href="//evil.example/x">x</a>', "evil.example"),
])
def test_sanitizer_strips_dangerous_markup(payload, forbidden):
    assert forbidden not in sanitize_html(payload).lower()


def test_sanitizer_keeps_safe_markup_and_hardens_links():
    out = sanitize_html('<p>Hi <a href="https://example.com/a">link</a> <img src="https://e.com/i.png" alt="i"></p>')
    assert 'href="https://example.com/a"' in out
    assert 'rel="noopener noreferrer nofollow"' in out
    assert 'target="_blank"' in out
    assert "<img" in out


def test_sanitizer_can_drop_images():
    assert "<img" not in sanitize_html('<img src="https://e.com/i.png">', allow_images=False)


def test_to_text():
    assert to_text("<b>Ransom</b>&amp;ware <script>evil()</script>") == "Ransom&ware"


# ------------------------------------------------------------------ search / rules
def test_fts_query_quotes_everything():
    assert fts_query('lockbit" OR 1=1 NEAR(') == '"lockbit" "OR" "1" "1" "NEAR"*'
    assert fts_query("***") is None


def test_rule_keywords_are_literal_and_word_bounded():
    pattern = compile_keywords(("apt", "(a+)+$", "c++"))
    assert pattern.search("New APT campaign")
    assert not pattern.search("an aptitude test")
    assert pattern.search("uses (a+)+$ literally")
    assert not pattern.search("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!")


def test_private_allowlist_is_exact_host_and_port(monkeypatch):
    """FEEDWARDEN_PRIVATE_ALLOWLIST opens one local service (e.g. RSSHub on 127.0.0.1:1200) and nothing else."""
    import pytest

    from app import netguard
    from app.config import ConfigError, _allowlist, reset_settings

    monkeypatch.setenv("FEEDWARDEN_PRIVATE_ALLOWLIST", "127.0.0.1:1200")
    reset_settings()
    try:
        assert netguard.private_ok("127.0.0.1", 1200, False)
        assert not netguard.private_ok("127.0.0.1", 1201, False)       # other port
        assert not netguard.private_ok("192.168.1.10", 1200, False)    # other host
        assert netguard.resolve_host("127.0.0.1", 1200, netguard.private_ok("127.0.0.1", 1200, False))
        with pytest.raises(netguard.UnsafeURLError):
            netguard.resolve_host("127.0.0.1", 8081, netguard.private_ok("127.0.0.1", 8081, False))
        with pytest.raises(netguard.UnsafeURLError):  # even allow-listed, unspecified addresses stay blocked
            netguard.resolve_host("0.0.0.0", 1200, True)
    finally:
        monkeypatch.delenv("FEEDWARDEN_PRIVATE_ALLOWLIST")
        reset_settings()
    for bad in ("127.0.0.1", "*:1200", "host:99999", "a b:1"):
        with pytest.raises(ConfigError):
            _allowlist(bad)
