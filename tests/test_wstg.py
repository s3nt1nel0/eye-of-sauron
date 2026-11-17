"""OWASP Web Security Testing Guide v4.2 checks that need white-box access (HTTPS scheme, the database,
or the source tree). Black-box WSTG checks live in tools/pentest_harness.py (IDs "WSTG-…"); the full
mapping is in docs/WSTG-COVERAGE.md."""
import re
import sqlite3
from pathlib import Path

from conftest import TEST_PASSWORD

ROOT = Path(__file__).resolve().parent.parent


def _login(c, password=TEST_PASSWORD):
    return c.post("/api/v1/auth/login", json={"username": "admin", "password": password})


# --------------------------------------------------------------- 4.4 Authentication (ATHN)
def test_athn_01_https_gets_hsts_and_secure_cookie(client):
    """WSTG-ATHN-01 / CONF-07 / CRYP-03: over HTTPS the session cookie is Secure and HSTS is sent."""
    client.base_url = "https://testserver"
    r = _login(client)
    assert r.status_code == 200
    assert "secure" in r.headers["set-cookie"].lower()
    assert r.headers["strict-transport-security"].startswith("max-age=31536000")


def test_athn_01_no_credentials_in_url_or_form(client):
    """WSTG-ATHN-01: credentials are only accepted as a JSON body, never via the query string or a GET."""
    q = f"username=admin&password={TEST_PASSWORD}"
    assert client.get(f"/api/v1/auth/login?{q}").status_code == 405
    assert client.post(f"/api/v1/auth/login?{q}").status_code == 422
    r = client.post("/api/v1/auth/login", data={"username": "admin", "password": TEST_PASSWORD})
    assert r.status_code in (400, 415, 422) and "set-cookie" not in r.headers


def test_athn_02_default_credentials_refused(client):
    """WSTG-ATHN-02: common default passwords never work (the first-run password is random or set by the admin)."""
    for pw in ("admin", "password", "eyeofsauron", "changeme", "123456"):
        assert _login(client, pw).status_code == 401


def test_athn_06_no_caching_of_authenticated_responses(authed):
    """WSTG-ATHN-06: API responses (including login and /auth/me) must not be stored by browsers or proxies."""
    for path in ("/api/v1/auth/me", "/api/v1/sidebar", "/api/v1/articles"):
        assert authed.get(path).headers["cache-control"] == "no-store"
    assert _login(authed).headers["cache-control"] == "no-store"


def test_athn_09_password_change_needs_current_password(authed):
    """WSTG-ATHN-09: a hijacked session cannot change the password without knowing the current one."""
    r = authed.post("/api/v1/auth/password", json={"current_password": "wrong-guess-123456",
                                                     "new_password": "a-brand-new-long-passphrase"})
    assert r.status_code == 400
    assert _login(authed).status_code == 200  # old password still valid


def test_idnt_02_no_self_registration(client):
    """WSTG-IDNT-02/03: there is no public sign-up or user-provisioning endpoint."""
    for path in ("/api/v1/auth/register", "/api/v1/auth/signup", "/api/v1/users", "/register", "/signup"):
        assert client.post(path, json={"username": "eve", "password": "x" * 20}).status_code in (401, 404, 405)


# --------------------------------------------------------------- 4.6 Session management (SESS)
def test_sess_01_session_tokens_are_random_and_rotated(client):
    """WSTG-SESS-01: ≥256-bit random session ids, a new one per login, stored only as a hash."""
    ids = set()
    for _ in range(3):
        cookie = _login(client).headers["set-cookie"]
        value = re.search(r"eos_session=([^;]+)", cookie).group(1)
        assert len(value) >= 40
        ids.add(value)
    assert len(ids) == 3
    db = sqlite3.connect(_data_dir() / "eos.db")
    stored = {r[0] for r in db.execute("SELECT token_hash FROM sessions")}
    db.close()
    assert not (ids & stored)


def _data_dir():
    from app.config import get_settings
    return get_settings().data_dir


def test_sess_04_session_id_not_exposed(client):
    """WSTG-SESS-04: the session id is only in the HttpOnly cookie, never in a response body."""
    r = _login(client)
    value = re.search(r"eos_session=([^;]+)", r.headers["set-cookie"]).group(1)
    assert value not in r.text
    assert value not in client.get("/api/v1/auth/me").text


def test_sess_07_idle_and_absolute_timeouts(client):
    """WSTG-SESS-07: sessions die after the idle timeout and after the absolute lifetime."""
    assert _login(client).status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 200
    db = sqlite3.connect(_data_dir() / "eos.db")
    db.execute("UPDATE sessions SET last_seen = last_seen - 30 * 86400")
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401   # idle

    assert _login(client).status_code == 200
    db.execute("UPDATE sessions SET expires_at = 1")
    db.commit()
    db.close()
    assert client.get("/api/v1/auth/me").status_code == 401   # absolute expiry


# --------------------------------------------------------------- 4.2 Configuration (CONF) / 4.11 Client-side (CLNT)
def test_clnt_02_09_csp_is_strict(client):
    """WSTG-CLNT-02 / CLNT-09 (CONF-12 in later WSTG versions): no inline or eval'd script, no framing, no plugins, no base-uri tricks."""
    csp = client.get("/login").headers["content-security-policy"]
    directives = dict((d.strip().split(" ", 1) + [""])[:2] for d in csp.split(";") if d.strip())
    assert directives["default-src"] == "'none'"
    assert directives["script-src"] == "'self'"
    assert "unsafe" not in csp and "*" not in directives["script-src"]
    assert directives["frame-ancestors"] == "'none'" and directives["base-uri"] == "'none'"
    assert directives["form-action"] == "'self'"


def test_clnt_01_no_dangerous_dom_sinks_in_frontend():
    """WSTG-CLNT-01/03/04: the UI never writes HTML strings into the DOM or navigates to data-derived URLs."""
    sinks = re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(|"
                       r"setTimeout\(\s*[\"'`]|setInterval\(\s*[\"'`]|\.srcdoc\s*=|createContextualFragment")
    nav = re.compile(r"location(\.href)?\s*=|location\.(assign|replace)\(")
    for js in (ROOT / "static").glob("*.js"):
        src = js.read_text(encoding="utf-8")
        code = "\n".join(line for line in src.splitlines() if not line.strip().startswith(("*", "//", "/*")))
        assert not sinks.search(code), f"{js.name}: {sinks.search(code).group(0)}"
        for m in nav.finditer(code):
            tail = code[m.end():m.end() + 12]
            assert tail.lstrip().startswith(('"/"', '"/login"', "(\"/\")", "(\"/login\")")), f"{js.name}: navigation to {tail!r}"


def test_clnt_11_12_no_message_listeners_and_no_secrets_in_storage():
    """WSTG-CLNT-11/12: no postMessage receivers; browser storage only holds UI preferences, never tokens."""
    for js in (ROOT / "static").glob("*.js"):
        src = js.read_text(encoding="utf-8")
        assert "addEventListener(\"message\"" not in src and "onmessage" not in src and "WebSocket(" not in src, js.name
        for m in re.finditer(r"(?:localStorage|sessionStorage|store)\.(?:setItem|set)\(([^)]*)\)", src):
            assert not re.search(r"token|csrf|session|password|secret|api_?key", m.group(1), re.I), f"{js.name}: {m.group(0)}"


def test_inpv_11_12_no_code_or_command_execution_sinks():
    """WSTG-INPV-11/12 (code / command injection): the server never evaluates code or spawns shells."""
    bad = re.compile(r"\b(eval|exec)\(|os\.system|os\.popen|subprocess|shell=True|pickle\.loads?|yaml\.load\(|"
                     r"marshal\.loads|__import__\(")
    for py in (ROOT / "app").rglob("*.py"):
        for n, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            assert not bad.search(line), f"{py.relative_to(ROOT)}:{n}: {line.strip()}"
