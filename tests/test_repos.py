"""📦 Repos tab: follow GitHub owners / repos / topics / stars through the official API (mocked here), validated
input, plain-text storage, topic filing, shelves, releases, ★, orphan clean-up, rate limits and the token."""

import json
import time
from unittest import mock
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from app import github, netguard
from app.db import get_db

RESET = int(time.time()) + 1800


def repo(full, stars=10, lang="Python", topics=(), desc="", archived=False, fork=False, homepage=None, gh_id=None, pushed="2026-11-01T10:00:00Z"):
    owner, name = full.split("/")
    return {"id": gh_id or abs(hash(full)) % 10**9 + 1, "full_name": full, "name": name, "owner": {"login": owner, "avatar_url": f"https://avatars.githubusercontent.com/u/{len(owner)}?v=4"},
            "description": desc, "language": lang, "stargazers_count": stars, "forks_count": 1, "open_issues_count": 2,
            "topics": list(topics), "license": {"spdx_id": "MIT"}, "homepage": homepage, "archived": archived, "fork": fork,
            "created_at": "2020-01-01T00:00:00Z", "pushed_at": pushed}


OWNER_REPOS = [repo("acme/proxmox-scripts", 500, "Shell", ["homelab", "proxmox"], "Helper scripts for Proxmox VE and Kali Linux labs"),
               repo("acme/old-tool", 3, None, [], "<b>Old</b> thing <script>alert(1)</script>", archived=True),
               repo("acme/forked", 1, "Go", [], "a fork", fork=True, homepage="javascript:alert(1)")]
RELEASES = b"""<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Release notes from nuclei</title>
<entry><id>tag:github.com,2008:Repository/1/v3.1.0</id><updated>2026-11-10T08:00:00Z</updated>
<link rel="alternate" type="text/html" href="https://github.com/projectdiscovery/nuclei/releases/tag/v3.1.0"/>
<title>v3.1.0</title><content type="html">&lt;p&gt;New &lt;b&gt;templates&lt;/b&gt;&lt;/p&gt;</content></entry>
<entry><id>x</id><updated>2026-11-09T08:00:00Z</updated><link rel="alternate" href="https://evil.example/x"/><title>bad</title></entry>
</feed>"""


# repos that exist in this fake GitHub (lower-case path → GitHub's own spelling)
KNOWN = {f"/repos/{n.lower()}": n for n in ("syncthing/syncthing", "OJ/gobuster", "mzet-/les-res", "elder-plinius/ChatGPT_DAN",
                                             "swisskyrepo/PayloadsAllTheThings", "swisskyrepo/InternalAllTheThings",
                                             "LOLBAS-Project/LOLBAS-Project.github.io", "mzet-/mzet-.github.io",
                                             "offensive-security/kali-nethunter", "UberGuidoZ/Flipper", "acme/proxmox-scripts")}


def fake_github(calls, remaining="59", status_for=None):
    def fake(method, url, **kw):
        calls.append((url, kw.get("headers", {}).get("Authorization")))
        parts = urlsplit(url)
        assert parts.scheme == "https" and parts.hostname in ("api.github.com", "github.com"), url
        hdr = {"content-type": "application/json", "x-ratelimit-remaining": remaining, "x-ratelimit-limit": "60", "x-ratelimit-reset": str(RESET)}
        if status_for and parts.path in status_for:
            return netguard.SafeResponse(status_for[parts.path], httpx.Headers(hdr), b"{}", url)
        tag = f'"etag-{parts.path}"'
        hdr["etag"] = tag
        if kw.get("headers", {}).get("If-None-Match") == tag:
            return netguard.SafeResponse(304, httpx.Headers(hdr), b"", url)
        body: object
        if parts.path == "/users/acme":
            body = {"login": "acme", "name": "ACME Labs", "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4"}
        elif parts.path == "/users/acme/repos":
            body = OWNER_REPOS if parse_qs(parts.query)["page"] == ["1"] else []
        elif parts.path == "/search/repositories":
            assert parse_qs(parts.query)["q"] == ["topic:homelab"]
            body = {"total_count": 4321, "items": [repo("acme/proxmox-scripts", 500, "Shell", ["homelab"]), repo("selfh/stack", 900, "TypeScript", ["homelab", "docker"], "Self-hosted dashboard")]}
        elif parts.path == "/repos/projectdiscovery/nuclei":
            body = repo("projectdiscovery/nuclei", 20000, "Go", ["security", "vulnerability-scanner"], "Fast vulnerability scanner")
        elif parts.path == "/projectdiscovery/nuclei/releases.atom":
            return netguard.SafeResponse(200, httpx.Headers({"content-type": "application/atom+xml"}), RELEASES, url)
        elif parts.path == "/users/me/starred":
            body = [repo("selfh/stack", 900, "TypeScript")]
        elif parts.path in ("/users/me", "/users/mzet-", "/users/elder-plinius", "/users/UberGuidoZ"):
            body = {"login": parts.path.rsplit("/", 1)[1], "name": None}
        elif parts.path in ("/users/mzet-/repos", "/users/elder-plinius/repos"):
            body = []
        elif parts.path == "/users/UberGuidoZ/repos":
            body = [repo("UberGuidoZ/Flipper", 15000, "C", ["flipper-zero"], "Playground for the Flipper Zero")]
        elif parts.path.startswith("/repos/") and parts.path.count("/") == 3 and parts.path.lower() in KNOWN:
            body = repo(KNOWN[parts.path.lower()])
        elif parts.path == "/gists/99241df331bb06f393be935f82f036a5":
            body = {"id": "99241df331bb06f393be935f82f036a5", "description": "Windows <b>event</b> log cheat sheet", "comments": 2,
                    "owner": {"login": "4n6ist", "avatar_url": "https://avatars.githubusercontent.com/u/9?v=4"},
                    "files": {"evtx.md": {"language": "Markdown"}, "query.ps1": {"language": "PowerShell"}},
                    "created_at": "2024-01-01T00:00:00Z", "updated_at": "2026-10-01T00:00:00Z"}
        elif parts.path == "/rate_limit":
            body = {"resources": {"core": {"limit": 5000, "remaining": 4999}}}
        else:
            return netguard.SafeResponse(404, httpx.Headers(hdr), b"{}", url)
        return netguard.SafeResponse(200, httpx.Headers(hdr), json.dumps(body).encode(), url)
    return fake


@pytest.fixture(autouse=True)
def _fresh_rate():
    github.reset_rate()
    yield
    github.reset_rate()


def follow(authed, text, calls, **kw):
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls, **kw)), mock.patch("app.github.time.sleep"):
        r = authed.post("/api/v1/repos/sources", json={"input": text})
        if github.repo_sync.thread is not None:
            github.repo_sync.thread.join(10)
    return r


def test_parse_input_accepts_links_and_rejects_everything_else():
    ok = {"https://github.com/SpecterOps": ("owner", "SpecterOps"), "github.com/projectdiscovery/nuclei/tree/main": ("repo", "projectdiscovery/nuclei"),
          "a/b.git": ("repo", "a/b"), "topic:HomeLab": ("topic", "homelab"), "https://github.com/topics/self-hosted": ("topic", "self-hosted"),
          "stars:torvalds": ("stars", "torvalds"), "https://github.com/torvalds?tab=stars": ("stars", "torvalds"), "@octocat": ("owner", "octocat")}
    for text, want in ok.items():
        assert github.parse_input(text) == want, text
    for bad in ["https://evil.example/a/b", "https://github.com.evil.example/x", "settings", "topic:Bad_Topic", "-ab", "../etc", "x/..",
                "javascript:alert(1)", "", "x" * 400, "-lead", "own er"]:
        with pytest.raises(github.GitHubError):
            github.parse_input(bad)


def test_follow_owner_stores_clean_repos_and_files_topics(authed):
    calls = []
    r = follow(authed, "https://github.com/acme", calls)
    assert r.status_code == 200, r.text
    assert all(a is None for _, a in calls)                                 # no token set: unauthenticated
    m = authed.get("/api/v1/repos/meta").json()
    assert m["total"] == 3 and m["sources"][0]["title"] == "ACME Labs" and m["sources"][0]["repo_count"] == 3
    assert m["rate"]["remaining"] == 59
    items = {i["full_name"]: i for i in authed.get("/api/v1/repos?sort=stars").json()["items"]}
    old = items["acme/old-tool"]
    assert "<" not in old["description"] and "script" not in old["description"].lower().replace("scripts", "")  # markup stripped
    assert old["archived"] and items["acme/forked"]["is_fork"]
    assert items["acme/forked"]["homepage"] is None                         # javascript: link dropped
    assert items["acme/proxmox-scripts"]["url"] == "https://github.com/acme/proxmox-scripts"
    with get_db() as db:   # "Kali Linux" in the description → the built-in "Red team & pentesting" topic
        names = {t[0] for t in db.execute("SELECT t.name FROM repo_topics x JOIN topics t ON t.id = x.topic_id JOIN repos r ON r.id = x.repo_id "
                                          "WHERE r.full_name = 'acme/proxmox-scripts'")}
    assert "Red team & pentesting" in names
    # filters
    assert authed.get("/api/v1/repos?hide_archived=true&hide_forks=true").json()["total"] == 1
    assert authed.get("/api/v1/repos?language=Shell").json()["total"] == 1
    assert authed.get("/api/v1/repos?language=Unknown").json()["total"] == 1
    assert authed.get("/api/v1/repos?min_stars=100").json()["total"] == 1
    assert authed.get("/api/v1/repos?gh_topic=proxmox").json()["total"] == 1
    assert authed.get("/api/v1/repos?q=helper").json()["total"] == 1
    assert authed.get("/api/v1/repos?owner=acme").json()["total"] == 3
    # duplicate follow
    assert follow(authed, "acme", []).status_code == 409


def test_topic_repo_stars_shelves_and_releases(authed):
    calls = []
    assert follow(authed, "topic:homelab", calls).status_code == 200
    assert follow(authed, "https://github.com/projectdiscovery/nuclei", calls).status_code == 200
    assert follow(authed, "stars:me", calls).status_code == 200
    m = authed.get("/api/v1/repos/meta").json()
    titles = {s["kind"]: s["title"] for s in m["sources"]}
    assert titles["topic"].startswith("# homelab (top 2 of 4,321)") and titles["repo"] == "projectdiscovery/nuclei"
    assert m["total"] == 3                                                  # selfh/stack listed twice, stored once
    rel = authed.get("/api/v1/repos/releases").json()
    assert rel["total"] == 1 and rel["items"][0]["tag"] == "v3.1.0"        # the off-site link was ignored
    assert rel["items"][0]["url"] == "https://github.com/projectdiscovery/nuclei/releases/tag/v3.1.0"
    assert rel["items"][0]["summary"] == "New templates"
    sh = authed.get("/api/v1/repos/shelves?by=language").json()
    assert {s["label"] for s in sh["shelves"]} == {"Shell", "Go", "TypeScript"}
    by_owner = authed.get("/api/v1/repos/shelves?by=owner&per=1").json()["shelves"]
    assert all(len(s["items"]) <= 1 for s in by_owner)
    assert authed.get("/api/v1/repos/shelves?by=topic").status_code == 200
    # date range on the last push
    assert authed.get(f"/api/v1/repos?since={int(time.time()) + 86400}").json()["total"] == 0
    assert authed.get("/api/v1/repos?since=10&until=5").status_code == 422


def test_star_keeps_a_repo_after_unfollowing(authed):
    follow(authed, "acme", [])
    items = {i["full_name"]: i for i in authed.get("/api/v1/repos").json()["items"]}
    keep = items["acme/proxmox-scripts"]["id"]
    assert authed.patch(f"/api/v1/repos/{keep}", json={"starred": True}).status_code == 200
    sid = authed.get("/api/v1/repos/meta").json()["sources"][0]["id"]
    r = authed.delete(f"/api/v1/repos/sources/{sid}").json()
    assert r["repos_removed"] == 2
    left = authed.get("/api/v1/repos").json()["items"]
    assert [i["full_name"] for i in left] == ["acme/proxmox-scripts"] and left[0]["starred"]
    authed.patch(f"/api/v1/repos/{keep}", json={"starred": False})
    assert authed.get("/api/v1/repos").json()["total"] == 0               # un-starred and unlisted: gone
    assert authed.patch("/api/v1/repos/999999", json={"starred": True}).status_code == 404


def test_rate_limit_stops_the_round_and_errors_are_kept(authed):
    calls = []
    r = follow(authed, "acme", calls, remaining="0", status_for={"/users/acme": 403})
    assert r.status_code == 200 and r.json()["pending"] and r.json()["until"] == RESET   # saved, finished after the reset
    github.reset_rate()
    with get_db() as db:
        db.execute("UPDATE repo_sources SET next_fetch = 0")
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    assert authed.get("/api/v1/repos/meta").json()["sources"][0]["repo_count"] == 3
    with get_db() as db:   # a later background round that hits the limit stops and waits for the reset
        db.execute("UPDATE repo_sources SET next_fetch = NULL")
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls, remaining="0", status_for={"/users/acme": 403})), \
            mock.patch("app.github.time.sleep"):
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    s = authed.get("/api/v1/repos/meta").json()["sources"][0]
    assert s["last_error"] is None and s["next_fetch"] >= RESET              # not an error: it waits for the reset
    n = len(calls)
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)):
        assert github.repo_sync.maybe_start() is False                      # not due before GitHub's reset
    assert len(calls) == n


def test_each_pasted_line_gets_a_precise_answer(authed):
    """Regression (2026-11-20): every line said "Not Found". Each case now has its own reason."""
    calls = []
    cases = {
        "https://github.com/syncthing/syncthing": (200, "syncthing/syncthing"),
        "https://github.com/OJ/gobuster": (200, "OJ/gobuster"),
        "https://github.com/mzet-/les-res": (200, "mzet-/les-res"),                       # legacy login ending in "-"
        "https://github.com/elder-plinius/ChatGPT_DAN/blob/main/README.md": (200, "elder-plinius/ChatGPT_DAN"),
        "https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md":
            (200, "swisskyrepo/PayloadsAllTheThings"),
        "https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#perl": (200, "swisskyrepo/InternalAllTheThings"),
        "https://github.com/swisskyrepo/payloadsallthethings?tab=readme-ov-file": (409, "already in your Repos"),
        "https://github.com/elder-plinius": (200, "elder-plinius"),
        "https://github.com/nvidia/no-such-thing": (404, "No public repo nvidia/no-such-thing"),
        "https://jhalon.github.io/becoming-a-pentester/": (200, "https://jhalon.github.io/becoming-a-pentester/"),   # saved as a website link
        "https://gist.github.com/johanwiden/d14ec414bd212e2ee8c2fae576115ef7": (404, "No public gist d14ec414bd212e2ee8c2fae576115ef7"),
        "https://example.com/owner/repo": (422, "isn't GitHub"),
        "https://github.com/no-user-here": (404, "No GitHub user or organisation called no-user-here"),
    }
    for line, (code, want) in cases.items():
        r = follow(authed, line, calls)
        assert r.status_code == code, (line, r.text)
        body = r.json()
        assert want in (body.get("value", "") if code == 200 else body["detail"]), (line, body)
    items = {i["full_name"] for i in authed.get("/api/v1/repos?limit=100").json()["items"]}
    assert {"syncthing/syncthing", "OJ/gobuster", "mzet-/les-res", "elder-plinius/ChatGPT_DAN", "swisskyrepo/InternalAllTheThings"} <= items
    with get_db() as db:   # a repo is stored from the check itself: one API request, not two
        assert db.execute("SELECT last_fetch IS NOT NULL FROM repo_sources WHERE value = 'OJ/gobuster'").fetchone()[0] == 1
    assert sum(1 for u, _ in calls if u.endswith("/repos/OJ/gobuster")) == 1


def test_follow_owner_is_optional(authed):
    calls = []
    r = follow(authed, "https://github.com/acme/proxmox-scripts".replace("acme/proxmox-scripts", "syncthing/syncthing"), calls)
    assert r.json()["owner"] is None
    kinds = {(s["kind"], s["value"]) for s in authed.get("/api/v1/repos/meta").json()["sources"]}
    assert kinds == {("repo", "syncthing/syncthing")}                         # off: only the repo
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        r = authed.post("/api/v1/repos/sources", json={"input": "github.com/acme/old-tool".replace("acme/old-tool", "OJ/gobuster"), "follow_owner": True})
        github.repo_sync.thread.join(10)
    assert r.status_code == 200 and r.json()["owner"] == {"id": r.json()["owner"]["id"], "value": "OJ", "added": True}
    kinds = {(s["kind"], s["value"]) for s in authed.get("/api/v1/repos/meta").json()["sources"]}
    assert ("owner", "OJ") in kinds and ("repo", "OJ/gobuster") in kinds
    # the repo is already there but its owner isn't yet: ticking the box still adds the owner
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        r = authed.post("/api/v1/repos/sources", json={"input": "syncthing/syncthing", "follow_owner": True})
    assert r.status_code == 200 and r.json()["added"] is False and r.json()["owner"]["added"] is True


def test_token_is_checked_stored_encrypted_and_never_returned(authed):
    calls = []
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)):
        assert authed.put("/api/v1/repos/token", json={"token": "not-a-token"}).status_code == 422
        tok = "ghp_" + "a" * 36
        r = authed.put("/api/v1/repos/token", json={"token": tok})
        assert r.status_code == 200 and r.json() == {"token_set": True, "limit": 5000, "resumed": 0}
    assert calls[-1][1] == f"Bearer {tok}"
    for path in ("/api/v1/repos/meta", "/api/v1/integrations"):
        assert tok not in authed.get(path).text
    with get_db() as db:
        assert tok.encode() not in db.execute("SELECT secret FROM integrations WHERE name = 'github'").fetchone()[0].encode()
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        authed.post("/api/v1/repos/sources", json={"input": "acme"})
        github.repo_sync.thread.join(10)
    assert calls[-1][1] == f"Bearer {tok}"                                  # used for fetching
    assert authed.put("/api/v1/repos/token", json={"clear": True}).json()["token_set"] is False


def test_permissions(authed):
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    write = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "w", "scope": "write"}).json()["token"]}
    c = authed
    csrf = c.headers.pop("X-CSRF-Token")
    cookies = dict(c.cookies)
    c.cookies.clear()
    try:
        assert c.get("/api/v1/repos", headers=read).status_code == 200
        assert c.post("/api/v1/repos/sources", json={"input": "acme"}, headers=read).status_code == 403
        assert c.post("/api/v1/repos/refresh", headers=read).status_code == 403
        assert c.put("/api/v1/repos/token", json={"clear": True}, headers=write).status_code == 403   # admin only
        assert c.get("/api/v1/repos").status_code == 401
    finally:
        c.headers["X-CSRF-Token"] = csrf
        c.cookies.update(cookies)


def test_bad_query_values_are_refused(authed):
    for q in ("language=%3Cscript%3E", "owner=a_b", "owner=-x", "gh_topic=Bad_Topic", "topic_ids=1;DROP", "min_stars=-1", "sort=evil", "per=999"):
        path = "/api/v1/repos/shelves?" if q.startswith("per") else "/api/v1/repos?"
        assert authed.get(path + q).status_code == 422, q


def test_search_budget_is_kept_apart_from_the_hourly_one(authed):
    calls = []
    follow(authed, "acme", calls)                                           # core: 59 left
    def search_hdr(method, url, **kw):
        resp = fake_github(calls)(method, url, **kw)
        if "/search/" in url:
            resp.headers["x-ratelimit-resource"] = "search"
            resp.headers["x-ratelimit-remaining"] = "0"
            resp.headers["x-ratelimit-limit"] = "10"
        return resp
    with mock.patch("app.github.netguard.request", side_effect=search_hdr), mock.patch("app.github.time.sleep"):
        authed.post("/api/v1/repos/sources", json={"input": "topic:homelab"})
        github.repo_sync.thread.join(10)
    assert authed.get("/api/v1/repos/meta").json()["rate"] == {"remaining": 59, "limit": 60, "reset": RESET}
    with pytest.raises(github.RateLimited):
        github.api_get("/search/repositories", {"q": "topic:x"})          # search spent: refused locally
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)):
        assert github.api_get("/users/acme")["login"] == "acme"            # the hourly budget still works


def api_calls(calls):
    return [u for u, _ in calls if u.startswith("https://api.github.com/")]


def test_one_request_per_line_and_no_duplicates(authed):
    """Regression (2026-11-20): a running background sync picked up a repo being added and fetched it again (2 requests
    a line), and an owner's profile was fetched twice."""
    calls = []
    follow(authed, "https://github.com/acme", calls)                           # owner: profile once + 1 page
    assert [u.split("?")[0] for u in api_calls(calls)] == ["https://api.github.com/users/acme", "https://api.github.com/users/acme/repos"]
    calls.clear()
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        with get_db() as db:   # a sync round is busy while the next line is added
            db.execute("UPDATE repo_sources SET next_fetch = 0")
        github.repo_sync.maybe_start()
        r = authed.post("/api/v1/repos/sources", json={"input": "https://github.com/OJ/gobuster"})
        github.repo_sync.thread.join(10)
    assert r.json()["requests"] == 1
    assert sum(1 for u in api_calls(calls) if u.endswith("/repos/OJ/gobuster")) == 1
    # the owner's refresh skipped the profile (already known) and sent its ETag
    assert not any(u.endswith("/users/acme") for u in api_calls(calls))
    calls.clear()
    r = follow(authed, "https://github.com/acme/proxmox-scripts", calls)       # already stored by the owner: no request
    assert r.status_code == 200 and r.json()["requests"] == 0 and api_calls(calls) == []
    with get_db() as db:
        assert db.execute("SELECT last_fetch IS NOT NULL FROM repo_sources WHERE value = 'acme/proxmox-scripts'").fetchone()[0] == 1


def test_refreshes_are_conditional(authed):
    calls = []
    follow(authed, "https://github.com/OJ/gobuster", calls)
    with get_db() as db:
        assert db.execute("SELECT etag FROM repo_sources").fetchone()[0] == '"etag-/repos/OJ/gobuster"'
        db.execute("UPDATE repo_sources SET next_fetch = 0")
        before = db.execute("SELECT updated_at FROM repos").fetchone()[0]
    sent = []
    def spy(method, url, **kw):
        sent.append(kw.get("headers", {}).get("If-None-Match"))
        return fake_github(calls)(method, url, **kw)
    with mock.patch("app.github.netguard.request", side_effect=spy), mock.patch("app.github.time.sleep"):
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    assert '"etag-/repos/OJ/gobuster"' in sent                                    # If-None-Match → 304
    s = authed.get("/api/v1/repos/meta").json()["sources"][0]
    assert s["last_error"] is None and s["repo_count"] == 1
    with get_db() as db:
        assert db.execute("SELECT updated_at FROM repos").fetchone()[0] == before  # nothing re-stored


def test_rate_limited_lines_are_saved_and_finished_later(authed):
    calls = []
    spent = dict(remaining="0", status_for={"/repos/UberGuidoZ/Flipper": 403, "/repos/nobody/missing": 403, "/repos/jhalon/becoming-a-pentester": 403})
    r = follow(authed, "https://github.com/UberGuidoZ/Flipper", calls, **spent)
    assert r.status_code == 200 and r.json()["pending"] and r.json()["requests"] == 1
    assert follow(authed, "https://github.com/nobody/missing", calls, **spent).json()["pending"]
    assert follow(authed, "https://jhalon.github.io/becoming-a-pentester/", calls, **spent).json()["pending"]
    n = len(api_calls(calls))
    follow(authed, "https://github.com/OJ/gobuster", calls, **spent)              # budget known to be spent: no request at all
    assert len(api_calls(calls)) == n
    m = authed.get("/api/v1/repos/meta").json()
    assert all(s["last_fetch"] is None and s["last_error"] is None and s["next_fetch"] >= RESET for s in m["sources"])
    github.reset_rate()
    with get_db() as db:
        db.execute("UPDATE repo_sources SET next_fetch = 0")
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    src = {s["value"]: s for s in authed.get("/api/v1/repos/meta").json()["sources"]}
    assert src["UberGuidoZ/Flipper"]["repo_count"] == 1 and src["OJ/gobuster"]["repo_count"] == 1
    assert "No public repo nobody/missing" in src["nobody/missing"]["last_error"]   # kept, with the reason - not dropped
    site = src["https://jhalon.github.io/becoming-a-pentester/"]                   # no repo, no site repo: kept as a website link
    assert site["kind"] == "doc" and site["last_error"] is None and site["repo_count"] == 1
    assert site["origin"] == "https://jhalon.github.io/becoming-a-pentester/"


def test_website_and_wiki_links_map_to_the_right_repo(authed):
    calls = []
    cases = {
        "https://lolbas-project.github.io/": ("LOLBAS-Project/LOLBAS-Project.github.io", "the website's source repo"),
        "https://mzet-.github.io/2019/05/10/les-paper.html": ("mzet-/mzet-.github.io", "a page on that website - its source repo"),
        "https://github.com/offensive-security/kali-nethunter/wiki": ("offensive-security/kali-nethunter", None),
        "https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/x/": ("swisskyrepo/InternalAllTheThings", "the repo behind that website"),
    }
    for line, (value, note) in cases.items():
        r = follow(authed, line, calls)
        assert r.status_code == 200, (line, r.text)
        assert (r.json()["value"], r.json()["note"]) == (value, note), line
    assert not any("/repos/mzet-/2019" in u for u in api_calls(calls))          # never "<owner>/2019"


def test_batch_saves_at_once_and_checks_in_the_background(authed):
    calls = []
    lines = ["https://github.com/OJ/gobuster", "https://github.com/oj/gobuster/wiki", "https://gist.github.com/x/y",
             "https://lolbas-project.github.io/", "https://github.com/nobody/missing", "https://github.com/UberGuidoZ", "", "  "]
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        with mock.patch.object(github.repo_sync, "maybe_start", return_value=False):
            r = authed.post("/api/v1/repos/sources/batch", json={"lines": lines, "owner_mode": "follow"})
        assert r.status_code == 200, r.text
        assert api_calls(calls) == []                                          # saving costs no GitHub request
        res = r.json()["results"]
        assert [x["status"] for x in res] == ["queued", "duplicate", "invalid", "queued", "queued", "queued"]
        assert "doesn't name a gist" in res[2]["detail"]
        ids = ",".join(str(x["id"]) for x in res if x.get("id"))
        st = authed.get(f"/api/v1/repos/sources/status?ids={ids}").json()["items"]
        assert {x["state"] for x in st} == {"queued"}
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    st = {x["value"]: x for x in authed.get(f"/api/v1/repos/sources/status?ids={ids}").json()["items"]}
    assert st["OJ/gobuster"]["state"] == "done" and st["UberGuidoZ"]["state"] == "done" and st["UberGuidoZ"]["repos"] == 1
    assert st["LOLBAS-Project/LOLBAS-Project.github.io"]["state"] == "done"
    assert st["nobody/missing"]["state"] == "error" and "No public repo" in st["nobody/missing"]["error"]
    assert sum(1 for u in api_calls(calls) if "/repos/OJ/gobuster" in u) == 1    # one request per repo
    again = authed.post("/api/v1/repos/sources/batch", json={"lines": ["https://github.com/OJ/gobuster"]}).json()["results"][0]
    assert again["status"] == "exists"


def test_batch_limits(authed):
    assert authed.post("/api/v1/repos/sources/batch", json={"lines": ["a/b"] * 201}).status_code == 422
    assert authed.post("/api/v1/repos/sources/batch", json={"lines": []}).status_code == 422
    assert authed.post("/api/v1/repos/sources/batch", json={"lines": ["x" * 501]}).status_code == 422
    assert authed.get("/api/v1/repos/sources/status?ids=1;2").status_code == 422
    assert authed.get("/api/v1/repos/sources/status?ids=" + ",".join(["1"] * 201)).status_code == 422
    with mock.patch.object(github.repo_sync, "maybe_start", return_value=False):
        r = authed.post("/api/v1/repos/sources/batch", json={"lines": [f"owner{i}/repo{i}" for i in range(200)]})
    assert r.status_code == 200 and r.json()["queued"] == 200                    # a full 200-line paste is one request
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    csrf = authed.headers.pop("X-CSRF-Token")
    cookies = dict(authed.cookies)
    authed.cookies.clear()
    try:
        assert authed.post("/api/v1/repos/sources/batch", json={"lines": ["a/b"]}, headers=read).status_code == 403
    finally:
        authed.headers["X-CSRF-Token"] = csrf
        authed.cookies.update(cookies)


def test_saving_a_token_resumes_waiting_lines(authed):
    calls = []
    follow(authed, "https://github.com/OJ/gobuster", calls, remaining="0", status_for={"/repos/OJ/gobuster": 403})
    assert authed.get("/api/v1/repos/meta").json()["sources"][0]["next_fetch"] >= RESET
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        r = authed.put("/api/v1/repos/token", json={"token": "ghp_" + "b" * 36})
        assert r.json()["resumed"] == 1
        github.repo_sync.thread.join(10)
    s = authed.get("/api/v1/repos/meta").json()["sources"][0]
    assert s["repo_count"] == 1 and s["last_fetch"]


def _ids(authed):
    return {i["full_name"]: i["id"] for i in authed.get("/api/v1/repos?limit=100").json()["items"]}


def test_folders_crud_filing_and_views(authed):
    follow(authed, "https://github.com/acme", [])
    ids = _ids(authed)
    red = authed.post("/api/v1/repos/folders", json={"name": "Red team", "emoji": "🟥", "color": "#dc2626"}).json()
    lab = authed.post("/api/v1/repos/folders", json={"name": "Homelab"}).json()
    assert lab["emoji"] == "📁" and authed.post("/api/v1/repos/folders", json={"name": "red TEAM"}).status_code == 409
    # bulk add, a repo in two folders
    assert authed.post(f"/api/v1/repos/folders/{red['id']}/items", json={"repo_ids": [ids["acme/proxmox-scripts"], ids["acme/forked"], 999999]}).json()["changed"] == 2
    assert authed.put(f"/api/v1/repos/{ids['acme/proxmox-scripts']}/folders", json={"folder_ids": [red["id"], lab["id"]]}).json()["folders"] == [red["id"], lab["id"]]
    f = {x["name"]: x for x in authed.get("/api/v1/repos/folders").json()["folders"]}
    assert f["Red team"]["repos"] == 2 and f["Homelab"]["repos"] == 1 and f["Red team"]["peek"][0]["full_name"] == "acme/proxmox-scripts"
    assert authed.get("/api/v1/repos/folders").json()["unfiled"] == 1
    # views: a folder, unfiled; repo rows carry their folders
    assert authed.get(f"/api/v1/repos?folder_id={red['id']}").json()["total"] == 2
    assert [i["full_name"] for i in authed.get("/api/v1/repos?folder_id=0").json()["items"]] == ["acme/old-tool"]
    row = [i for i in authed.get("/api/v1/repos").json()["items"] if i["full_name"] == "acme/proxmox-scripts"][0]
    assert sorted(row["folders"]) == sorted([red["id"], lab["id"]])
    assert authed.get(f"/api/v1/repos/shelves?by=language&folder_id={lab['id']}").json()["repos"] == 1
    # rename, emoji, colour, reorder
    assert authed.patch(f"/api/v1/repos/folders/{lab['id']}", json={"name": "Homelab & self-hosting", "emoji": "🏠"}).json()["emoji"] == "🏠"
    authed.post("/api/v1/repos/folders/reorder", json={"ids": [lab["id"], red["id"]]})
    assert [x["id"] for x in authed.get("/api/v1/repos/folders").json()["folders"]] == [lab["id"], red["id"]]
    # remove from a folder; delete a folder: repos stay
    authed.post(f"/api/v1/repos/folders/{red['id']}/items", json={"repo_ids": [ids["acme/forked"]], "action": "remove"})
    assert authed.delete(f"/api/v1/repos/folders/{red['id']}").json()["repos_kept"] == 1
    assert authed.get("/api/v1/repos").json()["total"] == 3
    assert authed.delete(f"/api/v1/repos/folders/{red['id']}").status_code == 404


def test_foldered_repos_survive_removing_their_source(authed):
    follow(authed, "https://github.com/acme", [])
    ids = _ids(authed)
    fid = authed.post("/api/v1/repos/folders", json={"name": "Keep"}).json()["id"]
    authed.post(f"/api/v1/repos/folders/{fid}/items", json={"repo_ids": [ids["acme/old-tool"]]})
    sid = authed.get("/api/v1/repos/meta").json()["sources"][0]["id"]
    r = authed.delete(f"/api/v1/repos/sources/{sid}").json()
    assert r["repos_removed"] == 2 and r["kept_in_folders"] == 1
    assert [i["full_name"] for i in authed.get("/api/v1/repos").json()["items"]] == ["acme/old-tool"]
    authed.put(f"/api/v1/repos/{ids['acme/old-tool']}/folders", json={"folder_ids": []})      # no source, no ★, no folder → gone
    assert authed.get("/api/v1/repos").json()["total"] == 0


def test_batch_files_new_repos_into_a_folder(authed):
    calls = []
    fid = authed.post("/api/v1/repos/folders", json={"name": "Tools"}).json()["id"]
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        with mock.patch.object(github.repo_sync, "maybe_start", return_value=False):
            r = authed.post("/api/v1/repos/sources/batch", json={"lines": ["https://github.com/OJ/gobuster", "https://github.com/UberGuidoZ"], "folder_id": fid,
                                                                    "owner_mode": "follow"})
        assert r.status_code == 200
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    got = {i["full_name"] for i in authed.get(f"/api/v1/repos?folder_id={fid}").json()["items"]}
    assert got == {"OJ/gobuster", "UberGuidoZ/Flipper"}
    assert authed.post("/api/v1/repos/sources/batch", json={"lines": ["a/b"], "folder_id": 999999}).status_code == 404


def test_folder_validation_and_permissions(authed):
    for bad in ({"name": ""}, {"name": "x" * 61}, {"name": "ok", "color": "red;}"}, {"name": "ok", "emoji": "x" * 9}, {"name": "ok", "extra": 1}):
        assert authed.post("/api/v1/repos/folders", json=bad).status_code == 422, bad
    assert authed.post("/api/v1/repos/folders/1/items", json={"repo_ids": []}).status_code == 422
    assert authed.post("/api/v1/repos/folders/1/items", json={"repo_ids": list(range(1, 502))}).status_code == 422
    assert authed.get("/api/v1/repos?folder_id=-1").status_code == 422
    fid = authed.post("/api/v1/repos/folders", json={"name": "<img src=x onerror=alert(1)>"}).json()["id"]   # stored as text
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    csrf = authed.headers.pop("X-CSRF-Token")
    cookies = dict(authed.cookies)
    authed.cookies.clear()
    try:
        assert authed.get("/api/v1/repos/folders", headers=read).status_code == 200
        for method, path, body in (("post", "/api/v1/repos/folders", {"name": "x"}), ("patch", f"/api/v1/repos/folders/{fid}", {"name": "y"}),
                                   ("delete", f"/api/v1/repos/folders/{fid}", None), ("post", "/api/v1/repos/folders/reorder", {"ids": [fid]}),
                                   ("post", f"/api/v1/repos/folders/{fid}/items", {"repo_ids": [1]}), ("put", "/api/v1/repos/1/folders", {"folder_ids": []})):
            kw = {"headers": read} | ({"json": body} if body is not None else {})
            assert getattr(authed, method)(path, **kw).status_code == 403, path
    finally:
        authed.headers["X-CSRF-Token"] = csrf
        authed.cookies.update(cookies)


def test_gists_and_docs_are_saved_as_items(authed):
    calls = []
    lines = ["https://gist.github.com/4n6ist/99241df331bb06f393be935f82f036a5",
             "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
             "https://docs.github.com/en/get-started/getting-started-with-git/managing-remote-repositories?platform=linux&evil=<x>#switching-remote-urls-from-https-to-ssh",
             "https://regseek.github.io/"]
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls)), mock.patch("app.github.time.sleep"):
        with mock.patch.object(github.repo_sync, "maybe_start", return_value=False):
            res = authed.post("/api/v1/repos/sources/batch", json={"lines": lines}).json()["results"]
        assert [r["kind"] for r in res] == ["gist", "doc", "doc", "repo"]
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    assert not any("docs.github.com" in u for u, _ in calls)                     # docs pages are never downloaded
    items = {i["kind"] + ":" + i["name"]: i for i in authed.get("/api/v1/repos?limit=100").json()["items"]}
    gist = items["gist:Windows event log cheat sheet"]
    assert gist["url"] == "https://gist.github.com/4n6ist/99241df331bb06f393be935f82f036a5" and gist["language"] == "Markdown"
    assert "Files: evtx.md, query.ps1" in gist["description"] and "<" not in gist["description"]
    doc = items["doc:Managing your personal access tokens"]
    assert doc["url"].startswith("https://docs.github.com/en/authentication/") and doc["owner"] == "github-docs"
    assert doc["description"] == "GitHub Docs › Authentication › Keeping your account and data secure"
    tab = items["doc:Managing remote repositories (Linux) › Switching remote URLs from HTTPS to SSH"]
    assert tab["url"] == ("https://docs.github.com/en/get-started/getting-started-with-git/managing-remote-repositories?platform=linux"
                          "#switching-remote-urls-from-https-to-ssh")                # only known tabs kept
    site = [i for i in items.values() if i["url"] == "https://regseek.github.io/"][0]  # no public repo: saved as the website
    assert site["kind"] == "doc"
    assert authed.get("/api/v1/repos?kind=gist").json()["total"] == 1
    assert authed.get("/api/v1/repos?kind=doc").json()["total"] == 3
    assert authed.get("/api/v1/repos?kind=evil").status_code == 422
    assert authed.get("/api/v1/repos/meta").json()["kinds"] == {"gist": 1, "doc": 3}
    # folders and ★ work for them too
    fid = authed.post("/api/v1/repos/folders", json={"name": "Docs"}).json()["id"]
    assert authed.post(f"/api/v1/repos/folders/{fid}/items", json={"repo_ids": [doc["id"], gist["id"]]}).json()["changed"] == 2
    assert authed.patch(f"/api/v1/repos/{gist['id']}", json={"starred": True}).status_code == 200


def test_bad_gist_and_doc_links():
    for bad in ("https://gist.github.com/someone", "https://gist.github.com/x/not-an-id!", "https://docs.github.com/"):
        with pytest.raises(github.GitHubError):
            github.parse_input(bad)
    assert github.page_url("https://evil.example/x") is None
    assert github.page_url("https://a.b.github.io/") is None


def test_remove_an_owner_with_its_repos(authed):
    calls = []
    follow(authed, "https://github.com/acme", calls)
    follow(authed, "https://github.com/acme/proxmox-scripts", calls)          # pasted on its own too
    ids = _ids(authed)
    fid = authed.post("/api/v1/repos/folders", json={"name": "All"}).json()["id"]
    authed.post(f"/api/v1/repos/folders/{fid}/items", json={"repo_ids": list(ids.values())})
    authed.patch(f"/api/v1/repos/{ids['acme/forked']}", json={"starred": True})
    owner = [s for s in authed.get("/api/v1/repos/meta").json()["sources"] if s["kind"] == "owner"][0]
    assert authed.get(f"/api/v1/repos/sources/{owner['id']}/only").json() == {"repos": 3, "only_here": 1, "only_here_in_folders": 2}
    r = authed.delete(f"/api/v1/repos/sources/{owner['id']}?with_repos=true").json()
    assert r["repos_removed"] == 1                                              # old-tool went; the starred one and the pasted one stay
    assert set(_ids(authed)) == {"acme/proxmox-scripts", "acme/forked"}


def test_old_sources_table_is_widened_once(tmp_path):
    import sqlite3

    from app import db as dbmod

    p = tmp_path / "old.db"
    conn = sqlite3.connect(p)
    conn.execute("CREATE TABLE repo_sources (id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('owner', 'repo', 'topic', 'stars')), "
                 "value TEXT NOT NULL COLLATE NOCASE, title TEXT NOT NULL DEFAULT '', avatar_url TEXT, created_at INTEGER NOT NULL, "
                 "last_fetch INTEGER, next_fetch INTEGER, last_error TEXT, repo_count INTEGER NOT NULL DEFAULT 0, UNIQUE (kind, value))")
    conn.execute("INSERT INTO repo_sources (kind, value, title, created_at) VALUES ('owner', 'acme', 'ACME', 1)")
    conn.commit()
    conn.close()
    dbmod.init_db(p)
    conn = sqlite3.connect(p)
    assert conn.execute("SELECT kind, value, title FROM repo_sources").fetchall() == [("owner", "acme", "ACME")]
    conn.execute("INSERT INTO repo_sources (kind, value, title, created_at) VALUES ('gist', 'abc', 'x', 1)")   # allowed now
    assert "'doc'" in conn.execute("SELECT sql FROM sqlite_master WHERE name = 'repo_sources'").fetchone()[0]
    conn.close()


def test_links_never_wait_for_the_github_limit(authed):
    calls = []
    lines = ["https://gist.github.com/4n6ist/99241df331bb06f393be935f82f036a5",
             "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"]
    spent = dict(remaining="0", status_for={"/gists/99241df331bb06f393be935f82f036a5": 403})
    with mock.patch("app.github.netguard.request", side_effect=fake_github(calls, **spent)), mock.patch("app.github.time.sleep"):
        with mock.patch.object(github.repo_sync, "maybe_start", return_value=False):
            res = authed.post("/api/v1/repos/sources/batch", json={"lines": lines}).json()["results"]
        github.repo_sync.maybe_start()
        github.repo_sync.thread.join(10)
    st = {x["kind"]: x["state"] for x in authed.get("/api/v1/repos/sources/status?ids=" + ",".join(str(r["id"]) for r in res)).json()["items"]}
    assert st == {"gist": "waiting", "doc": "done"}


def test_profile_links_ask_first(authed):
    with mock.patch.object(github.repo_sync, "maybe_start", return_value=False):
        res = authed.post("/api/v1/repos/sources/batch", json={"lines": ["https://github.com/elastic", "https://github.com/OJ/gobuster"]}).json()["results"]
        assert [r["status"] for r in res] == ["ask", "queued"]                   # nothing saved for the profile yet
        assert {s["kind"] for s in authed.get("/api/v1/repos/meta").json()["sources"]} == {"repo"}
        prof = authed.post("/api/v1/repos/sources/batch", json={"lines": ["https://github.com/elastic"], "owner_mode": "profile"}).json()["results"][0]
        assert prof["status"] == "queued" and prof["kind"] == "doc" and prof["value"] == "https://github.com/elastic"
        foll = authed.post("/api/v1/repos/sources/batch", json={"lines": ["https://github.com/elastic"], "owner_mode": "follow"}).json()["results"][0]
        assert foll["status"] == "queued" and foll["kind"] == "owner"
        again = authed.post("/api/v1/repos/sources/batch", json={"lines": ["https://github.com/elastic"]}).json()["results"][0]
        assert again["status"] == "exists"
    item = github.clean_doc("https://github.com/elastic")
    assert item["name"] == "elastic (GitHub profile)" and item["owner"] == "elastic"
    assert authed.post("/api/v1/repos/sources/batch", json={"lines": ["a/b"], "owner_mode": "evil"}).status_code == 422


def test_repo_topic_tuning(authed):
    from app.db import now as _now

    def add(full, desc="", tags=()):
        with get_db() as db:
            item = github.clean_repo(repo(full, desc=desc, topics=tags))
            return github.store_repo(db, item)

    def names(rid):
        with get_db() as db:
            return {t[0] for t in db.execute("SELECT t.name FROM repo_topics x JOIN topics t ON t.id = x.topic_id WHERE x.repo_id = ?", (rid,))}
    a = add("elastic/go-elasticsearch", "The official Go client for Elasticsearch: logs, monitoring")      # loose words only
    b = add("ez/EvtxECmd", "Windows event log (evtx) parser", ["windows", "forensics"])                      # DFIR wins over Windows
    c = add("x/web-ui", "A browser extension with oauth login")                                              # not web security
    ezs = [add(f"EricZ/Tool{i}", "Windows forensics artifact parser") for i in range(6)]
    bare = add("EricZ/MFTECmd", "")                                                                          # gets the owner's main topic
    with get_db() as db:
        github.classify(db)
    assert "Blue team & DFIR" not in names(a)
    assert "Blue team & DFIR" in names(b) and "Windows & endpoint" not in names(b)
    assert "Web security" not in names(c)
    assert names(bare) == {"Blue team & DFIR"}
    assert all("Blue team & DFIR" in names(i) for i in ezs)
    _ = _now
