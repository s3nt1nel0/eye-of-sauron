"""📦 Repos tab: follow GitHub owners (users / organisations), single repositories, GitHub topics and a user's stars.

Data comes from GitHub's official REST API (``api.github.com``) and, for releases of individually followed repos,
GitHub's public release Atom feed (``github.com/<owner>/<repo>/releases.atom``). Nothing is scraped.

* Without a token GitHub allows 60 API requests an hour; an optional read-only token (stored encrypted in the
  ``integrations`` table, never returned by the API) raises that to 5,000. The rate-limit headers are honoured:
  when the budget is spent the sync stops and resumes after GitHub's reset time.
* Every request goes through the SSRF guard (``netguard``) to the two fixed GitHub hosts. Names are validated
  strictly before they are put in a URL, and every URL is built here - never taken from a response.
* Text from GitHub is stored as plain text (markup stripped) and rendered as text by the UI. Homepages are kept
  only when they are plain http(s) links. READMEs are not fetched or rendered.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import threading
import time
from calendar import timegm
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

from app import integrations, netguard, topics
from app.config import get_settings
from app.db import get_db, now, placeholders
from app.sanitize import to_text

log = logging.getLogger("eos.github")

API = "https://api.github.com"
WEB = "https://github.com"
KINDS = ("owner", "repo", "topic", "stars")
REFRESH_SECONDS = 12 * 3600          # each source is checked twice a day
RETRY_SECONDS = 3600                 # after an error
MAX_PAGES = 5                        # 100 repos a page: up to 500 repos per owner / stars list
TOPIC_RESULTS = 100                  # most-starred repos of a GitHub topic
MAX_RELEASES = 20                    # newest releases kept per followed repo
MAX_SOURCES = 1000
MAX_BATCH = 200                      # lines per paste (＋ Add from GitHub)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ATOM_BYTES = 2 * 1024 * 1024
NOT_FOR_REPOS = ("Podcasts & interviews", "Conferences & talks", "Cyber news", "Careers & development", "General")

# GitHub logins: letters, digits, hyphens, not starting with one; older accounts may end in one or have two in a row ("mzet-")
OWNER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
REPO = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
TOPIC = re.compile(r"^[a-z0-9][a-z0-9-]{0,49}$")
TOKEN = re.compile(r"^(?:gh[pousr]_[A-Za-z0-9]{30,251}|github_pat_[A-Za-z0-9_]{22,255})$")
LANGUAGE = re.compile(r"^[\w#+.' -]{1,50}$")
LICENSE = re.compile(r"^[A-Za-z0-9.+-]{1,50}$")
AVATAR_HOST = "avatars.githubusercontent.com"
# github.com paths that are not users or organisations
RESERVED = {"about", "account", "apps", "blog", "collections", "contact", "customer-stories", "dashboard", "enterprise",
            "events", "explore", "features", "issues", "join", "login", "logout", "marketplace", "new", "notifications",
            "orgs", "organizations", "pricing", "pulls", "search", "security", "settings", "site", "sponsors", "stars",
            "team", "topics", "trending", "users", "codespaces", "copilot", "readme", "resources", "solutions"}


class GitHubError(Exception):
    """A problem worth showing the user (bad name, not found, rate limit, bad token)."""


class NotFound(GitHubError):
    """GitHub answered 404: the name doesn't exist (or is private - GitHub doesn't say which)."""


class RateLimited(GitHubError):
    def __init__(self, reset: int, bucket: str = "core") -> None:
        self.reset = reset
        what = "search limit (topics)" if bucket == "search" else "hourly request limit"
        super().__init__(f"GitHub's {what} is used up - continuing after {time.strftime('%H:%M', time.localtime(reset))}. "
                         "A free read-only GitHub token raises the limit (Repos → ⚙ Sources).")


# ============================================================================ input
class NotRepoLink(GitHubError):
    """A link we understand but can't follow (a gist, a file host, another site)."""


class Parsed(tuple):
    """(kind, value) plus where it came from: ``via`` = "github" | "pages" (an <owner>.github.io website) | "raw";
    ``pages`` = the website as pasted; ``note`` = how it was mapped; ``alt`` = a second repo to try for a website."""

    via: str = "github"
    pages: str = ""
    note: str = ""
    alt: str = ""

    def __new__(cls, kind: str, value: str, via: str = "github", pages: str = "", note: str = "", alt: str = ""):
        obj = super().__new__(cls, (kind, value))
        obj.via, obj.pages, obj.note, obj.alt = via, pages, note, alt
        return obj


SITE_NOTE = "the website's source repo"
PROJECT_NOTE = "the repo behind that website"
POST_NOTE = "a page on that website - its source repo"
# first path parts of a user / organisation website that are pages, not project sites
_SITE_PAGES = re.compile(r"^(\d{4}|posts?|blog|tags?|categor(y|ies)|archives?|about|page|feed\.xml|.+\.html?)$", re.I)


HELP = "Paste a GitHub link, owner/repo, topic:<name> or stars:<user>."


def parse_input(raw: str) -> Parsed:
    """A pasted line → (kind, value). Accepts github.com links (any page inside a repo: /blob/…, /tree/…, ?tab=…, #…),
    ``owner``, ``@owner``, ``owner/repo``, ``topic:<name>`` (or github.com/topics/<name>), ``stars:<user>`` (or
    github.com/<user>?tab=stars), ``<owner>.github.io/<repo>/…`` websites (→ the repo they're built from) and
    raw.githubusercontent.com file links. Gists and other sites are refused with a clear reason."""
    s = (raw or "").strip().strip("<>\"'").strip()
    if not s or len(s) > 500:
        raise GitHubError(HELP)
    low = s.lower()
    for prefix, kind in (("topic:", "topic"), ("stars:", "stars")):
        if low.startswith(prefix):
            return Parsed(*_checked(kind, s[len(prefix):].strip().lstrip("@")))
    host_like = re.match(r"^(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?(?:[/?#]|$)", low)
    if "://" in low or host_like:
        parts = urlsplit(s if "://" in s else "https://" + s)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or parts.username or parts.password:
            raise NotRepoLink("Only GitHub links (https://github.com/…) can be added.")
        segs = [b for b in parts.path.split("/") if b]
        if host in ("gist.github.com", "gist.githubusercontent.com"):
            ids = [b for b in segs if GIST_ID.match(b)]
            if not ids:
                raise NotRepoLink("That gist link doesn't name a gist (it should end in the gist's id).")
            return Parsed("gist", ids[0].lower(), via="gist")
        if host == "docs.github.com":
            return Parsed("doc", doc_url(parts), via="docs", note=DOCS_NOTE)
        if host in ("raw.githubusercontent.com",):
            if len(segs) >= 2:
                return Parsed(*_checked("repo", f"{segs[0]}/{_strip_git(segs[1])}"), via="raw")
            raise NotRepoLink("That raw.githubusercontent.com link doesn't name a repo.")
        if host.endswith(".github.io") and host.count(".") == 2:
            owner = host[: -len(".github.io")]
            site_repo = f"{owner}/{host}"                 # a user / organisation website is built from "<owner>/<owner>.github.io"
            if not segs:
                return Parsed(*_checked("repo", site_repo), via="pages", pages=host, note=SITE_NOTE)
            if _SITE_PAGES.match(segs[0]) or not REPO.match(segs[0]):  # /2019/05/10/post.html, /blog/…: a page of the main site
                return Parsed(*_checked("repo", site_repo), via="pages", pages=f"{host}/{'/'.join(segs)[:120]}", note=POST_NOTE)
            # /<name>/…: usually a project site built from "<owner>/<name>"; if there's no such repo, it's a page of the main site
            return Parsed(*_checked("repo", f"{owner}/{segs[0]}"), via="pages", pages=f"{host}/{segs[0]}", note=PROJECT_NOTE,
                          alt=_checked("repo", site_repo)[1])
        if host in ("gitlab.com", "www.gitlab.com"):
            return Parsed("gitlab", gitlab_path(segs), via="gitlab")
        if host not in ("github.com", "www.github.com"):
            raise NotRepoLink(f"{host} isn't GitHub: only github.com links (repos, owners, topics, stars) can be added.")
        return _from_path(segs, parts.query)
    return _from_path([b for b in s.split("#", 1)[0].split("?", 1)[0].split("/") if b], s.split("?", 1)[1] if "?" in s else "")


GIST_ID = re.compile(r"^(?:[0-9a-fA-F]{20,40}|\d{1,12})$")
DOCS_NOTE = "a GitHub Docs page"
PAGE_NOTE = "a website with no public repo behind it - saved as a link"
PROFILE_NOTE = "a GitHub profile - saved as a link (its repos aren't followed)"


def profile_url(login: str) -> str:
    return f"{WEB}/{quote(login)}"
_DOC_QUERY = ("platform", "tool", "apiVersion")
_ACRONYMS = {"ssh": "SSH", "https": "HTTPS", "http": "HTTP", "url": "URL", "urls": "URLs", "api": "API", "apis": "APIs", "gpg": "GPG",
             "cli": "CLI", "ssl": "SSL", "tls": "TLS", "2fa": "2FA", "ip": "IP", "github": "GitHub", "git": "Git", "saml": "SAML",
             "sso": "SSO", "oauth": "OAuth", "rest": "REST", "graphql": "GraphQL", "ci": "CI", "cd": "CD", "codeql": "CodeQL", "npm": "npm"}


def _words(slug: str) -> str:
    """ "managing-your-personal-access-tokens" → "Managing your personal access tokens" (common acronyms kept)."""
    slug = re.sub(r"\.html?$", "", slug, flags=re.I)
    out = [_ACRONYMS.get(w.lower(), w.lower()) for w in re.split(r"[-_\s]+", slug) if w]
    if out and out[0] == out[0].lower():
        out[0] = out[0][:1].upper() + out[0][1:]
    return " ".join(out)[:200]


def doc_url(parts) -> str:
    """A docs.github.com link reduced to its page (+ the platform / tool tab and section it points at). Built here from
    checked parts - the page is never fetched."""
    segs = [s for s in parts.path.split("/") if s and re.match(r"^[\w.-]{1,120}$", s)]
    if not segs:
        raise NotRepoLink("That docs.github.com link doesn't name a page.")
    query = [(k, v) for k, v in parse_qsl(parts.query) if k in _DOC_QUERY and re.match(r"^[\w.-]{1,40}$", v)]
    frag = parts.fragment if re.match(r"^[\w-]{1,120}$", parts.fragment or "") else ""
    return ("https://docs.github.com/" + "/".join(quote(s) for s in segs) + (f"?{urlencode(query)}" if query else "")
            + (f"#{frag}" if frag else ""))[:500]


def page_url(origin: str) -> str | None:
    """A <owner>.github.io page link (the line you pasted) as a clean https address, or None."""
    s = (origin or "").strip()
    parts = urlsplit(s if "://" in s else "https://" + s)
    host = (parts.hostname or "").lower()
    if not (host.endswith(".github.io") and host.count(".") == 2 and OWNER.match(host[: -len(".github.io")])):
        return None
    segs = [quote(x) for x in parts.path.split("/") if x and re.match(r"^[\w.%~-]{1,120}$", x)]
    frag = parts.fragment if re.match(r"^[\w-]{1,120}$", parts.fragment or "") else ""
    return (f"https://{host}/" + "/".join(segs) + ("/" if segs and parts.path.endswith("/") else "") + (f"#{frag}" if frag else ""))[:500]


def clean_doc(url: str, kind_note: str | None = None) -> dict[str, Any]:
    """A docs / website link as a Repos item - title and trail come from the address itself (nothing is downloaded)."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    segs = [unquote(s) for s in parts.path.split("/") if s]
    if host == "github.com":   # a profile saved as a link
        login = segs[0] if segs and OWNER.match(segs[0]) else "github"
        return {"gh_id": None, "full_name": f"doc:{hashlib.sha256(url.encode()).hexdigest()[:20]}", "owner": login,
                "name": f"{login} (GitHub profile)", "description": "GitHub profile - saved as a link; its repos aren't followed.",
                "language": None, "stars": 0, "forks": 0, "open_issues": 0, "gh_topics": "[]", "license": None, "homepage": None,
                "archived": 0, "is_fork": 0, "owner_avatar": None, "created_ts": None, "pushed_ts": None, "kind": "doc", "url": url}
    if host == "docs.github.com":
        trail = [s for s in segs if not re.match(r"^[a-z]{2}(-[a-z]{2})?$", s)]
        title = _words(trail[-1]) if trail else "GitHub Docs"
        q = dict(parse_qsl(parts.query))
        if q.get("platform") or q.get("tool"):
            title += f" ({_words(q.get('platform') or q.get('tool'))})"
        if parts.fragment:
            title += f" › {_words(parts.fragment)}"
        desc = "GitHub Docs › " + " › ".join(_words(s) for s in trail[:-1]) if len(trail) > 1 else "GitHub Docs"
        owner, avatar = "github-docs", None
    else:
        owner = host[: -len(".github.io")]
        title = _words(segs[-1]) if segs else host
        if parts.fragment:
            title += f" › {_words(parts.fragment)}"
        desc = f"Website {host}" + (" › " + " › ".join(_words(s) for s in segs[:-1]) if len(segs) > 1 else "")
        avatar = None
    key = hashlib.sha256(url.encode()).hexdigest()[:20]
    return {"gh_id": None, "full_name": f"doc:{key}", "owner": owner, "name": title, "description": desc[:500], "language": None,
            "stars": 0, "forks": 0, "open_issues": 0, "gh_topics": "[]", "license": None, "homepage": None, "archived": 0,
            "is_fork": 0, "owner_avatar": avatar, "created_ts": None, "pushed_ts": None, "kind": "doc", "url": url}


def clean_gist(g: Any, gist_id: str) -> dict[str, Any] | None:
    """One gist from GitHub's API → a Repos item (plain text; the address is built from the validated id)."""
    if not isinstance(g, dict):
        return None
    owner_obj = g.get("owner") if isinstance(g.get("owner"), dict) else {}
    login = owner_obj.get("login") if isinstance(owner_obj.get("login"), str) and OWNER.match(owner_obj.get("login")) else "anonymous"
    files = g.get("files") if isinstance(g.get("files"), dict) else {}
    names = [n for n in files if isinstance(n, str)][:50]
    langs = [f.get("language") for f in files.values() if isinstance(f, dict) and isinstance(f.get("language"), str) and LANGUAGE.match(f.get("language"))]
    desc = to_text(g.get("description") if isinstance(g.get("description"), str) else "", 500)
    title = (desc.split("\n")[0][:120] if desc else "") or (to_text(names[0], 120) if names else f"Gist {gist_id[:8]}")
    files_txt = ", ".join(to_text(n, 80) for n in names[:8]) + (f" (+{len(names) - 8} more)" if len(names) > 8 else "")
    return {"gh_id": None, "full_name": f"gist:{gist_id}", "owner": login, "name": title,
            "description": (desc + ("\n" if desc else "") + f"Files: {files_txt}")[:500] if names else desc,
            "language": langs[0] if langs else None, "stars": 0, "forks": 0,
            "open_issues": int(g.get("comments")) if isinstance(g.get("comments"), int) and g.get("comments") >= 0 else 0,
            "gh_topics": "[]", "license": None, "homepage": None, "archived": 0, "is_fork": 0,
            "owner_avatar": _avatar(owner_obj.get("avatar_url")), "created_ts": _ts(g.get("created_at")), "pushed_ts": _ts(g.get("updated_at")),
            "kind": "gist", "url": f"https://gist.github.com/{quote(login)}/{quote(gist_id)}" if login != "anonymous" else f"https://gist.github.com/{quote(gist_id)}"}


GITLAB = "https://gitlab.com"
GITLAB_API = "https://gitlab.com/api/v4"
GL_SEG = re.compile(r"^[A-Za-z0-9_.][A-Za-z0-9_.-]{0,99}$")
GL_RESERVED = {"explore", "users", "groups", "dashboard", "help", "api", "search", "projects", "admin", "-", "snippets", "uploads"}


def gitlab_path(segs: list[str]) -> str:
    """gitlab.com/<group>/<subgroups…>/<project>[/-/blob/…] → "group/…/project" (validated). Groups alone aren't followed."""
    if "-" in segs:
        segs = segs[:segs.index("-")]
    segs = [_strip_git(x) for x in segs]
    if len(segs) < 2:
        raise NotRepoLink("GitLab groups and users aren't supported yet: paste a GitLab project link (gitlab.com/<group>/<project>).")
    if len(segs) > 20 or segs[0].lower() in GL_RESERVED or not all(GL_SEG.match(x) and x not in (".", "..") for x in segs):
        raise GitHubError("That isn't a valid GitLab project link.")
    return "/".join(segs)


def gl_get(path: str, params: dict[str, Any] | None = None) -> Any:
    """GET GitLab's public REST API (``path`` built here from a validated project path). Unauthenticated, read-only."""
    url = GITLAB_API + path + (f"?{urlencode(params)}" if params else "")
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": get_settings().user_agent, "Accept": "application/json"},
                                max_bytes=MAX_JSON_BYTES, timeout=20.0, max_redirects=2)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise GitHubError(f"GitLab couldn't be reached: {str(exc)[:150]}") from None
    if resp.status_code == 404:
        raise NotFound("Not found on GitLab: it doesn't exist or is private.")
    if resp.status_code == 429:
        raise GitHubError("GitLab asked to slow down - it is tried again later.")
    if resp.status_code != 200:
        raise GitHubError(f"GitLab answered {resp.status_code}.")
    try:
        return json.loads(resp.content)
    except ValueError:
        raise GitHubError("GitLab sent something that isn't JSON.") from None


def clean_gitlab(p: Any, path: str) -> dict[str, Any] | None:
    """One GitLab project → a Repos item (plain text; its address is built from the validated path)."""
    if not isinstance(p, dict):
        return None
    full = p.get("path_with_namespace") if isinstance(p.get("path_with_namespace"), str) else path
    try:
        full = gitlab_path(full.split("/"))
    except GitHubError:
        full = path
    top = full.split("/")[0]
    tags = [t.lower().replace(" ", "-") for t in (p.get("topics") or p.get("tag_list") or []) if isinstance(t, str)]
    tags = [t for t in tags if TOPIC.match(t)][:20]
    lic = p.get("license") if isinstance(p.get("license"), dict) else {}
    key = lic.get("key") if isinstance(lic.get("key"), str) else None
    num = lambda k: int(p.get(k)) if isinstance(p.get(k), int) and p.get(k) >= 0 else 0  # noqa: E731
    return {"gh_id": None, "full_name": f"gitlab.com/{full}", "owner": top if OWNER.match(top) else "gitlab",
            "name": full.split("/")[-1], "description": to_text(p.get("description") if isinstance(p.get("description"), str) else "", 500),
            "language": None, "stars": num("star_count"), "forks": num("forks_count"), "open_issues": num("open_issues_count"),
            "gh_topics": json.dumps(tags), "license": key.upper()[:50] if key and LICENSE.match(key) else None,
            "homepage": None, "archived": 1 if p.get("archived") is True else 0, "is_fork": 1 if isinstance(p.get("forked_from_project"), dict) else 0,
            "owner_avatar": None, "created_ts": _ts(p.get("created_at")), "pushed_ts": _ts(p.get("last_activity_at")),
            "kind": "repo", "url": f"{GITLAB}/{'/'.join(quote(x) for x in full.split('/'))}"}


def gitlab_releases(project_id: int, web: str) -> list[dict[str, Any]]:
    try:
        rel = gl_get(f"/projects/{int(project_id)}/releases", {"per_page": MAX_RELEASES})
    except GitHubError:
        return []
    out = []
    for r in rel if isinstance(rel, list) else []:
        tag = r.get("tag_name") if isinstance(r, dict) and isinstance(r.get("tag_name"), str) else None
        ts = _ts(r.get("released_at") or r.get("created_at")) if isinstance(r, dict) else None
        if not tag or not ts:
            continue
        out.append({"tag": tag[:200], "title": to_text(r.get("name") or tag, 300), "url": f"{web}/-/releases/{quote(tag, safe='')}",
                    "published_ts": ts, "summary": to_text(r.get("description") or "", 600)})
    return out


def _strip_git(name: str) -> str:
    return name[:-4] if name.lower().endswith(".git") else name


def _from_path(segs: list[str], query: str) -> Parsed:
    if segs and segs[0].startswith("@"):
        segs[0] = segs[0][1:]
    if len(segs) >= 2 and segs[0].lower() == "topics":
        return Parsed(*_checked("topic", segs[1]))
    if len(segs) >= 2 and segs[0].lower() == "stars":          # github.com/stars/<user>
        return Parsed(*_checked("stars", segs[1]))
    if segs and segs[0].lower() in ("orgs", "users") and len(segs) >= 2:  # github.com/orgs/<org>/repositories
        return Parsed(*_checked("owner", segs[1]))
    if len(segs) == 1:
        if re.search(r"(^|&)tab=stars(&|$)", query):
            return Parsed(*_checked("stars", segs[0]))
        return Parsed(*_checked("owner", segs[0]))
    if len(segs) >= 2:
        return Parsed(*_checked("repo", f"{segs[0]}/{_strip_git(segs[1])}"))
    raise GitHubError(HELP)


def _checked(kind: str, value: str) -> tuple[str, str]:
    if kind == "topic":
        value = value.lower()
        if not TOPIC.match(value):
            raise GitHubError("A GitHub topic is lower-case letters, digits and dashes (for example homelab).")
        return kind, value
    if kind == "repo":
        owner, _, name = value.partition("/")
        if not OWNER.match(owner) or not REPO.match(name) or name in (".", "..") or owner.lower() in RESERVED:
            raise GitHubError(f"“{value[:120]}” isn't a valid owner/repo name.")
        return kind, f"{owner}/{name}"
    if not OWNER.match(value) or value.lower() in RESERVED:
        raise GitHubError(f"“{value[:120]}” isn't a valid GitHub user or organisation name.")
    return kind, value


def source_url(kind: str, value: str) -> str:
    """The page on github.com for a source (built from validated names only)."""
    if kind == "gitlab":
        return f"{GITLAB}/{'/'.join(quote(x) for x in value.split('/'))}"
    if kind == "gist":
        return f"https://gist.github.com/{quote(value)}"
    if kind == "doc":
        return value if value.startswith("https://") else ""
    if kind == "topic":
        return f"{WEB}/topics/{quote(value)}"
    if kind == "stars":
        return f"{WEB}/{quote(value)}?tab=stars"
    return f"{WEB}/{quote(value, safe='/')}"


# ============================================================================ HTTP
# GitHub keeps separate budgets: "core" (60 an hour without a token, 5,000 with) and "search" (10 / 30 a minute)
_rate: dict[str, dict[str, int | None]] = {"core": {"remaining": None, "limit": None, "reset": 0},
                                           "search": {"remaining": None, "limit": None, "reset": 0}}
_rate_lock = threading.Lock()


def reset_rate() -> None:
    with _rate_lock:
        for b in _rate.values():
            b.update(remaining=None, limit=None, reset=0)


def rate_status() -> dict[str, Any]:
    """The hourly ("core") budget - the one that matters for following owners, repos and stars."""
    with _rate_lock:
        return dict(_rate["core"])


def _token(db=None) -> str | None:
    if db is not None:
        return integrations.secret(db, "github", "token")
    with get_db() as conn:
        return integrations.secret(conn, "github", "token")


def _headers(token: str | None, accept: str = "application/vnd.github+json") -> dict[str, str]:
    h = {"User-Agent": get_settings().user_agent, "Accept": accept}
    if accept.startswith("application/vnd.github"):
        h["X-GitHub-Api-Version"] = "2022-11-28"
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _bucket(path: str) -> str:
    return "search" if path.startswith("/search/") else "core"


def _note_rate(resp: netguard.SafeResponse, bucket: str) -> None:
    def num(name: str) -> int | None:
        v = resp.headers.get(name)
        return int(v) if v and v.isdigit() else None
    remaining, limit, reset = num("x-ratelimit-remaining"), num("x-ratelimit-limit"), num("x-ratelimit-reset")
    if remaining is None:
        return
    said = (resp.headers.get("x-ratelimit-resource") or bucket).lower()
    with _rate_lock:
        _rate["search" if said == "search" else "core"].update(remaining=remaining, limit=limit, reset=reset or 0)


def _check_budget(bucket: str) -> None:
    with _rate_lock:
        remaining, reset = _rate[bucket]["remaining"], int(_rate[bucket]["reset"] or 0)
    if remaining == 0 and reset > time.time():
        raise RateLimited(reset, bucket)


def api_get(path: str, params: dict[str, Any] | None = None, token: str | None = None) -> Any:
    """GET a GitHub REST endpoint (``path`` is built by this module from validated names)."""
    return api_get_cond(path, params, token)[0]


_sent = threading.local()


def requests_sent() -> int:
    """API requests this thread has sent (to report what adding a line cost)."""
    return getattr(_sent, "n", 0)


def api_get_cond(path: str, params: dict[str, Any] | None = None, token: str | None = None,
                 etag: str | None = None) -> tuple[Any, str | None]:
    """GET with an optional If-None-Match: (data, etag), or (None, etag) when GitHub says nothing changed (304).
    With a token a 304 doesn't count against the hourly limit; without one it still does, but nothing is re-stored."""
    bucket = _bucket(path)
    if path != "/rate_limit":   # GitHub's /rate_limit is free: checking a new token must work even when the free hour is spent
        _check_budget(bucket)
    url = API + path + (f"?{urlencode(params)}" if params else "")
    headers = _headers(token)
    if etag and re.match(r'^(W/)?"[\w./+=-]{1,200}"$', etag):
        headers["If-None-Match"] = etag
    _sent.n = requests_sent() + 1
    try:
        resp = netguard.request("GET", url, headers=headers, max_bytes=MAX_JSON_BYTES, timeout=20.0, max_redirects=2)
    except (netguard.FetchError, netguard.UnsafeURLError) as exc:
        raise GitHubError(f"GitHub couldn't be reached: {str(exc)[:150]}") from None
    _note_rate(resp, bucket)
    new_etag = resp.headers.get("etag")
    new_etag = new_etag if new_etag and len(new_etag) <= 210 else None
    if resp.status_code == 304:
        return None, etag
    if resp.status_code == 404:
        raise NotFound("Not found on GitHub: it doesn't exist, was deleted or renamed, or is private.")
    if resp.status_code == 401:
        raise GitHubError("GitHub refused the token (expired or revoked?) - replace or remove it in Repos → ⚙ Sources.")
    if resp.status_code in (403, 429):
        with _rate_lock:
            spent = _rate[bucket]["remaining"] == 0
            reset = int(_rate[bucket]["reset"] or 0)
        retry = resp.headers.get("retry-after")
        if spent or (retry and retry.isdigit()):
            raise RateLimited(reset if spent and reset else int(time.time()) + int(retry or 60), bucket)
        raise GitHubError("GitHub refused the request (403).")
    if resp.status_code == 422:
        raise GitHubError("GitHub didn't accept that name.")
    if resp.status_code != 200:
        raise GitHubError(f"GitHub answered {resp.status_code}.")
    try:
        return json.loads(resp.content), new_etag
    except ValueError:
        raise GitHubError("GitHub sent something that isn't JSON.") from None


def check_token(token: str) -> dict[str, Any]:
    """Validate a token with the free /rate_limit endpoint (it doesn't use up any of the budget)."""
    if not TOKEN.match(token or ""):
        raise GitHubError("That doesn't look like a GitHub token (ghp_…, github_pat_…).")
    data = api_get("/rate_limit", token=token)
    core = (data or {}).get("resources", {}).get("core", {}) if isinstance(data, dict) else {}
    return {"limit": core.get("limit"), "remaining": core.get("remaining")}


# ============================================================================ storage
def _ts(value: Any) -> int | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        return None


def _homepage(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if not v or len(v) > 500:
        return None
    if "://" not in v and re.match(r"^[\w.-]+\.[a-z]{2,}(/|$)", v, re.I):
        v = "https://" + v
    parts = urlsplit(v)
    return v if parts.scheme in ("http", "https") and parts.hostname and not parts.username and not parts.password else None


def _avatar(value: Any) -> str | None:
    if not isinstance(value, str) or len(value) > 300:
        return None
    parts = urlsplit(value)
    return value if parts.scheme == "https" and parts.hostname == AVATAR_HOST and not parts.username else None


def clean_repo(r: Any) -> dict[str, Any] | None:
    """One GitHub repository object → the fields we keep (validated, plain text); None if unusable."""
    if not isinstance(r, dict):
        return None
    full = r.get("full_name")
    if not isinstance(full, str) or "/" not in full:
        return None
    owner, _, name = full.partition("/")
    if not OWNER.match(owner) or not REPO.match(name):
        return None
    gh_topics = [t for t in (r.get("topics") or []) if isinstance(t, str) and TOPIC.match(t)][:20]
    lic = r.get("license") if isinstance(r.get("license"), dict) else {}
    spdx = lic.get("spdx_id") if isinstance(lic.get("spdx_id"), str) and LICENSE.match(lic.get("spdx_id")) else None
    lang = r.get("language") if isinstance(r.get("language"), str) and LANGUAGE.match(r.get("language")) else None
    num = lambda k: int(r.get(k)) if isinstance(r.get(k), int) and r.get(k) >= 0 else 0  # noqa: E731
    gh_id = r.get("id") if isinstance(r.get("id"), int) and r.get("id") > 0 else None
    owner_obj = r.get("owner") if isinstance(r.get("owner"), dict) else {}
    return {
        "gh_id": gh_id, "full_name": full, "owner": owner, "name": name,
        "description": to_text(r.get("description") if isinstance(r.get("description"), str) else "", 500),
        "language": lang, "stars": num("stargazers_count"), "forks": num("forks_count"), "open_issues": num("open_issues_count"),
        "gh_topics": json.dumps(gh_topics), "license": None if spdx in (None, "NOASSERTION") else spdx,
        "homepage": _homepage(r.get("homepage")), "archived": 1 if r.get("archived") is True else 0,
        "is_fork": 1 if r.get("fork") is True else 0, "owner_avatar": _avatar(owner_obj.get("avatar_url")),
        "created_ts": _ts(r.get("created_at")), "pushed_ts": _ts(r.get("pushed_at")), "kind": "repo", "url": None,
    }


FIELDS = ("gh_id", "full_name", "owner", "name", "description", "language", "stars", "forks", "open_issues", "gh_topics",
          "license", "homepage", "archived", "is_fork", "owner_avatar", "created_ts", "pushed_ts", "kind", "url")


def store_repo(db, repo: dict[str, Any]) -> int:
    """Insert or update one cleaned repo; returns its id. A renamed repo (same GitHub id) keeps its row and ★."""
    row = None
    if repo["gh_id"]:
        row = db.execute("SELECT id FROM repos WHERE gh_id = ?", (repo["gh_id"],)).fetchone()
    if row is None:
        row = db.execute("SELECT id FROM repos WHERE full_name = ?", (repo["full_name"],)).fetchone()
    t = now()
    if row is None:
        cols = ", ".join(FIELDS)
        return db.execute(f"INSERT INTO repos ({cols}, added_at, updated_at) VALUES ({placeholders(len(FIELDS) + 2)})",  # nosec B608
                          [repo[k] for k in FIELDS] + [t, t]).lastrowid
    clash = db.execute("SELECT id FROM repos WHERE full_name = ? AND id != ?", (repo["full_name"], row["id"])).fetchone()
    if clash:  # the name now belongs to this repo: the stale row of the old owner of the name goes
        db.execute("DELETE FROM repos WHERE id = ?", (clash["id"],))
    sets = ", ".join(f"{k} = ?" for k in FIELDS)
    db.execute(f"UPDATE repos SET {sets}, updated_at = ? WHERE id = ?", [repo[k] for k in FIELDS] + [t, row["id"]])  # nosec B608
    return row["id"]


def drop_orphans(db) -> int:
    """Repos no source lists any more go, except the ones you ★ starred or put in a 📁 folder."""
    return db.execute("DELETE FROM repos WHERE starred = 0 AND id NOT IN (SELECT repo_id FROM repo_source_links) "
                      "AND id NOT IN (SELECT repo_id FROM repo_folder_items)").rowcount


def file_into_folder(db, source_id: int, repo_ids: list[int]) -> None:
    """A source added with a folder chosen: its repos go into that folder on the first fetch (later ones aren't forced in)."""
    row = db.execute("SELECT folder_id FROM repo_sources WHERE id = ?", (source_id,)).fetchone()
    if not row or not row["folder_id"]:
        return
    if db.execute("SELECT 1 FROM repo_folders WHERE id = ?", (row["folder_id"],)).fetchone():
        db.executemany("INSERT OR IGNORE INTO repo_folder_items (folder_id, repo_id, added_at) VALUES (?, ?, ?)",
                       [(row["folder_id"], i, now()) for i in repo_ids])
    db.execute("UPDATE repo_sources SET folder_id = NULL WHERE id = ?", (source_id,))


# Repo-specific topic tuning: repos describe themselves differently from news. Extra words a repo uses for a topic, and
# "loose" words that only count for a repo when a real signal for that topic is there too (an Elastic client mentions
# "elastic" and "monitoring" without being DFIR; a plugin mentioning "browser" isn't web security).
REPO_EXTRA = {
    "Blue team & DFIR": ["forensic", "forensics", "evtx", "event log", "event logs", "eventlog", "kape", "gkape", "triage", "mft", "ntfs",
                         "prefetch", "shellbags", "amcache", "srum", "lnk", "jump lists", "timeline", "timeliner", "artifact", "artifacts",
                         "registry explorer", "memory analysis", "autopsy", "sleuthkit", "plaso", "chainsaw", "hayabusa", "velociraptor",
                         "yara", "sigma rules", "zeek", "suricata", "nsm", "intrusion detection", "intrusion detection system", "osquery",
                         "sysmon", "threat hunting", "hunting", "case management", "blueteam", "detection rules", "siem", "soar", "xsoar",
                         "persistence hunting", "incident responders"],
    "AppSec & DevSecOps": ["owasp", "appsec", "sast", "dast", "sca", "sbom", "secure coding", "code review", "dependency check",
                           "dependency-check", "zap", "juice shop", "asvs", "samm", "threat modeling", "threat model", "devsecops",
                           "security testing", "cheat sheet series", "secure code"],
    "Cloud & containers": ["terraform", "kubernetes", "k8s", "aws", "azure", "gcp", "google cloud", "iac", "helm", "prisma cloud",
                           "cloudformation", "serverless", "vm series", "openshift"],
    "Network security": ["firewall", "firewalls", "pan os", "panos", "ngfw", "panorama", "globalprotect", "vpn", "pcap", "packet capture",
                         "skillets", "network security"],
    "Threat intelligence": ["stix", "taxii", "misp", "ioc", "iocs", "indicators of compromise", "threat intel", "threat intelligence", "unit42",
                            "unit 42"],
    "Red team & pentesting": ["c2", "post exploitation", "lateral movement", "wordlist", "wordlists", "seclists", "fuzzing", "red team",
                              "redteam", "oscp", "pentest", "pentesting", "penetration testing"],
    "AI security": ["llm security", "ai security", "prompt injection", "agent security", "jailbreak", "jailbreaks", "red teaming llm"],
}
REPO_LOOSE = {
    "Blue team & DFIR": {"elastic", "monitoring", "logs", "logging", "backup", "backups", "defense", "defenders", "hardening", "detecting",
                         "incident", "detection", "defender", "cis controls", "cis 18"},
    "Web security": {"php", "browser", "browsers", "chrome extension", "oauth", "jwt", "graphql", "cookies", "cors", "wordpress", "web app",
                     "web application", "api security", "authentication bypass"},
    "Windows & endpoint": {"microsoft", "chrome", "browser", "browsers", "apple", "macos", "endpoint", "endpoints", "patching", "firefox",
                           "security software"},
}
# when the first topic fits, the second is dropped for repos (forensics tools for Windows are DFIR first)
REPO_OVER = [("Blue team & DFIR", "Windows & endpoint")]
NOT_FOR_REPOS = NOT_FOR_REPOS + ("Computer science & explainers",)


def _repo_patterns(db) -> list[tuple[int, str, re.Pattern]]:
    out = []
    for row in db.execute("SELECT id, name, keywords FROM topics WHERE enabled = 1"):
        if row["name"] in NOT_FOR_REPOS:
            continue
        try:
            words = json.loads(row["keywords"])
        except ValueError:
            continue
        loose = REPO_LOOSE.get(row["name"], set())
        strong = [w for w in dict.fromkeys([*words, *REPO_EXTRA.get(row["name"], [])]) if w.lower() not in loose]
        if strong:
            out.append((row["id"], row["name"], topics._pattern(strong)))
    return out


def classify(db, repo_ids: list[int] | None = None) -> int:
    """File repos (and gists / docs) into the shared topics by their name, description and GitHub tags, with the repo
    tuning above."""
    if repo_ids is not None and not repo_ids:
        return 0
    compiled = _repo_patterns(db)
    names = {tid: name for tid, name, _ in compiled}
    by_name = {name: tid for tid, name, _ in compiled}
    where = f" WHERE id IN ({placeholders(len(repo_ids))})" if repo_ids is not None else ""
    links = 0
    for r in db.execute(f"SELECT id, name, description, gh_topics FROM repos{where}", repo_ids or []).fetchall():  # nosec B608
        try:
            gh = " · ".join(t.replace("-", " ") for t in json.loads(r["gh_topics"] or "[]"))
        except ValueError:
            gh = ""
        text = f"{re.sub(r'[-_.]+', ' ', r['name'])}\n{r['description'] or ''}\n{gh}"
        hit = {tid for tid, _, pattern in compiled if pattern.search(text)}
        for first, second in REPO_OVER:
            if by_name.get(first) in hit:
                hit.discard(by_name.get(second))
        db.execute("DELETE FROM repo_topics WHERE repo_id = ?", (r["id"],))
        db.executemany("INSERT OR IGNORE INTO repo_topics (repo_id, topic_id) VALUES (?, ?)", [(r["id"], t) for t in hit if t in names])
        links += len(hit)
    return links + _owner_fallback(db, repo_ids)


OWNER_MIN_REPOS = 5
OWNER_SHARE = 0.6


def _owner_fallback(db, repo_ids: list[int] | None) -> int:
    """A repo with no topic of its own gets its owner's main topic when the owner clearly specialises (at least 5 repos,
    60% of the owner's tagged repos share it) - e.g. Eric Zimmerman's MFTECmd / RECmd → Blue team & DFIR."""
    where = f" AND r.id IN ({placeholders(len(repo_ids))})" if repo_ids is not None else ""
    bare = db.execute(f"SELECT r.id, r.owner FROM repos r WHERE r.id NOT IN (SELECT repo_id FROM repo_topics){where}", repo_ids or []).fetchall()  # nosec B608
    main: dict[str, int | None] = {}
    added = 0
    for r in bare:
        owner = r["owner"]
        if owner not in main:
            tagged = db.execute("SELECT COUNT(DISTINCT x.repo_id) FROM repo_topics x JOIN repos o ON o.id = x.repo_id WHERE o.owner = ?", (owner,)).fetchone()[0]
            top = db.execute("SELECT x.topic_id, COUNT(*) AS n FROM repo_topics x JOIN repos o ON o.id = x.repo_id WHERE o.owner = ? "
                             "GROUP BY x.topic_id ORDER BY n DESC LIMIT 1", (owner,)).fetchone()
            main[owner] = top["topic_id"] if top and tagged >= OWNER_MIN_REPOS and top["n"] >= OWNER_SHARE * tagged else None
        if main[owner]:
            db.execute("INSERT OR IGNORE INTO repo_topics (repo_id, topic_id) VALUES (?, ?)", (r["id"], main[owner]))
            added += 1
    return added


# ============================================================================ fetching
def _pages(path: str, params: dict[str, Any], token: str | None, pages: int = MAX_PAGES,
           etag: str | None = None) -> tuple[list[Any] | None, str | None]:
    """All pages of a list (100 a page). ``etag`` (only sent for lists that fit one page) → (None, etag) when unchanged."""
    out: list[Any] = []
    first_etag = None
    for page in range(1, pages + 1):
        batch, tag = api_get_cond(path, {**params, "per_page": 100, "page": page}, token, etag if page == 1 else None)
        if page == 1:
            if batch is None:
                return None, tag
            first_etag = tag
        if not isinstance(batch, list):
            break
        out.extend(batch)
        if len(batch) < 100:
            break
    return out, (first_etag if len(out) < 100 else None)


def _profile_info(prof: Any, value: str) -> dict[str, Any]:
    if not isinstance(prof, dict):
        return {}
    login = prof.get("login") if isinstance(prof.get("login"), str) and OWNER.match(prof.get("login")) else value
    return {"login": login, "title": to_text(prof.get("name") if isinstance(prof.get("name"), str) else "", 200) or login,
            "avatar_url": _avatar(prof.get("avatar_url"))}


def fetch_source(kind: str, value: str, token: str | None, etag: str | None = None,
                 skip_profile: bool = False) -> tuple[dict[str, Any], list[dict[str, Any]] | None, str | None]:
    """(source details, cleaned repos or None when unchanged since ``etag``, new etag). Network only - no database.
    ``skip_profile``: an owner whose name and picture are already known isn't looked up again."""
    info: dict[str, Any] = {}
    new_etag = None
    if kind == "owner":
        if not skip_profile:
            info = _profile_info(api_get(f"/users/{quote(value)}", token=token), value)
        raw, new_etag = _pages(f"/users/{quote(value)}/repos", {"type": "owner", "sort": "pushed"}, token, etag=etag)
    elif kind == "stars":
        raw, new_etag = _pages(f"/users/{quote(value)}/starred", {"sort": "created"}, token, etag=etag)
        info = {"title": f"★ {value}'s stars"}
    elif kind == "topic":
        data = api_get("/search/repositories", {"q": f"topic:{value}", "sort": "stars", "order": "desc", "per_page": TOPIC_RESULTS}, token)
        raw = data.get("items", []) if isinstance(data, dict) else []
        total = data.get("total_count") if isinstance(data, dict) else None
        info = {"title": f"# {value}" + (f" (top {min(len(raw), TOPIC_RESULTS)} of {total:,})" if isinstance(total, int) else "")}
    elif kind == "gist":
        one, new_etag = api_get_cond(f"/gists/{quote(value)}", token=token, etag=etag)
        if one is None:
            return {"title": value}, None, new_etag
        item = clean_gist(one, value)
        return {"title": item["name"] if item else value}, ([item] if item else []), new_etag
    elif kind == "doc":
        item = clean_doc(value)
        return {"title": item["name"]}, [item], None
    elif kind == "gitlab":
        proj = gl_get(f"/projects/{quote(value, safe='')}", {"license": "true"})
        item = clean_gitlab(proj, value)
        if item is None:
            raise GitHubError("GitLab's answer for that project couldn't be read.")
        pid = proj.get("id") if isinstance(proj, dict) and isinstance(proj.get("id"), int) else None
        return {"title": item["full_name"], "releases": gitlab_releases(pid, item["url"]) if pid else []}, [item], None
    elif kind == "repo":
        owner, _, name = value.partition("/")
        one, new_etag = api_get_cond(f"/repos/{quote(owner)}/{quote(name)}", token=token, etag=etag)
        raw = None if one is None else [one]
        info = {"title": value}
    else:
        raise GitHubError("Unknown source kind")
    if raw is None:
        return info, None, new_etag
    repos = [c for c in (clean_repo(r) for r in raw) if c]
    if kind == "repo" and repos:
        info["title"] = repos[0]["full_name"]
    return info, repos, new_etag


def fetch_releases(full_name: str) -> list[dict[str, Any]]:
    """Newest releases of one repo from its public release Atom feed (no API budget used)."""
    from app.fetcher import parse_bytes, xml_guard

    owner, _, name = full_name.partition("/")
    if not OWNER.match(owner) or not REPO.match(name):
        return []
    url = f"{WEB}/{quote(owner)}/{quote(name)}/releases.atom"
    try:
        resp = netguard.request("GET", url, headers=_headers(None, "application/atom+xml"), max_bytes=MAX_ATOM_BYTES, timeout=20.0, max_redirects=2)
    except (netguard.FetchError, netguard.UnsafeURLError):
        return []
    if resp.status_code != 200 or xml_guard(resp.content, resp.headers.get("content-type")):
        return []
    parsed = parse_bytes(resp.content, resp.headers.get("content-type"), url)
    prefix = f"{WEB}/{owner}/{name}/releases/tag/".lower()
    out = []
    for e in parsed.entries[:MAX_RELEASES]:
        link = e.get("link") or ""
        if not isinstance(link, str) or not link.lower().startswith(prefix):
            continue
        tag = link[len(prefix):][:200]
        stamp = e.get("updated_parsed") or e.get("published_parsed")
        if not tag or not stamp:
            continue
        summary = ""
        if e.get("content"):
            summary = to_text(e["content"][0].get("value", ""), 600)
        out.append({"tag": tag, "title": to_text(e.get("title", ""), 300) or tag, "url": f"{WEB}/{quote(owner)}/{quote(name)}/releases/tag/{quote(tag, safe='')}",
                    "published_ts": timegm(stamp), "summary": summary})
    return out


def store_releases(db, repo_id: int, releases: list[dict[str, Any]]) -> int:
    new = 0
    for r in releases:
        new += db.execute("INSERT OR IGNORE INTO repo_releases (repo_id, tag, title, url, published_ts, summary, fetched_at) "
                          "VALUES (?, ?, ?, ?, ?, ?, ?)", (repo_id, r["tag"], r["title"], r["url"], r["published_ts"], r["summary"], now())).rowcount
    db.execute("DELETE FROM repo_releases WHERE repo_id = ? AND id NOT IN (SELECT id FROM repo_releases WHERE repo_id = ? "
               "ORDER BY published_ts DESC LIMIT ?)", (repo_id, repo_id, MAX_RELEASES))
    return new


def verify(kind: str, value: str, token: str | None) -> tuple[dict[str, Any], list[dict[str, Any]] | None, str | None]:
    """Check a new source exists before it is saved (one API request; topics aren't checked - search has its own small
    budget). For a repo the answer is complete, so it is stored straight away: (info, [repo], etag); otherwise
    (info, None, None) - for an owner the info has the name and picture, so the first fetch doesn't ask again."""
    if kind == "repo":
        owner, _, name = value.partition("/")
        data, etag = api_get_cond(f"/repos/{quote(owner)}/{quote(name)}", token=token)
        r = clean_repo(data)
        if r is None:
            raise GitHubError("GitHub's answer for that repo couldn't be read.")
        return {"title": r["full_name"]}, [r], etag
    if kind in ("owner", "stars"):
        return _profile_info(api_get(f"/users/{quote(value)}", token=token), value), None, None
    if kind in ("gist", "doc", "gitlab"):
        info, items, etag = fetch_source(kind, value, token)
        return info, items, etag
    return {}, None, None


def not_found_text(kind: str, value: str, note: str | None = None, origin: str | None = None) -> str:
    if kind == "gitlab":
        return f"No public GitLab project {value[:120]}: it doesn't exist, was moved, or is private."
    if kind == "gist":
        return f"No public gist {value[:40]} on GitHub: it was deleted, or the id is wrong."
    if kind == "repo" and note in (SITE_NOTE, POST_NOTE, PROJECT_NOTE):
        return f"{origin or 'That link'} is a website (GitHub Pages), not a repo - and there's no public repo {value} behind it to add."
    if kind == "repo":
        return f"No public repo {value} on GitHub: it doesn't exist, was deleted or renamed, or is private."
    return f"No GitHub user or organisation called {value}."


MISSING_RETRY_SECONDS = 24 * 3600


def refresh_after(kind: str) -> int:
    """Gists rarely change (checked weekly); docs / website links are never downloaded (a yearly no-op)."""
    return {"gist": 7 * 86400, "doc": 365 * 86400}.get(kind, REFRESH_SECONDS)   # a name GitHub says doesn't exist is only looked up again once a day


def refresh_source(source_id: int, prefetched: tuple[dict[str, Any], list[dict[str, Any]], str | None] | None = None) -> dict[str, Any]:
    """Fetch one source now and store what it lists. Raises RateLimited (the caller stops the round).
    ``prefetched`` = an answer already in hand (a repo checked while adding it), so it isn't asked for twice.
    Repeat checks are conditional (ETag): when GitHub says nothing changed, nothing is re-stored."""
    with get_db() as db:
        src = db.execute("SELECT id, kind, value, title, avatar_url, last_fetch, repo_count, etag, origin, note, alt_value "
                         "FROM repo_sources WHERE id = ?", (source_id,)).fetchone()
        if src is None:
            return {"ok": False}
        token = _token(db)
    if prefetched is None and src["kind"] == "repo" and not src["last_fetch"] and link_stored_repo(source_id, src["value"]):
        return {"ok": True, "repos": 1, "linked": True}     # stored by another source in the last 12 h: no request
    single_page = src["kind"] in ("owner", "stars") and src["last_fetch"] and src["repo_count"] < 100
    etag = src["etag"] if src["kind"] == "repo" and src["last_fetch"] or single_page else None
    skip_profile = src["kind"] == "owner" and bool(src["avatar_url"]) and src["title"] not in ("", src["value"])
    try:
        if prefetched is not None:
            info, repos, new_etag = prefetched
        else:
            info, repos, new_etag = fetch_source(src["kind"], src["value"], token, etag=etag, skip_profile=skip_profile)
    except RateLimited as exc:
        with get_db() as db:   # not an error: it simply waits for GitHub's reset
            db.execute("UPDATE repo_sources SET next_fetch = ? WHERE id = ?", (exc.reset + 30, source_id))
        raise
    except NotFound:
        if not src["last_fetch"] and src["alt_value"]:   # a website link: its first guess doesn't exist - try the site's own repo
            with get_db() as db:
                clash = db.execute("SELECT id FROM repo_sources WHERE kind = 'repo' AND value = ? AND id != ?", (src["alt_value"], source_id)).fetchone()
                if clash:
                    db.execute("DELETE FROM repo_sources WHERE id = ?", (source_id,))
                    return {"ok": False, "error": f"{src['alt_value']} is already in your Repos."}
                db.execute("UPDATE repo_sources SET value = ?, title = ?, alt_value = NULL, note = ? WHERE id = ?",
                           (src["alt_value"], src["alt_value"], POST_NOTE, source_id))
            return refresh_source(source_id)
        page = page_url(src["origin"]) if src["kind"] == "repo" and src["note"] in (SITE_NOTE, POST_NOTE, PROJECT_NOTE) else None
        if page:   # no public repo behind that website: keep the page itself as a link
            with get_db() as db:
                clash = db.execute("SELECT id FROM repo_sources WHERE kind = 'doc' AND value = ? AND id != ?", (page, source_id)).fetchone()
                if clash:
                    db.execute("DELETE FROM repo_sources WHERE id = ?", (source_id,))
                    return {"ok": False, "error": "That website is already in your Repos."}
                db.execute("UPDATE repo_sources SET kind = 'doc', value = ?, title = ?, alt_value = NULL, note = ?, etag = NULL WHERE id = ?",
                           (page, page, PAGE_NOTE, source_id))
            return refresh_source(source_id)
        msg = not_found_text(src["kind"], src["value"], src["note"], src["origin"])
        with get_db() as db:
            db.execute("UPDATE repo_sources SET last_fetch = ?, next_fetch = ?, last_error = ? WHERE id = ?",
                       (now(), now() + MISSING_RETRY_SECONDS, msg, source_id))
        return {"ok": False, "error": msg}
    except GitHubError as exc:
        with get_db() as db:
            db.execute("UPDATE repo_sources SET last_fetch = ?, next_fetch = ?, last_error = ? WHERE id = ?",
                       (now(), now() + RETRY_SECONDS, str(exc)[:300], source_id))
        return {"ok": False, "error": str(exc)}
    full = repos[0]["full_name"] if src["kind"] == "repo" and repos else None
    if src["kind"] == "repo" and repos is None:   # unchanged: its stored row is still right
        with get_db() as db:
            row = db.execute("SELECT r.full_name FROM repos r JOIN repo_source_links l ON l.repo_id = r.id WHERE l.source_id = ?", (source_id,)).fetchone()
        full = row["full_name"] if row else None
    releases = fetch_releases(full) if full else []
    with get_db() as db:
        if db.execute("SELECT 1 FROM repo_sources WHERE id = ?", (source_id,)).fetchone() is None:
            return {"ok": False}  # removed while fetching
        if repos is None:   # 304: nothing changed on GitHub
            if src["kind"] == "repo" and full:
                rid = db.execute("SELECT id FROM repos WHERE full_name = ?", (full,)).fetchone()
                if rid:
                    store_releases(db, rid["id"], releases)
            db.execute("UPDATE repo_sources SET last_fetch = ?, next_fetch = ?, last_error = NULL WHERE id = ?",
                       (now(), now() + REFRESH_SECONDS, source_id))
            return {"ok": True, "repos": src["repo_count"], "unchanged": True}
        if src["kind"] in ("repo", "gitlab", "gist", "doc"):   # you asked for this one: it isn't hidden any more
            db.executemany("DELETE FROM repo_hidden WHERE full_name = ?", [(r["full_name"],) for r in repos])
        else:                                                   # lists skip the repos you removed by hand
            hidden = {r[0].lower() for r in db.execute("SELECT full_name FROM repo_hidden")}
            repos = [r for r in repos if r["full_name"].lower() not in hidden]
        ids = [store_repo(db, r) for r in repos]
        db.execute("DELETE FROM repo_source_links WHERE source_id = ?", (source_id,))
        db.executemany("INSERT OR IGNORE INTO repo_source_links (source_id, repo_id) VALUES (?, ?)", [(source_id, i) for i in ids])
        file_into_folder(db, source_id, ids)
        if src["kind"] == "gitlab" and ids:
            store_releases(db, ids[0], info.get("releases") or [])
        if src["kind"] == "repo" and ids:
            store_releases(db, ids[0], releases)
            if full and full != src["value"] and not db.execute(  # GitHub's spelling / a renamed repo's new name
                    "SELECT 1 FROM repo_sources WHERE kind = 'repo' AND value = ? AND id != ?", (full, source_id)).fetchone():
                db.execute("UPDATE repo_sources SET value = ? WHERE id = ?", (full, source_id))
        drop_orphans(db)
        classify(db, ids)
        db.execute("UPDATE repo_sources SET title = COALESCE(NULLIF(?, ''), title), avatar_url = COALESCE(?, avatar_url), "
                   "last_fetch = ?, next_fetch = ?, last_error = NULL, repo_count = ?, etag = ?, alt_value = NULL WHERE id = ?",
                   (info.get("title") or "", info.get("avatar_url"), now(), now() + refresh_after(src["kind"]), len(ids), new_etag, source_id))
    return {"ok": True, "repos": len(ids)}


def link_stored_repo(source_id: int, full_name: str) -> bool:
    """A repo another source already stored in the last 12 hours is linked to a new source without asking GitHub."""
    with get_db() as db:
        row = db.execute("SELECT id, full_name FROM repos WHERE full_name = ? AND updated_at > ?", (full_name, now() - REFRESH_SECONDS)).fetchone()
        if row is None:
            return False
        db.execute("INSERT OR IGNORE INTO repo_source_links (source_id, repo_id) VALUES (?, ?)", (source_id, row["id"]))
        file_into_folder(db, source_id, [row["id"]])
        db.execute("UPDATE repo_sources SET value = ?, title = ?, last_fetch = ?, next_fetch = ?, last_error = NULL, repo_count = 1 WHERE id = ?",
                   (row["full_name"], row["full_name"], now(), now() + REFRESH_SECONDS, source_id))
    releases = fetch_releases(row["full_name"])     # the Atom feed - no API budget
    with get_db() as db:
        store_releases(db, row["id"], releases)
    return True


class RepoSync:
    """Background refresh of due sources, one at a time; stops for the hour when GitHub's limit is spent."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def due(self) -> list[int]:
        with get_db() as db:
            return [r[0] for r in db.execute("SELECT id FROM repo_sources WHERE next_fetch IS NULL OR next_fetch <= ? "
                                             "ORDER BY kind NOT IN ('doc', 'gitlab'), next_fetch IS NOT NULL, next_fetch LIMIT 50", (now(),))]  # links first: no request

    def maybe_start(self) -> bool:
        if not self.due() or not self._lock.acquire(blocking=False):
            return False

        def run() -> None:
            try:
                for _ in range(10):          # newly due sources (e.g. added meanwhile) are picked up too
                    ids = self.due()
                    if not ids:
                        break
                    for sid in ids:
                        refresh_source(sid)
                        time.sleep(1)
            except RateLimited as exc:
                log.info("GitHub rate limit reached; repos continue after %s", time.strftime("%H:%M", time.localtime(exc.reset)))
                with get_db() as db:   # nothing else is tried before the reset
                    db.execute("UPDATE repo_sources SET next_fetch = MAX(COALESCE(next_fetch, 0), ?) WHERE kind NOT IN ('doc', 'gitlab') AND (next_fetch IS NULL OR next_fetch <= ?)",
                               (exc.reset + 30, now()))
            except Exception:  # noqa: BLE001
                log.exception("Repos: background refresh failed")
            finally:
                self._lock.release()

        self.thread = threading.Thread(target=run, name="github-repos", daemon=True)
        self.thread.start()
        return True


repo_sync = RepoSync()
