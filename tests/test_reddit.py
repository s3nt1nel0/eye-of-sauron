"""Reddit fetching: app-wide pacing, 100 posts per fetch, older pages filled gradually, retries spread out."""

import json
from datetime import datetime, timezone
from unittest import mock

import httpx

from app import netguard, reddit


def _resp(body, status=200, url="https://www.reddit.com/", ctype="application/atom+xml"):
    if isinstance(body, (dict, list)):
        body = json.dumps(body).encode()
    return netguard.SafeResponse(status, httpx.Headers({"content-type": ctype}), body, url)


def _atom(ids, base_ts=1794700000):
    entries = "".join(
        f'<entry><id>t3_{i}</id><title>post {i}</title><link href="https://www.reddit.com/r/homelab/comments/{i}/x/"/>'
        f'<updated>{datetime.fromtimestamp(base_ts - n * 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}</updated>'
        f'<content type="html">hi</content></entry>' for n, i in enumerate(ids))
    return f'<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><title>newest submissions : homelab</title>{entries}</feed>'.encode()


def test_reddit_requests_are_paced_app_wide(monkeypatch):
    """Requests to reddit.com (any subdomain) are spaced PACED_HOSTS seconds apart; other sites are not slowed."""
    waits = []
    clock = [1000.0]
    monkeypatch.setattr(netguard.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(netguard.time, "sleep", lambda s: (waits.append(round(s, 1)), clock.__setitem__(0, clock[0] + s)))
    netguard._next_slot.clear()
    for host in ("www.reddit.com", "old.reddit.com", "www.reddit.com", "example.org"):
        netguard._pace(host)
    assert waits == [15.0, 15.0]          # 1st free, 2nd and 3rd wait their turn, example.org untouched
    # a 429 from Reddit: every later Reddit request waits out the cool-down (Retry-After or at least 5 minutes)
    waits.clear()
    netguard._cool_down("www.reddit.com", "60")
    assert netguard.cooling("old.reddit.com") and not netguard.cooling("example.org")
    netguard._pace("www.reddit.com")
    assert waits and waits[0] >= netguard.COOLDOWN_429 - 1
    netguard._next_slot.clear()


def test_older_pages_fill_until_the_end(authed):
    from app.db import get_db, now

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, social_platform) VALUES "
                         "('r/homelab', 'https://www.reddit.com/r/homelab/new/.rss?limit=100', ?, 'reddit')", (now(),)).lastrowid
        db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, 'https://www.reddit.com/r/homelab/new/t3_aaa0', 'p', ?, ?)",
                   (fid, now(), 1794700000))
    page1 = _atom([f"bbb{n:03d}" for n in range(100)], base_ts=1794690000)   # a full page → keep going
    page2 = _atom([f"ccc{n:03d}" for n in range(40)], base_ts=1794300000)    # a short page → the end
    seen = []

    def fake(method, url, **kw):
        seen.append(url)
        return _resp(page1 if "after=t3_aaa0" in url else page2)

    netguard._next_slot.clear()
    with mock.patch("app.netguard.request", side_effect=fake):   # one older page per fetch
        first = reddit.older_pages(fid, "https://www.reddit.com/r/homelab/new/.rss?limit=100", None)
        second = reddit.older_pages(fid, "https://www.reddit.com/r/homelab/new/.rss?limit=100", None)
    assert seen == ["https://www.reddit.com/r/homelab/new/.rss?limit=100&after=t3_aaa0",
                    "https://www.reddit.com/r/homelab/new/.rss?limit=100&after=t3_bbb099"]
    assert (first, second) == (100, 40)
    with mock.patch("app.netguard.request") as net:        # finished: nothing more is asked
        assert reddit.older_pages(fid, "https://www.reddit.com/r/homelab/new/.rss?limit=100", None) == 0
        assert not net.called
    assert reddit.older_pages(fid, "https://evil.example/r/x/new/.rss", None) == 0   # only real subreddit feeds


def test_older_pages_stop_at_retention_and_wait_on_429(authed):
    from app.db import get_db, now

    with get_db() as db:
        fid = db.execute("INSERT INTO feeds (title, url, created_at, social_platform) VALUES "
                         "('r/x', 'https://www.reddit.com/r/selfhosted/new/.rss?limit=100', ?, 'reddit')", (now(),)).lastrowid
        db.execute("INSERT INTO articles (feed_id, guid, title, fetched_at, sort_ts) VALUES (?, 't3_zzz1', 'p', ?, ?)", (fid, now(), now()))
    with mock.patch("app.netguard.request", return_value=_resp(b"", status=429)):
        assert reddit.older_pages(fid, "https://www.reddit.com/r/selfhosted/new/.rss?limit=100", None) == 0
    with get_db() as db:   # a rate limit is not "done": the next fetch tries again
        assert db.execute("SELECT 1 FROM sync_state WHERE key = ?", (f"reddit_history_done:{fid}",)).fetchone() is None
    old = _atom([f"old{n:03d}" for n in range(100)], base_ts=now() - 400 * 86400)
    with mock.patch("app.netguard.request", return_value=_resp(old)):
        reddit.older_pages(fid, "https://www.reddit.com/r/selfhosted/new/.rss?limit=100", now() - 365 * 86400)
    with get_db() as db:   # older than the retention: stored nothing, and done for good
        assert db.execute("SELECT COUNT(*) FROM articles WHERE feed_id = ?", (fid,)).fetchone()[0] == 1
        assert db.execute("SELECT 1 FROM sync_state WHERE key = ?", (f"reddit_history_done:{fid}",)).fetchone()


def test_rate_limited_retries_are_spread(authed):
    from app import fetcher
    from app.db import get_db, now

    with get_db() as db:
        ids = [db.execute("INSERT INTO feeds (title, url, created_at) VALUES (?, ?, ?)", (f"r{n}", f"https://www.reddit.com/r/s{n}/new/.rss", now())).lastrowid
               for n in range(8)]
    for fid in ids:
        fetcher._rate_limited(fid, 30, None)
    with get_db() as db:
        nexts = [db.execute("SELECT next_fetch FROM feeds WHERE id = ?", (fid,)).fetchone()[0] for fid in ids]
    assert min(nexts) >= now() + 15 * 60 - 5 and len(set(nexts)) > 1      # at least 15 min, and not all at once
