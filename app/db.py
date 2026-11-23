"""SQLite storage layer.

* Every query in the code base uses bound parameters - never string formatting
  of user input into SQL.
* One short-lived connection per unit of work (thread-safe, WAL mode).
"""

from __future__ import annotations

import logging
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA_VERSION = 9

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          INTEGER PRIMARY KEY,
    token_hash  TEXT NOT NULL UNIQUE,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    prefix      TEXT NOT NULL,
    scopes      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    last_used   INTEGER,
    expires_at  INTEGER
);

CREATE TABLE IF NOT EXISTS folders (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    position  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS feeds (
    id              INTEGER PRIMARY KEY,
    folder_id       INTEGER REFERENCES folders(id) ON DELETE SET NULL,
    title           TEXT NOT NULL DEFAULT '',
    custom_title    INTEGER NOT NULL DEFAULT 0,
    url             TEXT NOT NULL UNIQUE,
    site_url        TEXT,
    refresh_minutes INTEGER,
    retention_days  INTEGER,                    -- NULL = global setting, 0 = keep forever
    max_articles    INTEGER,                    -- NULL = global setting, 0 = unlimited
    kind            TEXT NOT NULL DEFAULT 'rss', -- rss | html | json (scraping) | youtube | hfpapers | x | telegram
    scrape          TEXT,                       -- JSON scraping rules for kind html/json (validated by the API)
    source          TEXT,                       -- JSON source config for youtube/hfpapers/x/telegram (validated)
    enabled         INTEGER NOT NULL DEFAULT 1,
    etag            TEXT,
    last_modified   TEXT,
    last_fetched    INTEGER,
    next_fetch      INTEGER,
    error_count     INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    created_at      INTEGER NOT NULL,
    social_platform TEXT,                       -- v9: set for social accounts (Accounts tab): bluesky, mastodon, ...
    full_text       TEXT                        -- v9: fetch the full article page: NULL/'auto' (short items), 'always', 'never'
);
CREATE INDEX IF NOT EXISTS idx_feeds_next ON feeds(enabled, next_fetch);

CREATE TABLE IF NOT EXISTS articles (
    id            INTEGER PRIMARY KEY,
    feed_id       INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    guid          TEXT NOT NULL,
    url           TEXT,
    title         TEXT NOT NULL DEFAULT '',
    author        TEXT,
    content_html  TEXT NOT NULL DEFAULT '',
    text_content  TEXT NOT NULL DEFAULT '',
    published     INTEGER,
    fetched_at    INTEGER NOT NULL,
    sort_ts       INTEGER NOT NULL,
    is_read       INTEGER NOT NULL DEFAULT 0,
    is_starred    INTEGER NOT NULL DEFAULT 0,
    starred_at    INTEGER,
    fulltext      INTEGER,                    -- v9: full article fetched from the page: NULL not tried, 1 done, -1 failed
    UNIQUE(feed_id, guid)
);
CREATE INDEX IF NOT EXISTS idx_articles_sort ON articles(sort_ts);
CREATE INDEX IF NOT EXISTS idx_articles_feed_sort ON articles(feed_id, sort_ts);
CREATE INDEX IF NOT EXISTS idx_articles_unread ON articles(is_read, sort_ts);
CREATE INDEX IF NOT EXISTS idx_articles_starred ON articles(is_starred, sort_ts);
CREATE INDEX IF NOT EXISTS idx_articles_feed_url ON articles(feed_id, url);
CREATE INDEX IF NOT EXISTS idx_articles_url ON articles(url);

-- Remembers GUIDs of articles removed by retention so they are not re-imported.
CREATE TABLE IF NOT EXISTS article_tombstones (
    feed_id    INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    guid       TEXT NOT NULL,
    removed_at INTEGER NOT NULL,
    manual     INTEGER NOT NULL DEFAULT 0,     -- v9: 1 = you removed it (kept for good, never re-added by back-fills)
    PRIMARY KEY (feed_id, guid)
);

CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
    title, text_content,
    content='articles', content_rowid='id',
    tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS articles_ai AFTER INSERT ON articles BEGIN
    INSERT INTO articles_fts(rowid, title, text_content) VALUES (new.id, new.title, new.text_content);
END;
CREATE TRIGGER IF NOT EXISTS articles_ad AFTER DELETE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, text_content)
    VALUES ('delete', old.id, old.title, old.text_content);
END;
CREATE TRIGGER IF NOT EXISTS articles_au AFTER UPDATE OF title, text_content ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, text_content)
    VALUES ('delete', old.id, old.title, old.text_content);
    INSERT INTO articles_fts(rowid, title, text_content) VALUES (new.id, new.title, new.text_content);
END;

-- "Collections": user categories for articles (Ransomware, Advisories, APT ...).
CREATE TABLE IF NOT EXISTS tags (
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL UNIQUE COLLATE NOCASE,
    color  TEXT NOT NULL DEFAULT '#6b7280'
);

CREATE TABLE IF NOT EXISTS article_tags (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    tag_id     INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    source     TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'rule')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (article_id, tag_id)
);
CREATE INDEX IF NOT EXISTS idx_article_tags_tag ON article_tags(tag_id);

CREATE TABLE IF NOT EXISTS webhooks (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    url         TEXT NOT NULL,
    secret      TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    last_status INTEGER,
    last_error  TEXT,
    last_sent   INTEGER
);

CREATE TABLE IF NOT EXISTS rules (
    id               INTEGER PRIMARY KEY,
    name             TEXT NOT NULL,
    keywords         TEXT NOT NULL,          -- JSON array of literal strings (any of them; may be [] for a scoped rule)
    exclude_keywords TEXT NOT NULL DEFAULT '[]',
    require_keywords TEXT NOT NULL DEFAULT '[]', -- v9: AND at least one of these too
    cve_severity     TEXT,                   -- v9: article must mention a CVE with this severity
    cve_owasp        TEXT,                   -- v9: ... or a CVE whose CWE maps to this OWASP category ('2025:A01')
    cve_category     TEXT,                   -- ... or a CVE in this CVE-tracking category slug ('rce', 'kev', ...)
    keywords_in_title INTEGER NOT NULL DEFAULT 0, -- v9: the main keywords must be in the title (other lists: match_in)
    match_in         TEXT NOT NULL DEFAULT 'title_content' CHECK (match_in IN ('title', 'title_content')),
    feed_id          INTEGER REFERENCES feeds(id) ON DELETE CASCADE,
    folder_id        INTEGER REFERENCES folders(id) ON DELETE CASCADE,
    tag_id           INTEGER REFERENCES tags(id) ON DELETE SET NULL,
    webhook_id       INTEGER REFERENCES webhooks(id) ON DELETE SET NULL,
    star             INTEGER NOT NULL DEFAULT 0,
    mark_read        INTEGER NOT NULL DEFAULT 0,
    ai_summarize     INTEGER NOT NULL DEFAULT 0,  -- v8: summarise matching new articles with the AI provider
    alert_channel_id INTEGER REFERENCES delivery_channels(id) ON DELETE SET NULL,  -- v8: instant alert
    enabled          INTEGER NOT NULL DEFAULT 1,
    position         INTEGER NOT NULL DEFAULT 0
);

-- Watchlists: named dictionaries of entities (threat actors, ransomware groups,
-- countries, sectors, vendors, AI-threat topics, or anything user-defined).
CREATE TABLE IF NOT EXISTS watchlists (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    slug        TEXT UNIQUE,                 -- set for built-in lists (templates refer to these)
    description TEXT NOT NULL DEFAULT '',
    position    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS entities (
    id           INTEGER PRIMARY KEY,
    watchlist_id INTEGER NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    aliases      TEXT NOT NULL DEFAULT '[]', -- JSON array of literal strings
    UNIQUE (watchlist_id, name)
);

-- Pre-computed mention index: which articles mention which entities.
CREATE TABLE IF NOT EXISTS article_entities (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    entity_id  INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    PRIMARY KEY (article_id, entity_id)
);
CREATE INDEX IF NOT EXISTS idx_article_entities_entity ON article_entities(entity_id, article_id);

-- "Not this one": a mention you rejected for one article (the indexer never re-adds it).
CREATE TABLE IF NOT EXISTS entity_rejections (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    entity_id  INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (article_id, entity_id)
);

-- Ad clean-up: how many articles of a feed carry a block (sig = hash of its text; sig '*' = articles counted)
CREATE TABLE IF NOT EXISTS feed_blocks (
    feed_id   INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    sig       TEXT NOT NULL,
    n         INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    PRIMARY KEY (feed_id, sig)
) WITHOUT ROWID;

-- 🔭 Observatory: cached public threat data for the dashboards (NVD totals, ransomware claims, DShield, Spamhaus)
CREATE TABLE IF NOT EXISTS observatory_cache (
    key        TEXT PRIMARY KEY,
    data       TEXT NOT NULL,
    fetched_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS dashboards (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    position   INTEGER NOT NULL DEFAULT 0,
    widgets    TEXT NOT NULL DEFAULT '[]',   -- JSON, validated by the API on write
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);



-- Accounts tab: who wrote a single saved post and what it shows (read from the platform's public / official endpoint)
CREATE TABLE IF NOT EXISTS social_post_meta (
    article_id   INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    handle       TEXT,                        -- "@karpathy", "in/jane-doe", "u/someone" (display only)
    profile_url  TEXT,                        -- the author's profile on the same platform (the Follow button)
    avatar_url   TEXT,
    image_url    TEXT,                        -- the post's picture / video thumbnail
    source       TEXT NOT NULL DEFAULT '',    -- where the text came from: oembed, api, jsonld, og, bridge, public, pasted, unavailable
    truncated    INTEGER NOT NULL DEFAULT 0,  -- 1 = the platform only handed over the start of the text
    fetched_at   INTEGER NOT NULL
);

-- CVE tracking: records from the NVD CVE API 2.0, enriched with CISA KEV and MITRE CWE.
CREATE TABLE IF NOT EXISTS cves (
    id             TEXT PRIMARY KEY,            -- CVE-YYYY-NNNN
    published      INTEGER,
    last_modified  INTEGER,
    status         TEXT NOT NULL DEFAULT '',    -- NVD vulnStatus (Rejected records are hidden by default)
    description    TEXT NOT NULL DEFAULT '',
    score          REAL,                        -- CVSS base score of the preferred metric
    cvss_version   TEXT,
    severity       TEXT NOT NULL DEFAULT 'UNSCORED',
    vector         TEXT,
    kev            INTEGER NOT NULL DEFAULT 0,  -- in CISA Known Exploited Vulnerabilities
    kev_added      INTEGER,
    kev_due        INTEGER,
    kev_ransomware INTEGER NOT NULL DEFAULT 0,
    kev_name       TEXT,
    exploitation   TEXT,                        -- SSVC exploitation: none | poc | active
    refs           TEXT NOT NULL DEFAULT '[]',
    source         TEXT NOT NULL DEFAULT 'nvd',
    fetched_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published);
CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(last_modified);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity, published);
CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(kev, kev_added);

CREATE TABLE IF NOT EXISTS cve_cwes (
    cve_id TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    cwe_id INTEGER NOT NULL,
    PRIMARY KEY (cve_id, cwe_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_cwes_cwe ON cve_cwes(cwe_id);

CREATE TABLE IF NOT EXISTS cve_products (
    cve_id        TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    vendor_key    TEXT NOT NULL,               -- normalised: lowercase alphanumerics only
    product_key   TEXT NOT NULL,
    vendor_label  TEXT NOT NULL,
    product_label TEXT NOT NULL,
    PRIMARY KEY (cve_id, vendor_key, product_key)
);
CREATE INDEX IF NOT EXISTS idx_cve_products_vendor ON cve_products(vendor_key);

-- Classification categories (edge devices, RCE, AI/ML, ...): built-in seeds, user-editable.
CREATE TABLE IF NOT EXISTS cve_categories (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    builtin     INTEGER NOT NULL DEFAULT 0,
    enabled     INTEGER NOT NULL DEFAULT 1,
    cwe_ids     TEXT NOT NULL DEFAULT '[]',
    keywords    TEXT NOT NULL DEFAULT '[]',
    products    TEXT NOT NULL DEFAULT '[]',
    position    INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cve_category_map (
    cve_id      TEXT NOT NULL REFERENCES cves(id) ON DELETE CASCADE,
    category_id INTEGER NOT NULL REFERENCES cve_categories(id) ON DELETE CASCADE,
    PRIMARY KEY (cve_id, category_id)
);
CREATE INDEX IF NOT EXISTS idx_cve_category_map_cat ON cve_category_map(category_id, cve_id);

-- MITRE CWE catalog (names) and OWASP Top Ten mappings derived from it.
CREATE TABLE IF NOT EXISTS cwe_entries (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'weakness'
);
CREATE TABLE IF NOT EXISTS cwe_owasp (
    cwe_id  INTEGER NOT NULL,
    edition TEXT NOT NULL,                     -- '2021' | '2025'
    code    TEXT NOT NULL,                     -- 'A01'
    name    TEXT NOT NULL,
    PRIMARY KEY (cwe_id, edition)
);

CREATE VIRTUAL TABLE IF NOT EXISTS cves_fts USING fts5(
    id, description, content='cves', content_rowid='rowid', tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS cves_ai AFTER INSERT ON cves BEGIN
    INSERT INTO cves_fts(rowid, id, description) VALUES (new.rowid, new.id, new.description);
END;
CREATE TRIGGER IF NOT EXISTS cves_ad AFTER DELETE ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, id, description) VALUES ('delete', old.rowid, old.id, old.description);
END;
CREATE TRIGGER IF NOT EXISTS cves_au AFTER UPDATE OF description ON cves BEGIN
    INSERT INTO cves_fts(cves_fts, rowid, id, description) VALUES ('delete', old.rowid, old.id, old.description);
    INSERT INTO cves_fts(rowid, id, description) VALUES (new.rowid, new.id, new.description);
END;

-- App passwords for native RSS apps (Google Reader API). argon2id hashes only.
CREATE TABLE IF NOT EXISTS reader_apps (
    id            INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used     INTEGER
);

-- Third-party integrations (YouTube Data API, X API / bridge, Telegram account). `secret` is a
-- secretbox-encrypted JSON object and is never returned by the API.
CREATE TABLE IF NOT EXISTS integrations (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    config      TEXT NOT NULL DEFAULT '{}',
    secret      TEXT,
    updated_at  INTEGER NOT NULL
);

-- YouTube library: one row per video article.
CREATE TABLE IF NOT EXISTS videos (
    article_id    INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    video_id      TEXT NOT NULL,
    channel_id    TEXT,
    channel_title TEXT,
    thumbnail     TEXT,
    duration_s    INTEGER,
    views         INTEGER,
    published     INTEGER
);
-- videos.video_id is UNIQUE (idx_videos_video_unique, made by the migration once old duplicates are merged):
-- one stored copy per video. A video that is also in other followed playlists / channels is linked to them here
-- instead of being copied; `position` = its place in a playlist (from YouTube), for the playlist's own order.
CREATE TABLE IF NOT EXISTS video_links (
    feed_id    INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    position   INTEGER,
    added_at   INTEGER NOT NULL,
    PRIMARY KEY (feed_id, article_id)
);
CREATE INDEX IF NOT EXISTS idx_video_links_article ON video_links(article_id);
-- Unfollowing a playlist or channel deletes its videos - except those still in another followed feed: they move there.
CREATE TRIGGER IF NOT EXISTS feeds_keep_linked_videos BEFORE DELETE ON feeds BEGIN
    UPDATE OR IGNORE articles SET feed_id = (SELECT l.feed_id FROM video_links l WHERE l.article_id = articles.id
                                             AND l.feed_id != OLD.id ORDER BY l.added_at, l.feed_id LIMIT 1)
    WHERE feed_id = OLD.id AND EXISTS (SELECT 1 FROM video_links l WHERE l.article_id = articles.id AND l.feed_id != OLD.id);
END;

-- Keyword topics across all sources (YouTube library now, topic hub later).
CREATE TABLE IF NOT EXISTS topics (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    keywords  TEXT NOT NULL,                 -- JSON list
    color     TEXT NOT NULL DEFAULT '#64748b',
    builtin   INTEGER NOT NULL DEFAULT 0,
    enabled   INTEGER NOT NULL DEFAULT 1
);
-- v9: your own video groups / series (playlists need no table: they are their own feeds)
CREATE TABLE IF NOT EXISTS video_groups (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS video_group_items (
    group_id   INTEGER NOT NULL REFERENCES video_groups(id) ON DELETE CASCADE,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    position   INTEGER NOT NULL DEFAULT 0,
    added_at   INTEGER NOT NULL,
    PRIMARY KEY (group_id, article_id)
);
CREATE INDEX IF NOT EXISTS idx_video_group_items_article ON video_group_items(article_id);
-- A playlist moved into one of your groups: shown inside the group instead of on the main page (one group each).
CREATE TABLE IF NOT EXISTS video_group_playlists (
    feed_id  INTEGER PRIMARY KEY REFERENCES feeds(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES video_groups(id) ON DELETE CASCADE,
    added_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_video_group_playlists_group ON video_group_playlists(group_id);
-- The order you dragged playlists ("p:<feed>") and groups ("g:<id>") into. Unlisted ones follow, oldest first.
CREATE TABLE IF NOT EXISTS video_group_order (
    ref      TEXT PRIMARY KEY,
    position INTEGER NOT NULL
);


-- Channel groups (Videos → Channels ▾): your own sets of channels, e.g. "Podcasts"
CREATE TABLE IF NOT EXISTS channel_groups (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at INTEGER NOT NULL
);
-- 📺 Favourite topics (★ in Videos → Topics ▾): a filter shows videos from any of them
CREATE TABLE IF NOT EXISTS favorite_topics (
    topic_id   INTEGER PRIMARY KEY REFERENCES topics(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL
);

-- 📺 Favourite channels (★ in Videos): a filter shows only their videos
CREATE TABLE IF NOT EXISTS favorite_channels (
    channel_key TEXT PRIMARY KEY,          -- "UC…" channel id, or "feed:<id>" for a feed without one
    created_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS channel_group_members (
    group_id    INTEGER NOT NULL REFERENCES channel_groups(id) ON DELETE CASCADE,
    channel_key TEXT NOT NULL,             -- "UC…" channel id, or "feed:<id>" for a feed without one
    PRIMARY KEY (group_id, channel_key)
);

-- 🎙 Podcast episodes: the audio file of a feed entry (podcast feeds have kind = 'podcast')
CREATE TABLE IF NOT EXISTS episodes (
    article_id INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    audio_url  TEXT NOT NULL,
    audio_type TEXT,
    duration_s INTEGER,
    image      TEXT
);

-- 🎙 → ▶ A show's YouTube channel(s) / playlist(s), their videos, and each episode's own video
CREATE TABLE IF NOT EXISTS podcast_youtube (
    feed_id     INTEGER PRIMARY KEY REFERENCES feeds(id) ON DELETE CASCADE,
    sources     TEXT NOT NULL DEFAULT '[]',   -- JSON [{"kind": "channel"|"playlist", "id", "title"}]
    how         TEXT NOT NULL,                -- site | feed | videos | search | manual | none
    detected_at INTEGER NOT NULL,
    listed_at   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS podcast_youtube_videos (
    feed_id   INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,
    video_id  TEXT NOT NULL,
    title     TEXT NOT NULL,
    published INTEGER,
    PRIMARY KEY (feed_id, video_id)
);
CREATE TABLE IF NOT EXISTS episode_youtube (
    article_id INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    video_id   TEXT NOT NULL,
    how        TEXT                            -- title | number | words
);

-- A show's own categories for its episodes (e.g. darknetdiaries.com/categories)
CREATE TABLE IF NOT EXISTS episode_categories (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    category   TEXT NOT NULL,
    PRIMARY KEY (article_id, category)
);

CREATE TABLE IF NOT EXISTS article_topics (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    topic_id   INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    source     TEXT NOT NULL DEFAULT 'keyword',  -- keyword | channel (the channel's main topic) | general
    PRIMARY KEY (article_id, topic_id)
);
CREATE INDEX IF NOT EXISTS idx_article_topics_topic ON article_topics(topic_id, article_id);

-- ---- Stage 3: AI summaries, delivery channels, digests and alerts ------------------------
-- AI output is stored as plain text and always rendered as text (never as HTML).
CREATE TABLE IF NOT EXISTS article_summaries (
    article_id  INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    summary     TEXT NOT NULL,
    provider    TEXT NOT NULL,
    model       TEXT NOT NULL,
    tokens_in   INTEGER,
    tokens_out  INTEGER,
    created_at  INTEGER NOT NULL
);

-- Daily AI request/token counters (budget enforcement). day = YYYY-MM-DD (UTC).
CREATE TABLE IF NOT EXISTS ai_usage (
    day         TEXT PRIMARY KEY,
    requests    INTEGER NOT NULL DEFAULT 0,
    tokens_in   INTEGER NOT NULL DEFAULT 0,
    tokens_out  INTEGER NOT NULL DEFAULT 0,
    failures    INTEGER NOT NULL DEFAULT 0
);

-- Where digests and alerts are sent: email | telegram | ntfy | discord | slack | webhook.
-- `credentials` is secretbox-encrypted JSON (SMTP password, bot token, webhook URLs) and never returned.
CREATE TABLE IF NOT EXISTS delivery_channels (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL,
    config      TEXT NOT NULL DEFAULT '{}',
    credentials TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    last_sent   INTEGER,
    last_error  TEXT
);

-- Scheduled digests: what to include (scope JSON), when (local time + weekdays + timezone), where.
CREATE TABLE IF NOT EXISTS digests (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config      TEXT NOT NULL,             -- validated JSON (see app/digests.py DigestConfig)
    last_run    INTEGER,
    next_run    INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS digest_runs (
    id          INTEGER PRIMARY KEY,
    digest_id   INTEGER NOT NULL REFERENCES digests(id) ON DELETE CASCADE,
    created_at  INTEGER NOT NULL,
    status      TEXT NOT NULL,             -- ok | partial | failed | preview
    item_count  INTEGER NOT NULL DEFAULT 0,
    cve_count   INTEGER NOT NULL DEFAULT 0,
    subject     TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL DEFAULT '',  -- plain text
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_digest_runs ON digest_runs(digest_id, created_at);

-- CVE alert rules (new high-severity / KEV / category / vendor matches) and a dedupe log.
CREATE TABLE IF NOT EXISTS alert_rules (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    config      TEXT NOT NULL,             -- validated JSON (see app/alerts.py CveAlertConfig)
    created_at  INTEGER NOT NULL,
    last_fired  INTEGER
);
CREATE TABLE IF NOT EXISTS alerts_sent (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,             -- 'cve_rule' | 'article_rule'
    rule_id     INTEGER NOT NULL,
    item_key    TEXT NOT NULL,             -- e.g. CVE id or article id
    title       TEXT NOT NULL DEFAULT '',
    sent_at     INTEGER NOT NULL,
    status      TEXT NOT NULL DEFAULT 'sent',
    error       TEXT,
    UNIQUE (source, rule_id, item_key)
);
CREATE INDEX IF NOT EXISTS idx_alerts_sent_at ON alerts_sent(sent_at);

-- MITRE ATT&CK (synced from MITRE's STIX data by app/attack_sync.py; replaced on every sync).
CREATE TABLE IF NOT EXISTS attack_groups (
    id          TEXT PRIMARY KEY,               -- G0007
    name        TEXT NOT NULL,
    aliases     TEXT NOT NULL DEFAULT '[]',     -- JSON array
    description TEXT NOT NULL DEFAULT '',
    domains     TEXT NOT NULL DEFAULT '[]',     -- enterprise-attack / ics-attack / mobile-attack
    url         TEXT NOT NULL DEFAULT '',
    created     TEXT,
    modified    TEXT
);
CREATE TABLE IF NOT EXISTS attack_techniques (
    id             TEXT PRIMARY KEY,            -- T1566 / T1566.001 / T0803
    name           TEXT NOT NULL,
    tactics        TEXT NOT NULL DEFAULT '[]',  -- JSON array of tactic names
    domain         TEXT NOT NULL,
    is_subtechnique INTEGER NOT NULL DEFAULT 0,
    url            TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    modified       TEXT
);
CREATE TABLE IF NOT EXISTS attack_group_techniques (
    group_id     TEXT NOT NULL REFERENCES attack_groups(id) ON DELETE CASCADE,
    technique_id TEXT NOT NULL REFERENCES attack_techniques(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, technique_id)
);
CREATE INDEX IF NOT EXISTS idx_agt_technique ON attack_group_techniques(technique_id);

-- The tactics of MITRE's matrices, in matrix order (ATT&CK domains and 'atlas'); written by the syncs.
CREATE TABLE IF NOT EXISTS attack_tactics (
    id       TEXT PRIMARY KEY,            -- TA0001 / AML.TA0002
    name     TEXT NOT NULL,
    domain   TEXT NOT NULL,
    position INTEGER NOT NULL DEFAULT 0,
    url      TEXT NOT NULL DEFAULT ''
);
-- Which technique / sub-technique / tactic entity files an article into which tactic collection (app/ttp_filing.py).
CREATE TABLE IF NOT EXISTS ttp_entity_tags (
    entity_id INTEGER NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    tag_id    INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (entity_id, tag_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_ttp_entity_tags_tag ON ttp_entity_tags(tag_id);
-- Reports & guidance (app/reports.py): items that are an advisory, guidance or report from a government agency / CERT
-- or a security vendor's research team.
CREATE TABLE IF NOT EXISTS publications (
    article_id INTEGER PRIMARY KEY REFERENCES articles(id) ON DELETE CASCADE,
    publisher  TEXT NOT NULL,
    kind       TEXT NOT NULL,              -- government | vendor
    doc_type   TEXT NOT NULL,              -- advisory | guidance | report
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_publications_kind ON publications(kind, doc_type);
-- Threat actor catalogue (app/threat_actors.py): which entity is which catalogue actor, plus what the catalogue says about it.
CREATE TABLE IF NOT EXISTS threat_actor_meta (
    entity_id INTEGER PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
    key       TEXT NOT NULL UNIQUE,
    country   TEXT NOT NULL DEFAULT '',
    kind      TEXT NOT NULL DEFAULT '',
    sources   TEXT NOT NULL DEFAULT '[]',
    names     TEXT NOT NULL DEFAULT '[]',   -- every name the sources give it (display / search; not all are matched)
    attack_id TEXT                          -- its MITRE ATT&CK group ID (G0065), when it is one
);
-- A tactic collection you took an article out of by hand: the technique filing never puts it back.
CREATE TABLE IF NOT EXISTS ttp_tag_removed (
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    tag_id     INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (article_id, tag_id)
) WITHOUT ROWID;

-- Internal key/value state for background jobs (not user settings).
CREATE TABLE IF NOT EXISTS sync_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- each feed's site icon (favicon), fetched once and served from our own origin
CREATE TABLE IF NOT EXISTS feed_icons (
    feed_id    INTEGER PRIMARY KEY REFERENCES feeds(id) ON DELETE CASCADE,
    mime       TEXT,
    data       BLOB,                 -- NULL = looked, found nothing usable (retried after a month)
    fetched_at INTEGER NOT NULL
);

-- 📦 Repos tab: GitHub sources you follow (an owner's repos, one repo, a GitHub topic, a user's stars) and the repos they list
CREATE TABLE IF NOT EXISTS repo_sources (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('owner', 'repo', 'topic', 'stars', 'gist', 'doc', 'gitlab')),
    value       TEXT NOT NULL COLLATE NOCASE,  -- login, owner/name, topic, login, gist id or a normalised doc / website URL
    title       TEXT NOT NULL DEFAULT '',
    avatar_url  TEXT,
    created_at  INTEGER NOT NULL,
    last_fetch  INTEGER,
    next_fetch  INTEGER,
    last_error  TEXT,
    repo_count  INTEGER NOT NULL DEFAULT 0,
    etag        TEXT,                          -- GitHub's ETag of the last answer (conditional refreshes)
    origin      TEXT,                          -- the line you pasted (shown as text)
    note        TEXT,                          -- how a link was mapped, e.g. "the website's source repo"
    alt_value   TEXT,                          -- a second repo to try when a website link's first guess doesn't exist
    folder_id   INTEGER,                       -- 📁 file what this source brings in on its first fetch (then cleared)
    UNIQUE (kind, value)
);
CREATE TABLE IF NOT EXISTS repos (
    id           INTEGER PRIMARY KEY,
    gh_id        INTEGER UNIQUE,
    full_name    TEXT NOT NULL UNIQUE COLLATE NOCASE,
    owner        TEXT NOT NULL COLLATE NOCASE,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    language     TEXT,
    stars        INTEGER NOT NULL DEFAULT 0,
    forks        INTEGER NOT NULL DEFAULT 0,
    open_issues  INTEGER NOT NULL DEFAULT 0,
    gh_topics    TEXT NOT NULL DEFAULT '[]',   -- JSON list of GitHub's own topic tags
    license      TEXT,
    homepage     TEXT,                         -- http(s) only
    archived     INTEGER NOT NULL DEFAULT 0,
    is_fork      INTEGER NOT NULL DEFAULT 0,
    owner_avatar TEXT,                         -- https://avatars.githubusercontent.com/... only
    created_ts   INTEGER,                      -- created on GitHub
    pushed_ts    INTEGER,                      -- last push on GitHub
    added_at     INTEGER NOT NULL,             -- first seen here
    updated_at   INTEGER NOT NULL,
    starred      INTEGER NOT NULL DEFAULT 0,   -- your ★ here (kept even when no source lists it any more)
    kind         TEXT NOT NULL DEFAULT 'repo', -- repo | gist | doc (a GitHub Docs page or a website with no public repo)
    url          TEXT                          -- gists / docs: their own address (repos: built from full_name)
);
CREATE INDEX IF NOT EXISTS idx_repos_owner ON repos(owner);
CREATE INDEX IF NOT EXISTS idx_repos_pushed ON repos(pushed_ts);
CREATE TABLE IF NOT EXISTS repo_source_links (
    source_id INTEGER NOT NULL REFERENCES repo_sources(id) ON DELETE CASCADE,
    repo_id   INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    PRIMARY KEY (source_id, repo_id)
);
CREATE INDEX IF NOT EXISTS idx_repo_source_links_repo ON repo_source_links(repo_id);
CREATE TABLE IF NOT EXISTS repo_topics (
    repo_id  INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    topic_id INTEGER NOT NULL REFERENCES topics(id) ON DELETE CASCADE,
    PRIMARY KEY (repo_id, topic_id)
);
CREATE INDEX IF NOT EXISTS idx_repo_topics_topic ON repo_topics(topic_id, repo_id);
CREATE TABLE IF NOT EXISTS repo_releases (
    id           INTEGER PRIMARY KEY,
    repo_id      INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    tag          TEXT NOT NULL,
    title        TEXT NOT NULL DEFAULT '',
    url          TEXT NOT NULL,                -- built from validated names
    published_ts INTEGER NOT NULL,
    summary      TEXT NOT NULL DEFAULT '',
    fetched_at   INTEGER NOT NULL,
    UNIQUE (repo_id, tag)
);
CREATE INDEX IF NOT EXISTS idx_repo_releases_time ON repo_releases(published_ts);
-- repos you removed by hand: a list source (owner / topic / stars) doesn't bring them back; pasting one again un-hides it
CREATE TABLE IF NOT EXISTS repo_hidden (
    full_name TEXT PRIMARY KEY COLLATE NOCASE,
    hidden_at INTEGER NOT NULL
);
-- 📁 your own repo folders (a repo can be in several); separate from GitHub sources: a repo in a folder is kept
-- even when the source that brought it in is removed
CREATE TABLE IF NOT EXISTS repo_folders (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    emoji      TEXT NOT NULL DEFAULT '📁',
    color      TEXT NOT NULL DEFAULT '#64748b',
    position   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS repo_folder_items (
    folder_id INTEGER NOT NULL REFERENCES repo_folders(id) ON DELETE CASCADE,
    repo_id   INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
    added_at  INTEGER NOT NULL,
    PRIMARY KEY (folder_id, repo_id)
);
CREATE INDEX IF NOT EXISTS idx_repo_folder_items_repo ON repo_folder_items(repo_id);
-- 🔗 Resources: websites, training, labs, cheat sheets, tools, docs you keep; sorted into your categories (never fetched)
CREATE TABLE IF NOT EXISTS resources (
    id            INTEGER PRIMARY KEY,
    url           TEXT NOT NULL UNIQUE,          -- http(s) only, normalised
    title         TEXT NOT NULL,
    host          TEXT NOT NULL DEFAULT '',
    kind          TEXT NOT NULL DEFAULT 'site',  -- course | labs | ctf | platform | cheatsheet | tool | docs | blog | video | repo | community | site
    trail         TEXT NOT NULL DEFAULT '',      -- the bookmark folders it came from ("Training / Red team")
    notes         TEXT NOT NULL DEFAULT '',
    summary       TEXT NOT NULL DEFAULT '',      -- what it's for and what you get out of it (short, editable)
    status        TEXT,                          -- todo | doing | done
    favourite     INTEGER NOT NULL DEFAULT 0,
    manual        INTEGER NOT NULL DEFAULT 0,    -- categories set by you: automatic sorting leaves them alone
    open_count    INTEGER NOT NULL DEFAULT 0,
    last_opened   INTEGER,
    bookmarked_at INTEGER,
    added_at      INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resources_kind ON resources(kind);
CREATE TABLE IF NOT EXISTS resource_categories (
    id         INTEGER PRIMARY KEY,
    key        TEXT UNIQUE,                      -- built-in starter category (NULL for your own)
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    emoji      TEXT NOT NULL DEFAULT '🔗',
    color      TEXT NOT NULL DEFAULT '#64748b',
    position   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS resource_category_items (
    category_id INTEGER NOT NULL REFERENCES resource_categories(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    PRIMARY KEY (category_id, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_resource_category_items_res ON resource_category_items(resource_id);
-- 🌳 your own folder tree (from your bookmark folders, or made here); a link can sit in several folders
CREATE TABLE IF NOT EXISTS resource_folders (
    id         INTEGER PRIMARY KEY,
    parent_id  INTEGER REFERENCES resource_folders(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    position   INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_resource_folders_parent ON resource_folders(parent_id, position);
CREATE TABLE IF NOT EXISTS resource_folder_items (
    folder_id   INTEGER NOT NULL REFERENCES resource_folders(id) ON DELETE CASCADE,
    resource_id INTEGER NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    position    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (folder_id, resource_id)
);
CREATE INDEX IF NOT EXISTS idx_resource_folder_items_res ON resource_folder_items(resource_id);
-- 🧠 mind map: "goes well with" between two folders (topics), with a note on why; a < b, one per pair
CREATE TABLE IF NOT EXISTS resource_folder_links (
    id         INTEGER PRIMARY KEY,
    a          INTEGER NOT NULL REFERENCES resource_folders(id) ON DELETE CASCADE,
    b          INTEGER NOT NULL REFERENCES resource_folders(id) ON DELETE CASCADE,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    CHECK (a < b),
    UNIQUE (a, b)
);
CREATE INDEX IF NOT EXISTS idx_resource_folder_links_b ON resource_folder_links(b);
-- 📦 repos (from the Repos tab) linked to a Resources folder / topic, by full_name (stable: repo ids change when a repo is
-- removed and added back). No foreign key into the Repos tables on purpose; links to repos not there right now are skipped
-- when read and come back when the repo does.
CREATE TABLE IF NOT EXISTS resource_folder_repos (
    folder_id INTEGER NOT NULL REFERENCES resource_folders(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL COLLATE NOCASE,
    added_at  INTEGER NOT NULL,
    PRIMARY KEY (folder_id, full_name)
);
CREATE INDEX IF NOT EXISTS idx_resource_folder_repos_name ON resource_folder_repos(full_name);
"""

_db_path: Path | None = None


def _configure(conn: sqlite3.Connection) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    conn.execute("PRAGMA synchronous = NORMAL")


LEGACY_DB_NAME = "feedwarden.db"  # the file name before the EOS rename


def _adopt_legacy_file(path: Path) -> None:
    """eos.db missing but the old feedwarden.db is there: rename it (and its WAL / shared-memory files)."""
    old = path.with_name(LEGACY_DB_NAME)
    if path.name == LEGACY_DB_NAME or path.exists() or not old.exists():
        return
    for suffix in ("-wal", "-shm"):  # WAL first: the main file without its WAL would lose the newest writes
        side = old.with_name(old.name + suffix)
        if side.exists():
            side.rename(path.with_name(path.name + suffix))
    old.rename(path)


def _sqlite_tmpdir() -> None:
    """Create the folder SQLITE_TMPDIR names (the container image points it into the data volume, so big sorts do
    not fill the small /tmp tmpfs). Private to the app user; never fatal - SQLite falls back to /tmp."""
    target = os.environ.get("SQLITE_TMPDIR")
    if not target:
        return
    try:
        Path(target).mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        logging.getLogger("eos.db").warning("Could not create SQLITE_TMPDIR %s; SQLite will use /tmp", target)


def init_db(path: Path) -> None:
    global _db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    _sqlite_tmpdir()
    _adopt_legacy_file(path)
    _db_path = path
    conn = sqlite3.connect(path, timeout=15)
    try:
        _configure(conn)
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        _migrate(conn)
        conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)}")
        conn.commit()
    finally:
        conn.close()


def _migrate(conn: sqlite3.Connection) -> None:
    """Additive, idempotent migrations for databases created by older versions."""
    feed_columns = {row[1] for row in conn.execute("PRAGMA table_info(feeds)")}
    for column in ("retention_days", "max_articles"):  # v4 - fixed names, not user input
        if column not in feed_columns:
            conn.execute(f"ALTER TABLE feeds ADD COLUMN {column} INTEGER")
    if "kind" not in feed_columns:  # v5: website scraping
        conn.execute("ALTER TABLE feeds ADD COLUMN kind TEXT NOT NULL DEFAULT 'rss'")
    if "scrape" not in feed_columns:
        conn.execute("ALTER TABLE feeds ADD COLUMN scrape TEXT")
    if "source" not in feed_columns:  # v7: YouTube / HF papers / X / Telegram sources
        conn.execute("ALTER TABLE feeds ADD COLUMN source TEXT")
    if "social_platform" not in feed_columns:  # v9: Accounts tab
        conn.execute("ALTER TABLE feeds ADD COLUMN social_platform TEXT")
    if "full_text" not in feed_columns:  # v9: full article text for summary-only feeds
        conn.execute("ALTER TABLE feeds ADD COLUMN full_text TEXT")
    if "translate_titles" not in feed_columns:  # titles translated by the AI provider
        conn.execute("ALTER TABLE feeds ADD COLUMN translate_titles INTEGER NOT NULL DEFAULT 0")
    if "adaptive_minutes" not in feed_columns:  # refresh interval learnt from how often the feed posts
        conn.execute("ALTER TABLE feeds ADD COLUMN adaptive_minutes INTEGER")
    topic_link_columns = {row[1] for row in conn.execute("PRAGMA table_info(article_topics)")}
    if topic_link_columns and "source" not in topic_link_columns:  # v10: channel / General fallback topics
        conn.execute("ALTER TABLE article_topics ADD COLUMN source TEXT NOT NULL DEFAULT 'keyword'")
    article_columns = {row[1] for row in conn.execute("PRAGMA table_info(articles)")}
    if "fulltext" not in article_columns:
        conn.execute("ALTER TABLE articles ADD COLUMN fulltext INTEGER")
    meta_columns = {row[1] for row in conn.execute("PRAGMA table_info(threat_actor_meta)")}
    if meta_columns and "names" not in meta_columns:  # every name of a catalogue actor (display), not only the matched ones
        conn.execute("ALTER TABLE threat_actor_meta ADD COLUMN names TEXT NOT NULL DEFAULT '[]'")
    if meta_columns and "attack_id" not in meta_columns:
        conn.execute("ALTER TABLE threat_actor_meta ADD COLUMN attack_id TEXT")
    if "title_original" not in article_columns:  # the title before translation
        conn.execute("ALTER TABLE articles ADD COLUMN title_original TEXT")
    if "story_id" not in article_columns:  # v11: articles about the same story share the first one's id
        conn.execute("ALTER TABLE articles ADD COLUMN story_id INTEGER")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_articles_story ON articles(story_id) WHERE story_id IS NOT NULL")
    entity_columns = {row[1] for row in conn.execute("PRAGMA table_info(entities)")}
    if "muted" not in entity_columns:  # v11: names you told the matcher to stop using (kept across MITRE syncs)
        conn.execute("ALTER TABLE entities ADD COLUMN muted TEXT NOT NULL DEFAULT '[]'")
    tomb_columns = {row[1] for row in conn.execute("PRAGMA table_info(article_tombstones)")}
    if tomb_columns and "manual" not in tomb_columns:  # v9: videos you removed yourself
        conn.execute("ALTER TABLE article_tombstones ADD COLUMN manual INTEGER NOT NULL DEFAULT 0")
    repo_source_columns = {row[1] for row in conn.execute("PRAGMA table_info(repo_sources)")}
    for column in ("etag", "origin", "note", "alt_value"):  # 📦 Repos: conditional refreshes, pending links (fixed names)
        if repo_source_columns and column not in repo_source_columns:
            conn.execute(f"ALTER TABLE repo_sources ADD COLUMN {column} TEXT")
    if repo_source_columns and "folder_id" not in repo_source_columns:  # 📁 file new repos into a folder
        conn.execute("ALTER TABLE repo_sources ADD COLUMN folder_id INTEGER")
    repo_columns = {row[1] for row in conn.execute("PRAGMA table_info(repos)")}
    if repo_columns and "kind" not in repo_columns:  # gists and docs live next to repos
        conn.execute("ALTER TABLE repos ADD COLUMN kind TEXT NOT NULL DEFAULT 'repo'")
    if repo_columns and "url" not in repo_columns:
        conn.execute("ALTER TABLE repos ADD COLUMN url TEXT")
    ddl = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'repo_sources'").fetchone()
    if ddl and "'gitlab'" not in ddl[0]:  # widen the allowed source kinds: SQLite can't change a CHECK, so copy the table once
        conn.commit()
        conn.execute("PRAGMA foreign_keys = OFF")
        try:
            conn.execute("DROP TABLE IF EXISTS repo_sources_new")
            conn.execute("""CREATE TABLE repo_sources_new (
    id          INTEGER PRIMARY KEY,
    kind        TEXT NOT NULL CHECK (kind IN ('owner', 'repo', 'topic', 'stars', 'gist', 'doc', 'gitlab')),
    value       TEXT NOT NULL COLLATE NOCASE,
    title       TEXT NOT NULL DEFAULT '',
    avatar_url  TEXT,
    created_at  INTEGER NOT NULL,
    last_fetch  INTEGER,
    next_fetch  INTEGER,
    last_error  TEXT,
    repo_count  INTEGER NOT NULL DEFAULT 0,
    etag        TEXT,
    origin      TEXT,
    note        TEXT,
    alt_value   TEXT,
    folder_id   INTEGER,
    UNIQUE (kind, value)
)""")
            cols = "id, kind, value, title, avatar_url, created_at, last_fetch, next_fetch, last_error, repo_count, etag, origin, note, alt_value, folder_id"
            conn.execute(f"INSERT INTO repo_sources_new ({cols}) SELECT {cols} FROM repo_sources")
            conn.execute("DROP TABLE repo_sources")
            conn.execute("ALTER TABLE repo_sources_new RENAME TO repo_sources")
            conn.commit()
        finally:
            conn.execute("PRAGMA foreign_keys = ON")
    rule_columns = {row[1] for row in conn.execute("PRAGMA table_info(rules)")}
    if "ai_summarize" not in rule_columns:  # v8: AI summaries + instant alerts from rules
        conn.execute("ALTER TABLE rules ADD COLUMN ai_summarize INTEGER NOT NULL DEFAULT 0")
    if "alert_channel_id" not in rule_columns:
        conn.execute("ALTER TABLE rules ADD COLUMN alert_channel_id INTEGER REFERENCES delivery_channels(id) ON DELETE SET NULL")
    for column, ddl in (("require_keywords", "TEXT NOT NULL DEFAULT '[]'"), ("cve_severity", "TEXT"),
                        ("cve_owasp", "TEXT"), ("keywords_in_title", "INTEGER NOT NULL DEFAULT 0"),
                        ("cve_category", "TEXT")):  # v9: richer collection rules (fixed names, not user input)
        if column not in rule_columns:
            conn.execute(f"ALTER TABLE rules ADD COLUMN {column} {ddl}")
    resource_columns = {row[1] for row in conn.execute("PRAGMA table_info(resources)")}
    if resource_columns and "summary" not in resource_columns:  # Resources: what it's for + what you get out of it
        conn.execute("ALTER TABLE resources ADD COLUMN summary TEXT NOT NULL DEFAULT ''")
    from app import video_links  # one stored copy per video: fold old duplicates, then videos.video_id is UNIQUE

    merged = video_links.ensure_unique(conn)
    if merged and merged["removed"]:
        logging.getLogger("eos.db").info("Merged %d duplicate video copies (%d videos) into one copy each",
                                         merged["removed"], merged["sets"])


@contextmanager
def get_db() -> Iterator[sqlite3.Connection]:
    if _db_path is None:
        raise RuntimeError("Database not initialised")
    conn = sqlite3.connect(_db_path, timeout=15)
    try:
        _configure(conn)
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def now() -> int:
    return int(time.time())


def placeholders(count: int) -> str:
    """Return '?,?,?' for an IN clause. Only the *count* is interpolated, never values."""
    if count <= 0:
        raise ValueError("placeholders() needs at least one value")
    return ",".join("?" * count)
