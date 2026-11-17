"""Threat-actor catalogue, one-actor-many-names, the actor filter, and related videos / podcasts."""

import json
from unittest import mock

import pytest

from app import attack_sync, entities, related, threat_actors
from app.db import get_db, now

CATALOG = {"version": 1, "built": "test", "actors": [
    {"name": "APT28", "match_name": True, "aliases": ["FANCY BEAR", "Forest Blizzard", "Sofacy"], "country": "RU", "kind": "state",
     "sources": ["MISP galaxy", "CrowdStrike"]},
    {"name": "Scattered Spider", "match_name": True, "aliases": ["Octo Tempest", "UNC3944"], "country": "", "kind": "crime", "sources": ["CrowdStrike"]},
    {"name": "Akira", "match_name": False, "aliases": ["Storm-1567"], "country": "", "kind": "crime", "sources": ["MISP galaxy"]},
    {"name": "VOLTZITE", "match_name": True, "aliases": [], "country": "CN", "kind": "", "sources": ["Dragos"]},
]}


@pytest.fixture()
def catalog(tmp_path, monkeypatch, authed):
    path = tmp_path / "actors.json"
    path.write_text(json.dumps(CATALOG), encoding="utf-8")
    monkeypatch.setattr(threat_actors, "CATALOG", path)
    with get_db() as db:  # a MITRE group that is the same actor as a catalogue entry, under MITRE's own name
        wid = attack_sync._watchlist(db, attack_sync.GROUPS_SLUG, "MITRE ATT&CK groups", "x")
        db.execute("INSERT INTO entities (watchlist_id, name, aliases) VALUES (?, 'APT28 (G0007)', ?)", (wid, json.dumps(["G0007", "APT28", "Fancy Bear", "STRONTIUM"])))
    with mock.patch("app.threat_actors.entities.reindexer.request") as req:
        out = threat_actors.apply_catalog()
        assert out == {"entities_changed": 4, "entities_removed": 0} and len(req.call_args.args[0]) == 4
    entities.invalidate()
    return authed


def item(kind, title, text="", ts=None):
    ts = ts or now()
    with get_db() as db:
        feed = db.execute("SELECT id FROM feeds WHERE COALESCE(kind, 'rss') = ?", (kind,)).fetchone()
        fid = feed[0] if feed else db.execute("INSERT INTO feeds (title, url, kind, created_at) VALUES (?, ?, ?, ?)",
                                              (f"{kind} feed", f"https://{kind}.example/f", kind, now())).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                         (fid, title, title, text, ts, ts)).lastrowid
        if kind == "youtube":
            db.execute("INSERT INTO videos (article_id, video_id, channel_title) VALUES (?, ?, 'Chan')", (aid, f"v{aid:010d}"))
        if kind == "podcast":
            db.execute("INSERT INTO episodes (article_id, audio_url) VALUES (?, 'https://p.example/a.mp3')", (aid,))
        entities.invalidate()
        entities.extract_for_articles(db, [aid])
    return aid


def test_catalogue_entities_and_idempotence(catalog):
    with get_db() as db:
        ents = {r["name"]: json.loads(r["aliases"]) for r in db.execute(
            "SELECT e.name, e.aliases FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ?", (threat_actors.SLUG,))}
    assert ents["APT28"] == ["FANCY BEAR", "Forest Blizzard", "Sofacy"] and ents["VOLTZITE"] == []
    assert "Akira (threat actor)" in ents and "Akira" not in ents           # an everyday word: only its other names match
    with mock.patch("app.threat_actors.entities.reindexer.request") as req:
        assert threat_actors.apply_catalog() == {"entities_changed": 0, "entities_removed": 0} and not req.called
        assert threat_actors.ensure_current() is False
    # a newer file: one actor gone, one renamed alias set
    newer = {**CATALOG, "built": "test2", "actors": [a for a in CATALOG["actors"] if a["name"] != "VOLTZITE"]}
    threat_actors.CATALOG.write_text(json.dumps(newer), encoding="utf-8")
    with mock.patch("app.threat_actors.entities.reindexer.request"):
        assert threat_actors.ensure_current() is True
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM threat_actor_meta").fetchone()[0] == 3


def test_one_actor_under_several_names_and_the_filter(catalog):
    a = item("rss", "Forest Blizzard targets ministries")              # catalogue name only
    b = item("rss", "New STRONTIUM tooling analysed")                  # MITRE alias only
    c = item("rss", "Report cites G0007 and Sofacy")                   # both
    item("rss", "Akira the film gets a remake")                        # the everyday word is not the actor
    d = item("rss", "Storm-1567 affiliates hit a hospital")
    v = item("youtube", "Talk: tracking Fancy Bear")
    old = item("rss", "Old APT28 story", ts=now() - 200 * 86400)
    lst = catalog.get("/api/v1/threat-actors").json()
    by = {x["name"]: x for x in lst["items"]}
    # APT28 (MITRE) + APT28 (catalogue) = one actor
    assert [x["name"] for x in catalog.get("/api/v1/threat-actors?q=forest blizzard").json()["items"]] == ["APT28 (G0007)"]
    apt = by["APT28 (G0007)"]                                           # MITRE's name leads
    assert (apt["articles"], apt["videos"], apt["podcasts"]) == (4, 1, 0) and apt["country"] == "RU" and apt["kind"] == "state"
    assert {"MITRE ATT&CK", "MISP galaxy", "CrowdStrike"} <= set(apt["sources"]) and "Forest Blizzard" in apt["also"]   # + the built-in list's entry
    akira = next(x for x in lst["items"] if "akira" in x["name"].lower())  # joined with the built-in ransomware list's "Akira"
    assert akira["articles"] >= 1 and "VOLTZITE" not in by             # not mentioned: left out…
    assert "VOLTZITE" in [x["name"] for x in catalog.get("/api/v1/threat-actors?q=voltz").json()["items"]]   # …but found by search
    assert [x["name"] for x in catalog.get("/api/v1/threat-actors?q=octo tempest").json()["items"]] == ["Scattered Spider"]
    assert catalog.get("/api/v1/threat-actors?days=30").json()["items"][0]["articles"] == 3
    # filtering by the actor = under any of its names, whichever entity id is used
    with get_db() as db:
        ids = [r[0] for r in db.execute("SELECT id FROM entities WHERE name IN ('APT28 (G0007)', 'APT28')")]
    for eid in ids:
        got = catalog.get(f"/api/v1/articles?entity_id={eid}").json()
        assert sorted(x["id"] for x in got["items"]) == sorted([a, b, c, old]) and got["total"] == 4
        page = catalog.get(f"/api/v1/entities/{eid}/page?days=0").json()
        assert page["totals"]["articles"] == 4 and page["totals"]["videos"] == 1 and page["all_time"] == 5
        assert page["actor"]["members"] >= 2 and page["actor"]["country"] == "RU"
        assert [x["id"] for x in catalog.get(f"/api/v1/library/videos?entity_id={eid}").json()["items"]] == [v]
    assert d and catalog.get("/api/v1/entities/999999/page").status_code == 404
    for bad in ("/api/v1/threat-actors?days=5", "/api/v1/threat-actors?limit=0", "/api/v1/threat-actors?q=" + "x" * 81):
        assert catalog.get(bad).status_code == 422


def test_related_videos_and_podcasts(catalog):
    with get_db() as db:  # background, so that "rare" means something
        fid = db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('Bg', 'https://bg.example/f', ?)", (now(),)).lastrowid
        db.executemany("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, '', ?, ?)",
                       [(fid, f"bg{i}", f"Unrelated story number {i} about budgets", now(), now()) for i in range(600)])
    art = item("rss", "Scattered Spider breaks into a casino", "Octo Tempest used help-desk calls.")
    v1 = item("youtube", "Deep dive: Scattered Spider's playbook")
    v2 = item("youtube", "UNC3944 and the help desk problem")
    item("youtube", "Cooking with spiders")                              # no shared name
    ep = item("podcast", "Episode 9: Octo Tempest")
    plain = item("rss", "Quarterly results of a hardware vendor")
    got = catalog.get(f"/api/v1/articles/{art}").json()
    assert got["related"] == {"videos": 2, "podcasts": 1}
    assert catalog.get(f"/api/v1/articles/{plain}").json()["related"] == {"videos": 0, "podcasts": 0}
    vids = catalog.get(f"/api/v1/articles/{art}/related?kind=videos").json()
    assert vids["total"] == 2 and sorted(x["id"] for x in vids["items"]) == sorted([v1, v2])
    assert vids["items"][0]["shared"] == ["Scattered Spider"] and vids["items"][0]["score"] >= related.MIN_SCORE
    assert [x["id"] for x in catalog.get(f"/api/v1/articles/{art}/related?kind=podcasts").json()["items"]] == [ep]
    # "open all on one page": the Videos / Podcasts lists narrowed to exactly those
    assert sorted(x["id"] for x in catalog.get(f"/api/v1/library/videos?related_to={art}").json()["items"]) == sorted([v1, v2])
    assert [x["id"] for x in catalog.get(f"/api/v1/podcasts/episodes?related_to={art}").json()["items"]] == [ep]
    assert catalog.get(f"/api/v1/library/videos?related_to={plain}").json()["total"] == 0
    assert catalog.get("/api/v1/library/videos").json()["total"] == 3
    # the switch
    assert catalog.patch("/api/v1/settings", json={"related_media": False}).status_code == 200
    assert catalog.get(f"/api/v1/articles/{art}").json()["related"] == {"videos": 0, "podcasts": 0}
    for bad in (f"/api/v1/articles/{art}/related", f"/api/v1/articles/{art}/related?kind=articles", f"/api/v1/articles/{art}/related?kind=videos&limit=0",
                "/api/v1/library/videos?related_to=0", "/api/v1/podcasts/episodes?related_to=abc"):
        assert catalog.get(bad).status_code == 422, bad
    assert catalog.get("/api/v1/articles/999999/related?kind=videos").status_code == 404


def test_new_routes_need_a_session(client):
    for path in ("/api/v1/threat-actors", "/api/v1/articles/1/related?kind=videos"):
        assert client.get(path).status_code == 401, path


def test_bundled_catalogue_is_well_formed():
    data = threat_actors.load_catalog()
    assert len(data["actors"]) > 900
    names = {a["name"].lower() for a in data["actors"]}
    alias = {x.lower() for a in data["actors"] for x in a["aliases"]}
    for must in ("APT28", "Lazarus Group", "Scattered Spider", "Volt Typhoon", "Hydro Kitten", "GTG-1002", "Cosmic Wolf", "Umbral Bison"):
        assert must.lower() in names or must.lower() in alias, must
    for dragos in ("VOLTZITE", "ELECTRUM", "KAMACITE", "XENOTIME", "BAUXITE", "GRAPHITE", "PARISITE"):
        assert dragos.lower() in names or dragos.lower() in alias, dragos
    for a in data["actors"]:
        assert isinstance(a["name"], str) and 0 < len(a["name"]) <= 80 and len(a["aliases"]) <= 30
        assert set(a) == {"name", "match_name", "aliases", "country", "kind", "sources"}
        assert a["match_name"] or a["aliases"]                           # something it can be recognised by
        assert all(len(x) >= 4 and "<" not in x for x in a["aliases"])


def test_conti_seed_fix_only_touches_an_unedited_entry(authed):
    from app import entities_seed

    with get_db() as db:
        wid = db.execute("SELECT id FROM watchlists WHERE slug = 'ransomware-groups'").fetchone()[0]
        db.execute("UPDATE entities SET name = 'Conti', aliases = '[\"Conti ransomware\"]' WHERE watchlist_id = ? AND name = 'Conti (ransomware)'", (wid,))
        fixed = entities_seed.fix_seeded(db)
        assert len(fixed) == 1 and entities_seed.fix_seeded(db) == []
        row = db.execute("SELECT name, aliases FROM entities WHERE id = ?", (fixed[0],)).fetchone()
        assert row["name"] == "Conti (ransomware)" and "Conti gang" in json.loads(row["aliases"])
        # an entry you edited yourself is left alone
        db.execute("UPDATE entities SET name = 'Conti', aliases = '[\"Conti ransomware\", \"my own alias\"]' WHERE id = ?", (fixed[0],))
        assert entities_seed.fix_seeded(db) == []
    entities.invalidate()
    talk = item("youtube", "DEF CON 12 - Greg Conti, Network Attack Visualization")
    real = item("rss", "Former Conti members regroup", "The Conti ransomware gang split in 2022.")
    with get_db() as db:
        db.execute("UPDATE entities SET name = 'Conti (ransomware)', aliases = ? WHERE id = ?",
                   (json.dumps(dict((n, a) for _s, _t, _d, items in entities_seed.BUILTIN_WATCHLISTS for n, a in items)["Conti (ransomware)"]), fixed[0]))
        entities.invalidate()
        db.execute("DELETE FROM article_entities WHERE entity_id = ?", (fixed[0],))
        entities.extract_for_articles(db, [talk, real])
        got = [r[0] for r in db.execute("SELECT article_id FROM article_entities WHERE entity_id = ?", (fixed[0],))]
    assert got == [real]
