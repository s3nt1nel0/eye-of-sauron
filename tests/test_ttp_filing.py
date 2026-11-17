"""Tactic collections filed from the techniques an article names (app/ttp_filing.py), sub-technique and tactic entities."""

import json
from unittest import mock

from app import atlas_sync, attack_sync, entities, ttp_filing
from app.db import get_db, now

TACTICS = [("TA0001", "Initial Access"), ("TA0005", "Stealth"), ("TA0112", "Defense Impairment"), ("TA0008", "Lateral Movement"),
           ("TA0040", "Impact")]
TECHS = [("T1566", "Phishing", ["Initial Access"], 0), ("T1566.001", "Spearphishing Attachment", ["Initial Access"], 1),
         ("T1055", "Process Injection", ["Privilege Escalation", "Stealth"], 0),
         ("T1685", "Disable or Modify Tools", ["Defense Impairment"], 0),
         ("T1486", "Data Encrypted for Impact", ["Impact"], 0),
         ("T0800", "Activate Firmware Update Mode", ["Inhibit Response Function", "Impact"], 0)]


def seed(old_collections=True):
    """A stored ATT&CK release with its tactic list, plus the collections an earlier version of the app made."""
    with get_db() as db:
        for tid, name, tactics, sub in TECHS:
            db.execute("INSERT INTO attack_techniques (id, name, tactics, domain, is_subtechnique, url) VALUES (?, ?, ?, ?, ?, ?)",
                       (tid, name, json.dumps(tactics), "ics-attack" if tid == "T0800" else "enterprise-attack", sub,
                        f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}"))
        ttp_filing.store_tactics(db, "enterprise-attack", [{"id": i, "name": n, "url": f"https://attack.mitre.org/tactics/{i}"} for i, n in TACTICS])
        attack_sync._watchlist(db, attack_sync.TECH_SLUG, "MITRE ATT&CK techniques", "x")
        if old_collections:
            for name in ("ATT&CK: Initial access", "ATT&CK: Defense evasion", "ATT&CK: Impact"):
                tag = db.execute("INSERT INTO tags (name, color) VALUES (?, '#475569')", (name,)).lastrowid
                db.execute("INSERT INTO rules (name, keywords, exclude_keywords, match_in, tag_id, position) VALUES (?, '[\"outage\"]', '[]', 'title_content', ?, 1000)",
                           (f"Auto: {name}", tag))
    with mock.patch("app.attack_sync.entities.reindexer.request"):
        attack_sync.refresh_aliases()
    entities.invalidate()


def article(title, text=""):
    with get_db() as db:
        fid = db.execute("SELECT id FROM feeds LIMIT 1").fetchone()
        fid = fid[0] if fid else db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('F', 'https://f.example/rss', ?)", (now(),)).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                         (fid, title, title, text, now(), now())).lastrowid
        entities.invalidate()
        entities.extract_for_articles(db, [aid])
        ttp_filing.file(db, [aid])
    return aid


def tags_of(authed, aid):
    return sorted(t["name"] for t in authed.get(f"/api/v1/articles/{aid}").json()["tags"])


def test_collections_follow_the_matrix_and_old_keyword_rules_go(authed):
    seed()
    with get_db() as db:
        names = [r[0] for r in db.execute("SELECT name FROM tags WHERE name LIKE 'ATT&CK: %' ORDER BY name")]
        rules = db.execute("SELECT COUNT(*) FROM rules WHERE name LIKE 'Auto: ATT&CK%'").fetchone()[0]
    # renamed to MITRE's spelling, Defense evasion replaced by the two tactics that succeeded it, every tactic present
    assert names == ["ATT&CK: Defense Impairment", "ATT&CK: Impact", "ATT&CK: Initial Access", "ATT&CK: Lateral Movement", "ATT&CK: Stealth"]
    assert rules == 0
    m = authed.get("/api/v1/attack/matrix?framework=attack&days=0").json()
    assert [t["name"] for t in m["tactics"]] == [n for _i, n in TACTICS]            # matrix order, not alphabetical
    assert [x["id"] for x in m["tactics"][2]["techniques"]] == ["T1685"]


def test_an_article_is_filed_under_the_tactics_of_the_techniques_it_names(authed):
    seed()
    inj = article("Loader hides with process injection", "It then runs an EDR killer.")
    assert tags_of(authed, inj) == ["ATT&CK: Defense Impairment", "ATT&CK: Stealth"]     # T1055 -> Stealth, T1685 -> Defense Impairment
    got = authed.get(f"/api/v1/articles/{inj}").json()
    assert [t["id"] for t in got["ttps"]] == ["T1055", "T1685"] and all(t["source"] == "rule" for t in got["tags"])
    # a word the old keyword rule filed on is not a technique: no filing
    assert tags_of(authed, article("Cloud outage takes down a bank for hours", "The outage was a configuration mistake.")) == []
    # the tactic named directly: filed, and reported as such
    lat = authed.get(f"/api/v1/articles/{article('Attackers moved laterally within minutes')}").json()
    assert [t["name"] for t in lat["tags"]] == ["ATT&CK: Lateral Movement"] and lat["ttps"] == []
    assert lat["ttp_tactics"] == [{"id": "TA0008", "name": "Lateral Movement", "framework": "attack"}]
    # the collections are the Enterprise matrix: an ICS technique shows as a technique, without a tactic collection
    ics = authed.get(f"/api/v1/articles/{article('Advisory references T0800')}").json()
    assert ics["tags"] == [] and [t["id"] for t in ics["ttps"]] == ["T0800"]


def test_sub_techniques_have_entities_and_show_under_their_technique(authed):
    seed()
    with get_db() as db:
        ents = {r["name"]: json.loads(r["aliases"]) for r in db.execute(
            "SELECT e.name, e.aliases FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ?", (attack_sync.TECH_SLUG,))}
    assert ents["Spearphishing Attachment (T1566.001)"] == ["T1566.001", "Spearphishing Attachment", *attack_sync.ATTACK_TERMS["T1566.001"]]
    assert "malicious attachment" in ents["Phishing (T1566)"]                         # the technique matches what its subs match
    assert ents["Lateral Movement (TA0008)"][:2] == ["TA0008", "Lateral Movement"] and ents["Impact (TA0040)"] == ["TA0040"]
    a = article("Invoice lure carries a malicious attachment")
    got = authed.get(f"/api/v1/articles/{a}").json()
    assert [(t["id"], [s["id"] for s in t["subs"]]) for t in got["ttps"]] == [("T1566", ["T1566.001"])]
    assert tags_of(authed, a) == ["ATT&CK: Initial Access"]
    plain = authed.get(f"/api/v1/articles/{article('A phishing campaign hits a university')}").json()
    assert [(t["id"], t["subs"]) for t in plain["ttps"]] == [("T1566", [])]
    # lists and pages by sub-technique ID
    assert [x["id"] for x in authed.get("/api/v1/articles?technique=T1566.001").json()["items"]] == [a]
    eid = authed.get("/api/v1/attack/techniques/T1566.001/entity").json()["entity_id"]
    page = authed.get(f"/api/v1/entities/{eid}/page?days=0").json()
    assert page["mitre"]["kind"] == "technique" and page["mitre"]["parent"]["id"] == "T1566" and page["mitre"]["tactics"] == ["Initial Access"]
    parent = authed.get(f"/api/v1/entities/{page['mitre']['parent']['entity_id']}/page?days=0").json()
    assert [(s["id"], s["entity_id"]) for s in parent["mitre"]["subtechniques"]] == [("T1566.001", eid)]
    tactic = authed.get(f"/api/v1/entities/{authed.get('/api/v1/attack/techniques/TA0001/entity').json()['entity_id']}/page?days=0").json()
    assert tactic["mitre"]["kind"] == "tactic" and [t["id"] for t in tactic["mitre"]["techniques"]] == ["T1566"]
    for bad in ("T15", "TA1", "T1566.0001", "x' OR 1=1--"):
        assert authed.get(f"/api/v1/attack/techniques/{bad}/entity").status_code in (404, 422)
    assert authed.get("/api/v1/attack/techniques/T9999/entity").status_code == 404


def test_rejecting_a_technique_covers_its_sub_techniques_and_unfiles_the_tactic(authed):
    seed()
    a = article("Invoice lure carries a malicious attachment")
    assert tags_of(authed, a) == ["ATT&CK: Initial Access"]
    assert authed.post("/api/v1/attack/techniques/T1566/reject", json={"article_id": a}).status_code == 200
    got = authed.get(f"/api/v1/articles/{a}").json()
    assert got["ttps"] == [] and got["tags"] == []
    with get_db() as db:  # a re-index adds neither the technique nor its sub-technique back
        entities.invalidate()
        entities.extract_for_articles(db, [a])
        ttp_filing.file(db, [a])
    assert tags_of(authed, a) == []
    # muting a name mutes it on the sub-technique that shares it
    b = article("Second lure with a malicious attachment")
    with mock.patch("app.api.attack.entities.reindexer.request"):
        assert authed.post("/api/v1/attack/techniques/T1566/reject", json={"article_id": b, "mute": "malicious attachment"}).status_code == 200
    with get_db() as db:
        muted = {r["name"]: json.loads(r["muted"]) for r in db.execute("SELECT name, muted FROM entities WHERE muted != '[]'")}
    assert muted == {"Phishing (T1566)": ["malicious attachment"], "Spearphishing Attachment (T1566.001)": ["malicious attachment"]}
    assert tags_of(authed, article("Third lure with a malicious attachment")) == []


def test_manual_filings_and_your_own_rules_are_left_alone(authed):
    seed()
    plain = article("Quarterly results of a hardware vendor")
    with get_db() as db:
        stealth = db.execute("SELECT id FROM tags WHERE name = 'ATT&CK: Stealth'").fetchone()[0]
    assert authed.post(f"/api/v1/articles/{plain}/tags/{stealth}").status_code == 200
    ttp_filing.refile_all()
    assert tags_of(authed, plain) == ["ATT&CK: Stealth"]                 # filed by hand: kept although no technique supports it
    # taken out by hand: the technique filing does not put it back; filing it by hand again does
    inj = article("Loader hides with process injection")
    assert tags_of(authed, inj) == ["ATT&CK: Stealth"]
    assert authed.delete(f"/api/v1/articles/{inj}/tags/{stealth}").status_code == 200
    ttp_filing.refile_all()
    assert tags_of(authed, inj) == []
    assert authed.post(f"/api/v1/articles/{inj}/tags/{stealth}").status_code == 200
    assert tags_of(authed, inj) == ["ATT&CK: Stealth"]
    # a tactic MITRE drops: its collection goes - unless you filed into it by hand
    with get_db() as db:
        db.execute("DELETE FROM attack_tactics WHERE id IN ('TA0005', 'TA0008')")
    ttp_filing.refile_all()
    with get_db() as db:
        names = {r[0] for r in db.execute("SELECT name FROM tags WHERE name LIKE 'ATT&CK: %'")}
    assert "ATT&CK: Stealth" in names and "ATT&CK: Lateral Movement" not in names


def test_pack_not_installed_means_no_collections(authed):
    seed(old_collections=False)
    a = article("Loader hides with process injection")
    assert tags_of(authed, a) == []
    assert [t["id"] for t in authed.get(f"/api/v1/articles/{a}").json()["ttps"]] == ["T1055"]   # techniques still show
    with mock.patch("app.api.automation.threading.Thread"):
        assert authed.post("/api/v1/rules/packs", json={"slugs": ["attack"]}).status_code == 200
    # installing the pack creates the collections of the stored matrix and files what is already indexed
    assert tags_of(authed, a) == ["ATT&CK: Stealth"]
    with get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM tags WHERE name LIKE 'ATT&CK: %'").fetchone()[0] == len(TACTICS)
    assert authed.post("/api/v1/rules/packs/remove", json={"slugs": ["attack"]}).json()["collections_removed"] == len(TACTICS)
    assert tags_of(authed, a) == []


def test_atlas_parent_id_and_family():
    assert atlas_sync.parent_id("T1566.001") == "T1566" and atlas_sync.parent_id("T1566") == "T1566"
    assert atlas_sync.parent_id("AML.T0051.000") == "AML.T0051" and atlas_sync.parent_id("AML.T0051") == "AML.T0051"
    for name, want in (("X (T1566)", "T1566"), ("X (T1566.001)", "T1566.001"), ("X (TA0001)", "TA0001"), ("X (AML.TA0002)", "AML.TA0002"),
                       ("X (AML.T0051.000)", "AML.T0051.000")):
        assert ttp_filing.ANY_ID.search(name).group(1) == want
    assert ttp_filing.ANY_ID.search("APT28 (G0007)") is None


def test_sidebar_lists_the_tactic_collections_in_matrix_order(authed):
    seed()
    authed.post("/api/v1/tags", json={"name": "Aardvark", "color": "#112233"})
    names = [t["name"] for t in authed.get("/api/v1/sidebar").json()["tags"]]
    assert names == ["Aardvark", "ATT&CK: Initial Access", "ATT&CK: Stealth", "ATT&CK: Defense Impairment", "ATT&CK: Lateral Movement",
                     "ATT&CK: Impact"]


def test_sub_techniques_are_recognised_next_to_their_technique_only(authed):
    from app import ttp_subs

    with get_db() as db:
        for tid, name, sub in (("T1078", "Valid Accounts", 0), ("T1078.004", "Cloud Accounts", 1), ("T1684", "Social Engineering", 0),
                               ("T1684.001", "Impersonation", 1), ("T1588", "Obtain Capabilities", 0), ("T1588.002", "Tool", 1)):
            db.execute("INSERT INTO attack_techniques (id, name, tactics, domain, is_subtechnique, url) VALUES (?, ?, '[\"Stealth\"]', 'enterprise-attack', ?, '')",
                       (tid, name, sub))
    seed()

    def with_subs(title, text=""):
        with get_db() as db:
            fid = db.execute("SELECT id FROM feeds LIMIT 1").fetchone()
            fid = fid[0] if fid else db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('F', 'https://f.example/rss', ?)", (now(),)).lastrowid
            aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                             (fid, title, title, text, now(), now())).lastrowid
            entities.invalidate()
            entities.extract_for_articles(db, [aid])
            ttp_subs.assign(db, [aid])
            ttp_filing.file(db, [aid])
        return [(t["id"], [s["id"] for s in t["subs"]]) for t in authed.get(f"/api/v1/articles/{aid}").json()["ttps"]], aid

    # the everyday name "cloud accounts" alone names nothing…
    assert with_subs("Company moves its cloud accounts to a new provider")[0] == []
    # …but next to its technique it tells which sub-technique is meant (official name, and a context term)
    assert with_subs("Intruders used valid accounts", "They logged in to cloud accounts with stolen keys.")[0] == [("T1078", ["T1078.004"])]
    ttps, imp = with_subs("Social engineering crew hits help desks", "Callers were impersonating new employees.")
    assert ttps == [("T1684", ["T1684.001"])]
    assert with_subs("Social engineering awareness month begins")[0] == [("T1684", [])]         # nothing named: the technique alone
    assert with_subs("Group will obtain capabilities from a broker", "A tool was bought.")[0] == [("T1588", [])]   # "Tool" says nothing
    # the sub-technique's own count and list follow
    eid = authed.get("/api/v1/attack/techniques/T1684.001/entity").json()["entity_id"]
    assert authed.get(f"/api/v1/entities/{eid}/page?days=0").json()["totals"]["articles"] == 1
    parent = authed.get(f"/api/v1/entities/{authed.get('/api/v1/attack/techniques/T1684/entity').json()['entity_id']}/page?days=0").json()
    assert [(s["id"], s["n"]) for s in parent["mitre"]["subtechniques"]] == [("T1684.001", 1)]
    # "not this sub-technique": removed from the article for good, the technique stays
    assert authed.post("/api/v1/attack/techniques/T1684.001/reject", json={"article_id": imp}).status_code == 200
    with get_db() as db:
        ttp_subs.assign(db, [imp])
    assert [(t["id"], t["subs"]) for t in authed.get(f"/api/v1/articles/{imp}").json()["ttps"]] == [("T1684", [])]
    # a rebuilt index gets the context matches back, and a second pass adds nothing
    with get_db() as db:
        db.execute("DELETE FROM article_entities WHERE entity_id = ?", (authed.get("/api/v1/attack/techniques/T1078.004/entity").json()["entity_id"],))
    assert ttp_subs.assign_all() == 1 and ttp_subs.assign_all() == 0
