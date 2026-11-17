"""MITRE ATLAS sync (AI techniques), the ATLAS collection pack and technique chips / filter on articles."""

from unittest import mock

import httpx
import pytest
import yaml

from app import atlas_sync, attack_sync, entities, netguard, ttp_filing
from app.db import get_db, now


def resp(body: bytes, status=200, url="https://x.example/"):
    return netguard.SafeResponse(status, httpx.Headers({"content-type": "text/plain"}), body, url)


def release_doc(extra=None):
    techs = {f"AML.T9{n:03d}": {"name": f"Filler AI Model Technique {n}", "description": "x", "modified-date": "2026-01-01"}
             for n in range(60)}
    techs.update({
        "AML.T0051": {"name": "LLM Prompt Injection", "description": "See [Direct](/techniques/AML.T0051.000).", "modified-date": "2026-05-27"},
        "AML.T0051.000": {"name": "Direct", "description": "d"},
        "AML.T0052": {"name": "Phishing", "description": "p"},
        "AML.T0108": {"name": "AI Agent", "description": "generic name"},
        "AML.T0012": {"name": "Valid Accounts", "description": "shared with ATT&CK"},
        "AML.T0999": {"name": "Gone", "description": "x", "deprecated": True},
        "bogus": {"name": "Not a technique"},
    })
    techs.update(extra or {})
    rel = {tid: {"achieves": [{"source": tid, "target": "AML.TA0005", "relationship-type": "achieves"}]} for tid in techs}
    rel["AML.T0052"] = {"achieves": [{"source": "AML.T0052", "target": "AML.TA0004"}]}
    return {"format-version": "6.1.0", "collection": {"version": "2026.10"},
            "tactics": {"AML.TA0005": {"name": "Execution"}, "AML.TA0004": {"name": "Initial Access"}},
            "matrix": {"id": "ATLAS-matrix", "name": "ATLAS"},
            "techniques": techs, "relationships": {**rel, "ATLAS-matrix": {"sequences": [
                {"source": "ATLAS-matrix", "target": "AML.TA0005", "relationship-type": "sequences", "position": 1},
                {"source": "ATLAS-matrix", "target": "AML.TA0004", "relationship-type": "sequences", "position": 2}]}}}


def run_sync(doc, manifest=None):
    manifest = manifest if manifest is not None else [{"release": "2026.10", "versions": [{"format-version": "6.1.0", "path": "v6/ATLAS-2026.10.yaml"}]}]

    def fake(method, url, **kw):
        if url == atlas_sync.MANIFEST_URL:
            return resp(yaml.safe_dump(manifest).encode(), url=url)
        assert url == atlas_sync.DIST + "v6/ATLAS-2026.10.yaml"
        return resp(yaml.safe_dump(doc).encode(), url=url)

    with mock.patch("app.attack_sync.netguard.request", side_effect=fake), \
            mock.patch.object(atlas_sync.threading, "Thread") as thread:
        assert atlas_sync.atlas_sync.start(force=True)
        thread.call_args.kwargs["target"](*thread.call_args.kwargs["args"])


@pytest.fixture()
def no_reindex():
    with mock.patch("app.atlas_sync.entities.reindexer.request") as req:
        yield req


def add_article(title, text=""):
    with get_db() as db:
        fid = db.execute("SELECT id FROM feeds LIMIT 1").fetchone()
        fid = fid[0] if fid else db.execute("INSERT INTO feeds (title, url, created_at) VALUES ('F', 'https://f.example/rss', ?)", (now(),)).lastrowid
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                         (fid, title, title, text, now(), now())).lastrowid
        entities.invalidate()
        entities.extract_for_articles(db, [aid])
        ttp_filing.file(db, [aid])
    return aid


def test_atlas_sync_builds_watchlist_collections_and_chips(authed, no_reindex):
    with mock.patch("app.api.automation.threading.Thread"):
        assert authed.post("/api/v1/rules/packs", json={"slugs": ["atlas"]}).json()["collections_created"] == 16
    with get_db() as db:  # an ATT&CK technique with the same name: ATLAS "Phishing" must only match through its ID
        db.execute("INSERT INTO attack_techniques (id, name, tactics, domain, url) VALUES ('T1566', 'Phishing', '[\"Initial Access\"]', 'enterprise-attack', 'https://attack.mitre.org/techniques/T1566')")
    run_sync(release_doc())
    st = authed.get("/api/v1/attack/status").json()
    assert st["atlas"]["last_result"]["status"] == "updated" and st["atlas"]["version"] == "2026.10"
    # the collections follow the release's own tactics (this test release has two)
    assert st["atlas"]["techniques"] == 65 and st["atlas"]["collections"] == 2 and st["atlas"]["watchlist"]
    assert st["atlas"]["last_result"]["report"]["tactics"] == ["Execution", "Initial Access"]   # the matrix's order, not the IDs'
    assert [t["name"] for t in authed.get("/api/v1/attack/matrix?framework=atlas&days=0").json()["tactics"]] == ["Execution", "Initial Access"]
    assert st["counts"]["techniques"] == 1  # ATT&CK's own count leaves ATLAS out
    with get_db() as db:
        ents = {r["name"]: r["aliases"] for r in db.execute(
            "SELECT e.name, e.aliases FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug = ?", (atlas_sync.SLUG,))}
        rules = db.execute("SELECT COUNT(*) FROM rules WHERE name LIKE 'Auto: ATLAS:%'").fetchone()[0]
        tags = sorted(r[0] for r in db.execute("SELECT name FROM tags WHERE name LIKE 'ATLAS: %'"))
    assert rules == 0 and tags == ["ATLAS: Execution", "ATLAS: Initial Access"]  # filed from techniques, not keyword rules
    assert "Gone (AML.T0999)" not in ents and not any("bogus" in n for n in ents)
    inj = ents["LLM Prompt Injection (AML.T0051)"]
    assert '"AML.T0051"' in inj and '"prompt injection"' in inj and '"LLM Prompt Injection"' in inj and '"AML.T0051.000"' in inj
    assert '"Direct"' not in inj                                     # one-word sub-technique name: ID only
    phish = ents["Phishing (AML.T0052)"]                             # shared with ATT&CK: ID and AI-specific terms only
    assert '"AML.T0052"' in phish and '"AI phishing"' in phish and '"Phishing"' not in phish
    assert ents["AI Agent (AML.T0108)"] == '["AML.T0108"]'           # generic name: ID only
    assert ents["Direct (AML.T0051.000)"] == '["AML.T0051.000"]'     # the sub-technique has its own entity
    assert ents["Execution (AML.TA0005)"] == '["AML.TA0005"]'        # tactics: by ID only

    hit = add_article("Researchers show a prompt injection against a coding assistant", "The indirect prompt injection used AML.T0052 too.")
    plain = add_article("Bank customers hit by a phishing wave", "Ordinary phishing, no AI involved.")
    items = {a["id"]: a for a in authed.get("/api/v1/articles").json()["items"]}
    ttps = {t["id"]: t for t in items[hit]["ttps"]}
    assert set(ttps) == {"AML.T0051", "AML.T0052"} and ttps["AML.T0051"]["framework"] == "atlas"
    assert ttps["AML.T0051"]["subs"] == [] and items[hit]["ttp_tactics"] == []
    # filed under the tactics of the techniques it names - and only those
    assert sorted(t["name"] for t in items[hit]["tags"]) == ["ATLAS: Execution", "ATLAS: Initial Access"]
    assert items[plain]["tags"] == []
    sub = add_article("Write-up cites AML.T0051.000 and the tactic AML.TA0004")
    got = authed.get(f"/api/v1/articles/{sub}").json()
    assert [(t["id"], [s["id"] for s in t["subs"]]) for t in got["ttps"]] == [("AML.T0051", ["AML.T0051.000"])]
    assert got["ttp_tactics"] == [{"id": "AML.TA0004", "name": "Initial Access", "framework": "atlas"}]
    assert sorted(t["name"] for t in got["tags"]) == ["ATLAS: Execution", "ATLAS: Initial Access"]
    assert authed.get("/api/v1/articles?technique=AML.T0051.000").json()["total"] == 1
    assert ttps["AML.T0051"]["tactics"] == ["Execution"] and ttps["AML.T0051"]["url"] == "https://atlas.mitre.org/techniques/AML.T0051"
    assert items[plain]["ttps"] == []
    assert [t["id"] for t in authed.get(f"/api/v1/articles/{hit}").json()["ttps"]] == ["AML.T0051", "AML.T0052"]
    only = authed.get("/api/v1/articles?technique=AML.T0051").json()
    assert sorted(a["id"] for a in only["items"]) == sorted([hit, sub]) and only["total"] == 2
    assert authed.get("/api/v1/articles?technique=T1566").json()["total"] == 0
    for bad in ("AML.T0051.0000", "T15", "x' OR 1=1--", "%"):
        assert authed.get("/api/v1/articles", params={"technique": bad}).status_code == 422
    top = authed.get("/api/v1/attack/techniques?framework=atlas&tactic=Execution").json()["items"]
    assert top == [{"id": "AML.T0051", "name": "LLM Prompt Injection", "url": "https://atlas.mitre.org/techniques/AML.T0051", "articles": 2}]
    assert authed.get("/api/v1/attack/techniques?framework=nope&tactic=Execution").status_code == 422
    assert authed.get("/api/v1/attack/techniques?framework=atlas&tactic=<script>").status_code == 422

    # An ATT&CK sync replaces its own techniques and keeps the ATLAS ones.
    attack_sync.apply({"groups": {}, "techniques": {}, "uses": set()})
    assert authed.get("/api/v1/attack/status").json()["atlas"]["techniques"] == 65


def test_atlas_sync_rejects_foreign_paths_and_bad_releases(authed, no_reindex):
    for path in ("https://evil.example/ATLAS.yaml", "../x.yaml", "v6/../../x.yaml", "v6/ATLAS-latest.yml"):
        run_sync(release_doc(), manifest=[{"release": "9", "versions": [{"path": path}]}])
        assert authed.get("/api/v1/attack/status").json()["atlas"]["last_result"]["status"] == "error"
    small = release_doc()
    small["techniques"] = {"AML.T0051": {"name": "LLM Prompt Injection"}}
    run_sync(small)
    st = authed.get("/api/v1/attack/status").json()["atlas"]
    assert st["last_result"]["status"] == "error" and st["techniques"] == 0
    with mock.patch("app.attack_sync.netguard.request", return_value=resp(b"!!python/object/apply:os.system ['echo hi']")):
        with pytest.raises(atlas_sync.AtlasError):
            atlas_sync.release()


def test_atlas_schedule_and_sync_button(authed, client):
    with mock.patch.object(atlas_sync.atlas_sync, "start") as start:
        atlas_sync.atlas_sync.maybe_start()  # never checked -> due
        assert start.called
    assert authed.patch("/api/v1/settings", json={"attack_sync": "off"}).status_code == 200
    with mock.patch.object(atlas_sync.atlas_sync, "start") as start:
        atlas_sync.atlas_sync.maybe_start()
        assert not start.called
    with mock.patch.object(attack_sync.attack_sync, "start", return_value=False), \
            mock.patch.object(atlas_sync.atlas_sync, "start", return_value=True):
        assert authed.post("/api/v1/attack/sync").json() == {"started": True}
    with mock.patch.object(attack_sync.attack_sync, "start", return_value=False), \
            mock.patch.object(atlas_sync.atlas_sync, "start", return_value=False):
        assert authed.post("/api/v1/attack/sync").status_code == 409
    assert client.get("/api/v1/attack/techniques?framework=atlas&tactic=Impact", headers={"Cookie": ""}).status_code in (200, 401)
