"""📑 Reports & guidance (app/reports.py) and the digest's reports / threat-actor sections."""

import json
from unittest import mock

from app import digests, entities, reports
from app.db import get_db, now


def feed(url, title):
    with get_db() as db:
        return db.execute("INSERT INTO feeds (title, url, created_at) VALUES (?, ?, ?)", (title, url, now())).lastrowid


def article(fid, title, text=""):
    with get_db() as db:
        aid = db.execute("INSERT INTO articles (feed_id, guid, title, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?)",
                         (fid, title, title, text, now(), now())).lastrowid
        entities.invalidate()
        entities.extract_for_articles(db, [aid])
        return aid, reports.assign(db, [aid])


def test_publisher_is_recognised_by_the_feed_not_the_link():
    assert reports.publisher_of("https://www.cyber.gov.au/rss/publications", None) == ("ASD's ACSC", "government", True)
    assert reports.publisher_of("https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", None)[0] == "NCSC UK"
    assert reports.publisher_of("https://www.sentinelone.com/labs/feed/", None)[0] == "SentinelLABS"
    assert reports.publisher_of("https://www.sentinelone.com/feed/", None) is None        # the marketing blog is not the lab
    assert reports.publisher_of("https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/", None)[0].startswith("Google Threat Intelligence")
    assert reports.publisher_of("https://www.bleepingcomputer.com/feed/", None) is None   # news about a report is not the report
    assert reports.publisher_of("https://www.crowdstrike.com/en-us/blog/feed", None) == ("CrowdStrike", "vendor", False)


def test_classification():
    c = reports.classify
    assert c("Joint guidance on securing OT edge devices", "", "government", True) == "guidance"
    assert c("ICSA-26-301-01 Siemens SCALANCE", "", "government", True) == "advisory"
    assert c("Annual Cyber Threat Report 2025-26", "", "government", True) == "report"
    assert c("Director speaks at conference", "", "government", True) is None              # agency news
    assert c("Qualcomm security advisory (AV26-1164)", "", "government", True) is None     # a relayed vendor patch note
    assert c("Inside a new Lazarus loader", "", "vendor", True) == "report"
    assert c("Join our webinar on cloud detection", "", "vendor", True) is None
    assert c("Company named a leader in the Forrester Wave", "", "vendor", True) is None
    assert c("New product features for SOC teams", "", "vendor", False) is None            # general blog, no cue
    assert c("New product features for SOC teams", "", "vendor", False, names_actor=True) == "report"
    assert c("2026 Global Threat Report", "", "vendor", False) == "report"


def test_view_filters_alerts_and_rebuild(authed):
    gov = feed("https://www.cyber.gov.au/rss/publications", "ASD")
    lab = feed("https://unit42.paloaltonetworks.com/feed/", "Unit 42")
    news = feed("https://www.bleepingcomputer.com/feed/", "News")
    g, found = article(gov, "Guidance: hardening Microsoft Exchange")
    assert found == [g]
    v, found = article(lab, "Campaign analysis: new stealer family")
    assert found == [v]
    n, found = article(news, "CISA releases guidance on Exchange")
    assert found == []
    article(gov, "Director welcomes new staff")
    got = authed.get("/api/v1/articles?publication=all").json()
    assert sorted(x["id"] for x in got["items"]) == sorted([g, v])
    assert [x["id"] for x in authed.get("/api/v1/articles?publication=government").json()["items"]] == [g]
    assert [x["id"] for x in authed.get("/api/v1/articles?publication=guidance").json()["items"]] == [g]
    assert authed.get("/api/v1/articles?publication=nope").status_code == 422
    s = authed.get("/api/v1/reports/summary").json()
    assert (s["total"], s["government"], s["vendor"], s["guidance"], s["report"]) == (2, 1, 1, 1, 1)
    assert {p["publisher"] for p in s["publishers"]} == {"ASD's ACSC", "Unit 42"}
    assert "reports_unread" not in authed.get("/api/v1/sidebar").json()["counts"]   # no separate view any more
    # publications are filed into the ordinary collections: guidance -> Defensive security, reports -> Threat intelligence
    tags = {t["name"]: t["id"] for t in authed.get("/api/v1/sidebar").json()["tags"]}
    in_tag = lambda name: [x["id"] for x in authed.get(f"/api/v1/articles?tag_id={tags[name]}").json()["items"]]  # noqa: E731
    assert in_tag("Defensive security") == [g] and in_tag("Threat intelligence") == [v]
    assert n not in in_tag("Defensive security")                           # a news site writing about guidance is not filed
    # instant alerts: only to the chosen channels, only the chosen kind, never twice
    assert authed.patch("/api/v1/settings", json={"report_alert_channels": [7, 7, 3], "report_alert_kinds": "government"}).status_code == 200
    assert authed.get("/api/v1/settings").json()["report_alert_channels"] == [3, 7]
    for bad in ({"report_alert_channels": [0]}, {"report_alert_channels": "1"}, {"report_alert_channels": list(range(1, 12))}, {"report_alert_kinds": "x"}):
        assert authed.patch("/api/v1/settings", json=bad).status_code == 422, bad
    with mock.patch("app.delivery.send_many", return_value=[]) as send:
        reports._notify([g, v])
        reports._notify([g, v])
    assert send.call_count == 1 and send.call_args.args[0] == [3, 7]
    assert "ASD" in send.call_args.args[1].subject and "Unit 42" not in send.call_args.args[1].text
    # a full rebuild finds the same
    assert reports.rebuild() == 2


def test_digest_includes_reports_and_threat_actors(authed):
    gov = feed("https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml", "NCSC")
    article(gov, "Advisory: APT28 targets routers", "Fancy Bear has been exploiting edge devices.")
    cfg = digests.DigestConfig(use_ai=False, reports={"enabled": True}, actors={"enabled": True})
    with get_db() as db:
        rep = digests._reports(db, cfg, now() - 3600)
        act = digests._actors(db, cfg, now() - 3600)
    assert [r["publisher"] for r in rep] == ["NCSC UK"]
    assert act and act[0]["n"] == 1 and "APT28" in act[0]["name"]
    subject, body, err = digests.render("Morning", cfg, [], [], rep, act)
    assert "1 reports" in subject and "NEW REPORTS & GUIDANCE" in body and "THREAT ACTORS IN THE NEWS" in body and err is None
    with mock.patch("app.ai.complete") as complete:
        complete.return_value = mock.Mock(text="briefing")
        digests.render("Morning", cfg.model_copy(update={"use_ai": True}), [], [], rep, act)
        sent = complete.call_args.args[1]
    assert "[R1]" in sent and "[A1]" in sent
    assert json.loads(digests.config_json(cfg))["reports"]["enabled"] is True


def test_rule_edits_never_take_publications_out_of_their_collection(authed):
    from app import rules
    from app.db import get_db

    gov = feed("https://www.cyber.gov.au/rss/publications", "ASD")
    a, found = article(gov, "Advisory: actively exploited flaw in VPN appliances")
    assert found == [a]
    with get_db() as db:
        tag = reports.collection_ids(db)["advisory"]
        db.execute("INSERT INTO rules (name, keywords, tag_id) VALUES ('adv', ?, ?)", ('["zzz-never"]', tag))
    assert rules.refile_tags([tag]) == 0                                     # no rule matches it, but it stays filed
    with get_db() as db:
        assert db.execute("SELECT source FROM article_tags WHERE article_id = ? AND tag_id = ?", (a, tag)).fetchone()[0] == "rule"


def test_existing_publications_are_filed_once(authed):
    from app.db import get_db

    gov = feed("https://www.cyber.gov.au/rss/publications", "ASD")
    a, _ = article(gov, "Guidance: securing edge devices")
    with get_db() as db:
        db.execute("DELETE FROM article_tags")
    out = reports.file_all()
    assert out["added"] == 1 and out["per_collection"] == {"Defensive security": 1}
    assert reports.file_all()["added"] == 0
