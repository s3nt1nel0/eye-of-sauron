"""CVE tracking: NVD parsing, KEV, CWE/OWASP catalog, classification, analytics, API, safety."""

import io
import json
import time
import zipfile
from unittest import mock

import httpx
import pytest

from app import cve_analytics, cve_classify, cve_sync, netguard


def nvd_item(cve_id, desc, *, score=None, version="cvssMetricV31", cwes=(), vendor=None, product=None,
             cpe=None, published="2026-11-10T08:00:00.000", kev=None, ssvc=None, status="Analyzed"):
    cve = {"id": cve_id, "published": published, "lastModified": published, "vulnStatus": status,
           "descriptions": [{"lang": "en", "value": desc}], "metrics": {},
           "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": f"CWE-{c}"} for c in cwes]}],
           "references": [{"url": "https://vendor.example/advisory"}, {"url": "javascript:alert(1)"}]}
    if score is not None:
        cve["metrics"][version] = [{"type": "Primary", "cvssData": {"baseScore": score, "vectorString": "CVSS:3.1/AV:N"}}]
    if vendor:
        cve["affected"] = [{"affectedData": [{"vendor": vendor, "product": product, "versions": [{"version": "1", "status": "affected"}],
                                              **({"cpes": [cpe]} if cpe else {})}]}]
    if kev:
        cve["cisaExploitAdd"] = kev
        cve["cisaVulnerabilityName"] = f"{vendor} vuln"
    if ssvc:
        cve["metrics"]["ssvcV203"] = [{"ssvcData": {"options": [{"exploitation": ssvc}]}}]
    return {"cve": cve}


def recent(days_ago=0):
    t = time.gmtime(time.time() - days_ago * 86400)
    return time.strftime("%Y-%m-%dT%H:%M:%S.000", t)


ITEMS = [
    nvd_item("CVE-2026-1000", "Command injection in the GlobalProtect SSL VPN lets an unauthenticated attacker run code.",
             score=10.0, cwes=(77,), vendor="Palo Alto Networks", product="PAN-OS",
             cpe="cpe:2.3:o:paloaltonetworks:pan-os:11.1.0:*:*:*:*:*:*:*", published=recent(1), kev="2026-11-10"),
    nvd_item("CVE-2026-1001", "Prompt injection in the LLM agent allows data exfiltration.", score=8.1, cwes=(1427,),
             vendor="langchain-ai", product="langchain", published=recent(2)),
    nvd_item("CVE-2026-1002", "Stored cross-site scripting in a WordPress plugin.", score=5.4, cwes=(79,),
             vendor="n/a", product="n/a", published=recent(3)),
    nvd_item("CVE-2026-1003", "SQL injection in admin panel.", score=9.8, version="cvssMetricV40", cwes=(89,), published=recent(1),
             ssvc="active"),
    nvd_item("CVE-2026-1004", "Rejected duplicate.", status="Rejected", published=recent(1)),
    nvd_item("CVE-2026-1005", "Out-of-bounds write in kernel driver.", score=3.1, cwes=(787,), vendor="Microsoft",
             product="Windows 11", cpe="cpe:2.3:o:microsoft:windows_11_24h2:*:*:*:*:*:*:*:*", published=recent(40)),
    {"cve": {"id": "not-a-cve", "descriptions": []}},
]


def cwe_zip(extra_xml=""):
    xml = ('<?xml version="1.0"?><Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">'
           '<Weaknesses>' + "".join(f'<Weakness ID="{i}" Name="Weakness {i}"/>' for i in [77, 79, 89, 787, 1427] + list(range(2000, 2060))) +
           '</Weaknesses><Groupings>'
           '<Grouping ID="1347" Name="OWASP Top Ten 2021 Category A03:2021 - Injection"><Relationships>'
           '<Has_Member CWE_ID="77" View_ID="1344"/><Has_Member CWE_ID="79" View_ID="1344"/><Has_Member CWE_ID="89" View_ID="1344"/>'
           '</Relationships></Grouping>'
           '<Grouping ID="1406" Name="OWASP Top Ten 2025 Category A05:2025 - Injection"><Relationships>'
           '<Has_Member CWE_ID="89" View_ID="1450"/></Relationships></Grouping>' + extra_xml +
           '</Groupings></Weakness_Catalog>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("cwec_v5.0.xml", xml)
    return buf.getvalue()


KEV_DOC = {"vulnerabilities": [
    {"cveID": "CVE-2026-1000", "dateAdded": "2026-11-10", "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known",
     "vulnerabilityName": "PAN-OS Command Injection", "vendorProject": "Palo Alto Networks", "product": "PAN-OS"},
    {"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10", "knownRansomwareCampaignUse": "Known", "vendorProject": "Apache",
     "product": "Log4j2", "vulnerabilityName": "Log4Shell", "shortDescription": "JNDI lookup RCE.", "cwes": ["CWE-917"]},
    {"cveID": "'; DROP TABLE cves;--", "dateAdded": "2026-01-01"},
]}


@pytest.fixture()
def loaded(authed):
    from app.db import get_db

    with get_db() as db:
        cve_classify.seed_builtin(db)
    entries, owasp = cve_sync.parse_cwe_zip(cwe_zip())
    with get_db() as db:
        db.executemany("INSERT OR REPLACE INTO cwe_entries (id, name, kind) VALUES (?, ?, ?)", entries)
        db.executemany("INSERT OR IGNORE INTO cwe_owasp VALUES (?, ?, ?, ?)", owasp)
        ids = cve_sync.upsert(db, [r for r in (cve_sync.parse_nvd(i) for i in ITEMS) if r])
        cve_classify.classify(db, ids)
    return authed


def q(client, **body):
    r = client.post("/api/v1/analytics/query", json={"dataset": "cves", **body})
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- parsing
def test_parse_nvd_fields():
    r = cve_sync.parse_nvd(ITEMS[0])
    assert r["severity"] == "CRITICAL" and r["score"] == 10.0 and r["cwes"] == {77} and r["kev"] == 1
    assert ("paloaltonetworks", "panos") in r["products"]
    assert r["products"][("paloaltonetworks", "panos")][0] == "Palo Alto Networks"  # human label wins
    assert json.loads(r["refs"]) == ["https://vendor.example/advisory"]  # javascript: dropped
    assert cve_sync.parse_nvd(ITEMS[3])["cvss_version"] == "4.0"
    assert cve_sync.parse_nvd(ITEMS[3])["exploitation"] == "active"
    assert cve_sync.parse_nvd(ITEMS[2])["products"] == {}  # n/a vendors ignored
    assert cve_sync.parse_nvd(ITEMS[-1]) is None


def test_cwe_zip_owasp_and_zip_bomb_guard():
    entries, owasp = cve_sync.parse_cwe_zip(cwe_zip())
    assert (89, "2021", "A03", "Injection") in owasp and (89, "2025", "A05", "Injection") in owasp
    with pytest.raises(cve_sync.SyncError):  # suspicious compression ratio
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("cwec.xml", b"<a>" + b" " * 5_000_000 + b"</a>")
        cve_sync.parse_cwe_zip(buf.getvalue())
    bad = cwe_zip().replace(b"cwec_v5.0.xml", b"../evil.xmlx")
    with pytest.raises((cve_sync.SyncError, zipfile.BadZipFile)):
        cve_sync.parse_cwe_zip(bad)


def test_cwe_xml_entities_rejected():
    import defusedxml

    xml = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Weakness_Catalog/>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("c.xml", xml)
    with pytest.raises((defusedxml.DTDForbidden, defusedxml.EntitiesForbidden, cve_sync.SyncError)):
        cve_sync.parse_cwe_zip(buf.getvalue())


# ---------------------------------------------------------------- classification
def test_classification(loaded):
    from app.db import get_db

    with get_db() as db:
        cats = {r[0]: set(r[1].split(",")) for r in db.execute(
            "SELECT m.cve_id, group_concat(k.slug) FROM cve_category_map m JOIN cve_categories k ON k.id = m.category_id GROUP BY m.cve_id")}
    assert {"edge-firewall-vpn", "rce"} <= cats["CVE-2026-1000"]
    assert "ai-ml" in cats["CVE-2026-1001"]
    assert {"xss", "wordpress"} <= cats["CVE-2026-1002"]
    assert "injection-sqli" in cats["CVE-2026-1003"]
    assert {"memory-corruption", "operating-systems"} <= cats["CVE-2026-1005"]  # microsoft:windows* prefix


def test_product_pattern_validation():
    assert cve_classify.validate_patterns(["Fortinet:FortiOS", "microsoft:windows*", "*:pytorch", "cisco"]) == \
        ["fortinet:fortios", "microsoft:windows*", "*:pytorch", "cisco"]
    for bad in ["a:b:c", "x y", "(.*)+", "vendor:", "*"]:
        with pytest.raises(ValueError):
            cve_classify.validate_patterns([bad])


# ---------------------------------------------------------------- analytics
def test_kpi_severity_and_rejected_hidden(loaded):
    assert q(loaded, type="kpi", days=7)["value"] == 4  # rejected + 40-day-old excluded
    assert q(loaded, type="kpi", days=7, filters={"severities": ["CRITICAL"]})["value"] == 2
    assert q(loaded, type="kpi", days=7, filters={"include_rejected": True})["value"] == 5
    items = q(loaded, type="breakdown", days=60, group_by="severity")["items"]
    assert [i["key"] for i in items] == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]  # fixed order
    assert items[0]["color"] == "#d03b3b"


def test_groupings(loaded):
    owasp = q(loaded, type="breakdown", days=7, group_by="owasp2021")["items"]
    assert owasp[0]["key"] == "A03" and owasp[0]["count"] == 3 and "Injection" in owasp[0]["label"]
    vendors = {i["key"]: i["label"] for i in q(loaded, type="breakdown", days=60, group_by="vendor")["items"]}
    assert vendors["paloaltonetworks"] == "Palo Alto Networks"
    cats = {i["key"] for i in q(loaded, type="breakdown", days=7, group_by="category", limit=50)["items"]}
    assert {"edge-firewall-vpn", "ai-ml", "rce"} <= cats
    ts = q(loaded, type="timeseries", days=7, group_by="category", group_categories=["ai-ml", "rce"])
    assert {s["key"] for s in ts["series"]} == {"ai-ml", "rce"}


def test_list_sort_filters_and_search(loaded):
    res = q(loaded, type="cves", days=7, sort="score", limit=10)
    assert [i["id"] for i in res["items"]][:2] == ["CVE-2026-1000", "CVE-2026-1003"] and res["total"] == 4
    assert res["items"][0]["categories"] and res["items"][0]["cwes"][0]["name"] == "Weakness 77"
    assert q(loaded, type="cves", days=7, filters={"kev_only": True})["total"] == 1
    assert q(loaded, type="cves", days=7, filters={"exploited_only": True})["total"] == 2  # KEV or SSVC active
    assert q(loaded, type="cves", days=7, filters={"ransomware_only": True})["total"] == 0  # KEV not applied yet
    assert q(loaded, type="cves", days=7, filters={"q": "cve-2026-1001"})["items"][0]["id"] == "CVE-2026-1001"
    assert q(loaded, type="cves", days=7, filters={"q": "prompt injection"})["total"] == 1
    assert q(loaded, type="cves", days=7, filters={"owasp": ["A05"], "owasp_edition": "2025"})["total"] == 1
    assert q(loaded, type="cves", days=7, filters={"categories": ["edge-firewall-vpn"], "exclude_categories": ["rce"]})["total"] == 0
    assert q(loaded, type="cves", days=7, filters={"min_score": 9})["total"] == 2


@pytest.mark.parametrize("body", [
    {"type": "breakdown", "group_by": "severity; DROP TABLE cves"},
    {"type": "cves", "sort": "score DESC; --"},
    {"type": "cves", "date_field": "id"},
    {"type": "cves", "filters": {"severities": ["EVIL"]}},
    {"type": "cves", "filters": {"categories": ["x' OR 1=1 --"]}},
    {"type": "cves", "filters": {"vendors": ["Palo Alto"]}},
    {"type": "cves", "limit": 5000},
    {"type": "breakdown", "group_by": "none"},
    {"type": "cves", "unknown": 1},
])
def test_query_validation(loaded, body):
    assert loaded.post("/api/v1/analytics/query", json={"dataset": "cves", **body}).status_code == 422


def test_fts_operators_inert(loaded):
    for text in ['" OR 1=1', "NEAR(a b)", "*", "description:x", "CVE-2026-*"]:
        assert loaded.post("/api/v1/analytics/query", json={"dataset": "cves", "type": "cves", "filters": {"q": text}}).status_code == 200


# ---------------------------------------------------------------- KEV
def test_kev_apply(loaded):
    count, missing = cve_sync.apply_kev(KEV_DOC)
    assert count == 2 and missing == ["CVE-2021-44228"]
    detail = loaded.get("/api/v1/cves/CVE-2026-1000").json()
    assert detail["kev"] == 1 and detail["kev_ransomware"] == 1 and detail["kev_name"] == "PAN-OS Command Injection"
    assert detail["links"]["nvd"].endswith("CVE-2026-1000")
    log4j = loaded.get("/api/v1/cves/cve-2021-44228").json()
    assert log4j["source"] == "kev" and log4j["cwes"][0]["id"] == 917
    with pytest.raises(cve_sync.SyncError):
        cve_sync.apply_kev({"nope": 1})


def test_cve_detail_validation(loaded):
    assert loaded.get("/api/v1/cves/..%2f..%2fetc").status_code in (404, 422)
    assert loaded.get("/api/v1/cves/CVE-1999-0").status_code == 422
    assert loaded.get("/api/v1/cves/CVE-2030-99999").status_code == 404


# ---------------------------------------------------------------- dashboards
def test_cve_template_and_legacy_widgets(loaded):
    d = loaded.post("/api/v1/dashboard-templates/cve").json()
    assert len(d["widgets"]) >= 12 and all(w["query"]["dataset"] in ("cves", "observatory") for w in d["widgets"])
    for w in d["widgets"]:
        assert loaded.post("/api/v1/analytics/query", json=w["query"]).status_code == 200, w["title"]
    # widgets saved before CVE support (no "dataset") still validate as article queries
    legacy = {"id": "abc", "title": "Old", "chart": "number", "size": "s", "query": {"type": "kpi", "days": 7}}
    r = loaded.put(f"/api/v1/dashboards/{d['id']}", json={"name": "x", "widgets": [legacy]})
    assert r.status_code == 200 and r.json()["widgets"][0]["query"]["dataset"] == "articles"
    assert loaded.post("/api/v1/analytics/query", json={"type": "kpi", "days": 7}).json()["type"] == "kpi"
    bad = {**legacy, "chart": "cvelist"}
    assert loaded.put(f"/api/v1/dashboards/{d['id']}", json={"name": "x", "widgets": [bad]}).status_code == 422


# ---------------------------------------------------------------- categories & permissions
def test_category_crud_and_reclassify(loaded):
    body = {"name": "Our vendors", "products": ["paloaltonetworks"], "keywords": ["admin panel"]}
    cat = loaded.post("/api/v1/cves/categories", json=body).json()
    assert cat["slug"] == "our-vendors"
    for _ in range(100):
        if not loaded.get("/api/v1/cves/status").json()["reclassifying"]:
            break
        time.sleep(0.05)
    assert q(loaded, type="kpi", days=7, filters={"categories": ["our-vendors"]})["value"] == 2
    assert loaded.post("/api/v1/cves/categories", json={"name": "Empty"}).status_code == 422
    assert loaded.post("/api/v1/cves/categories", json={"name": "Bad", "products": ["((a+)+)$"]}).status_code == 422
    assert loaded.patch(f"/api/v1/cves/categories/{cat['id']}", json={"enabled": False}).json()["enabled"] is False
    assert loaded.delete(f"/api/v1/cves/categories/{cat['id']}").json()["ok"]


def test_cve_scopes(loaded):
    read = {"Authorization": "Bearer " + loaded.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    assert loaded.get("/api/v1/cves/status", headers=read).status_code == 200
    assert loaded.post("/api/v1/cves/sync", json={}, headers=read).status_code == 403
    assert loaded.post("/api/v1/cves/categories", json={"name": "x", "cwe_ids": [1]}, headers=read).status_code == 403
    assert loaded.get("/api/v1/cves/status", headers={}).status_code in (200, 401)


# ---------------------------------------------------------------- NVD client
def test_nvd_client_pagination_rate_limit_and_key_header(monkeypatch, loaded):
    pages = [
        {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": ITEMS[:2]},
        {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": ITEMS[2:3]},
    ]
    calls = []

    def fake(method, url, **kw):
        calls.append((url, kw["headers"]))
        if len(calls) == 1:
            return netguard.SafeResponse(503, httpx.Headers(), b"", url)  # retried
        return netguard.SafeResponse(200, httpx.Headers(), json.dumps(pages[len(calls) - 2]).encode(), url)

    monkeypatch.setenv("EOS_NVD_API_KEY", "12345678-1234-1234-1234-123456789abc")
    from app.config import reset_settings

    reset_settings()
    import threading

    with mock.patch("app.cve_sync.netguard.request", side_effect=fake), mock.patch("app.cve_sync.time.sleep"):
        client = cve_sync.NvdClient()
        batches = list(client.iterate({"pubStartDate": "x"}, threading.Event(), lambda d, t: None))
    assert sum(len(b) for b in batches) == 3 and len(calls) == 3
    url, headers = calls[-1]
    assert headers["apiKey"].startswith("12345678") and "12345678" not in url  # key in header, not URL
    assert "startIndex=2" in url and url.startswith(cve_sync.NVD_URL)
