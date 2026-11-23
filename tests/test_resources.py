"""🔗 Resources tab: sorting rules, bookmark import (Netscape HTML and pasted lines), duplicates, categories, manual
changes surviving a re-sort, and permissions. Nothing here makes an outbound request."""

from unittest import mock

from app import resources

BOOKMARKS = """<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE><H1>Bookmarks</H1>
<DL><p>
  <DT><H3>Cyber</H3>
  <DL><p>
    <DT><H3>Defensive Security</H3>
    <DL><p>
      <DT><H3>Digital Forensics</H3>
      <DL><p>
        <DT><A HREF="https://www.kroll.com/kape" ADD_DATE="1700000000">Kroll Artifact Parser and Extractor - KAPE</A>
        <DT><A HREF="https://ericzimmerman.github.io/">Eric Zimmerman's tools</A>
      </DL><p>
    </DL><p>
    <DT><H3>Training</H3>
    <DL><p>
      <DT><H3>CTF</H3>
      <DL><p>
        <DT><A HREF="https://ctf.hackthebox.com/">Capture The Flag Competitions For Hackers | Hack The Box CTFs</A>
        <DT><A HREF="https://picoctf.org/">picoCTF - CMU Cybersecurity Competition</A>
      </DL><p>
      <DT><A HREF="https://tryhackme.com/">TryHackMe | Red Team Fundamentals</A>
    </DL><p>
    <DT><A HREF="https://www.youtube.com/@JohnHammond010">John Hammond - YouTube</A>
    <DT><A HREF="javascript:alert(1)">evil</A>
    <DT><A HREF="https://user:pass@example.com/x">creds</A>
    <DT><A HREF="https://tryhackme.com">TryHackMe again (duplicate)</A>
    <DT><A HREF="https://example.com/<script>">Plain &lt;b&gt;site&lt;/b&gt;</A>
  </DL><p>
</DL><p>
"""


def test_sorting_rules():
    cases = {
        ("Kroll Artifact Parser and Extractor - KAPE", "https://www.kroll.com/kape", "Cyber / Defensive Security / Digital Forensics"): ("dfir", None),
        ("Capture The Flag Competitions For Hackers | Hack The Box CTFs", "https://ctf.hackthebox.com/", "Cyber / Training / CTF"): (None, "ctf"),
        ("TryHackMe | Red Team Fundamentals", "https://tryhackme.com/", ""): ("redteam", "platform"),
        ("OWASP Top 10:2021", "https://owasp.org/Top10/", ""): ("appsec", "docs"),
        ("REMnux: A Linux Toolkit for Malware Analysis", "https://remnux.org/", ""): ("malware", None),
        ("John Hammond - YouTube", "https://www.youtube.com/@JohnHammond010", ""): (None, "video"),
        ("OJ/gobuster: Directory/File busting tool", "https://github.com/OJ/gobuster", ""): ("offensive", "repo"),
        ("Maldev Academy", "https://maldevacademy.com/", ""): ("maldev", None),
        ("STIX Version 2.1", "https://docs.oasis-open.org/cti/stix/v2.1/", ""): ("cti", "docs"),
        ("Modbus RTU and DNP3 in substations", "https://example.com/x", ""): ("otics", None),
        ("Krebs on Security – In-depth security news", "https://krebsonsecurity.com/", ""): ("news", "blog"),
        ("PowerShell Documentation", "https://learn.microsoft.com/powershell/", "Powershell / Maintain"): ("scripting", "docs"),
    }
    for (title, url, trail), (cat, kind) in cases.items():
        cats, k = resources.classify(title, url, trail)
        if cat:
            assert cat in cats, (title, cats)
        if kind:
            assert k == kind, (title, k)
        assert len(cats) <= 3


def test_parse_bookmark_file_keeps_folders_and_drops_unsafe_links():
    items = resources.parse_bookmarks(BOOKMARKS)
    urls = {i["url"]: i for i in items}
    assert urls["https://www.kroll.com/kape"]["trail"] == "Cyber / Defensive Security / Digital Forensics"
    assert urls["https://www.kroll.com/kape"]["bookmarked_at"] == 1700000000
    assert urls["https://ctf.hackthebox.com/"]["trail"] == "Cyber / Training / CTF"
    assert urls["https://tryhackme.com/"]["trail"] == "Cyber / Training"
    assert urls["https://www.youtube.com/@JohnHammond010"]["trail"] == "Cyber"
    assert resources.clean_url("javascript:alert(1)") is None
    assert resources.clean_url("https://user:pass@example.com/x") is None
    assert resources.clean_url("file:///etc/passwd") is None


def test_parse_pasted_lines():
    items = resources.parse_lines(["https://gtfobins.github.io", "LOLBAS | https://lolbas-project.github.io/", "[HackTricks](https://book.hacktricks.wiki)",
                                   "a line with no link at all, just words"])
    assert [i["url"] for i in items[:3]] == ["https://gtfobins.github.io", "https://lolbas-project.github.io/", "https://book.hacktricks.wiki"]
    assert items[1]["title"] == "LOLBAS" and items[2]["title"] == "HackTricks"
    assert items[3]["url"] == ""                                                    # reported as invalid, not stored
    # a plain list with headings (what a copied bookmark list looks like)
    listed = resources.parse_bookmarks("Training\nhttps://pwn.college\nDFIR\nVolatility - https://volatilityfoundation.org/")
    assert [(i["trail"], i["url"]) for i in listed] == [("Training", "https://pwn.college"), ("DFIR", "https://volatilityfoundation.org/")]


def test_import_and_browse(authed):
    with mock.patch("app.netguard.request", side_effect=AssertionError("no outbound requests")):
        r = authed.post("/api/v1/resources/import", json={"html": BOOKMARKS})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["added"] == 7 and out["found"] >= 9
    m = authed.get("/api/v1/resources/meta").json()
    assert m["total"] == 7
    cats = {c["key"]: c for c in m["categories"]}
    assert cats["dfir"]["count"] >= 2 and "Defensive security" in {c["name"] for c in m["categories"]}
    assert m["training"] >= 3                                                   # CTFs + the platform
    items = authed.get("/api/v1/resources?limit=100").json()["items"]
    plain = [i for i in items if i["host"] == "example.com"][0]
    assert plain["title"] == "Plain site" and "<" not in plain["title"]          # markup stripped
    assert authed.get(f"/api/v1/resources?category_id={cats['dfir']['id']}").json()["total"] >= 2
    assert authed.get("/api/v1/resources?training=true").json()["total"] >= 3
    assert authed.get("/api/v1/resources?kind=ctf").json()["total"] == 2
    assert authed.get("/api/v1/resources?q=hack%20box").json()["total"] == 1     # every word must match
    # importing again adds nothing
    again = authed.post("/api/v1/resources/import", json={"html": BOOKMARKS}).json()
    assert again["added"] == 0 and again["duplicates"] == 8                 # (the file lists one of them twice)


def test_manual_changes_survive_resorting_and_categories(authed):
    authed.post("/api/v1/resources/batch", json={"lines": ["https://www.kroll.com/kape", "Krebs | https://krebsonsecurity.com/"]})
    m = authed.get("/api/v1/resources/meta").json()
    cats = {c["key"]: c["id"] for c in m["categories"]}
    items = {i["host"]: i for i in authed.get("/api/v1/resources").json()["items"]}
    kape = items["kroll.com"]
    mine = authed.post("/api/v1/resources/categories", json={"name": "Exam prep", "emoji": "📝"}).json()
    r = authed.patch(f"/api/v1/resources/{kape['id']}", json={"category_ids": [mine["id"]], "favourite": True, "status": "todo", "notes": "Do the KAPE lab"})
    assert r.status_code == 200 and r.json()["manual"] and r.json()["categories"] == [mine["id"]]
    assert authed.post("/api/v1/resources/reclassify").json()["sorted"] == 1        # only the one you didn't touch
    kape = [i for i in authed.get("/api/v1/resources").json()["items"] if i["id"] == kape["id"]][0]
    assert kape["categories"] == [mine["id"]] and kape["favourite"] and kape["status"] == "todo"
    # deleting a category keeps its links; favourites show in the quick bar
    assert authed.delete(f"/api/v1/resources/categories/{mine['id']}").json()["resources_kept"] == 1
    m = authed.get("/api/v1/resources/meta").json()
    assert m["uncategorised"] == 1 and [f["id"] for f in m["favourites"]] == [kape["id"]]
    # opening counts
    authed.post(f"/api/v1/resources/{kape['id']}/opened")
    assert authed.get("/api/v1/resources/meta").json()["recent"][0]["id"] == kape["id"]
    # bulk: add to a category, then delete
    ids = [i["id"] for i in authed.get("/api/v1/resources").json()["items"]]
    assert authed.post("/api/v1/resources/bulk", json={"ids": ids, "action": "add", "category_id": cats["news"]}).json()["changed"] >= 1
    assert authed.post("/api/v1/resources/bulk", json={"ids": ids, "action": "delete"}).json()["changed"] == 2
    assert authed.get("/api/v1/resources/meta").json()["total"] == 0


def test_starter_categories_are_seeded_once(authed):
    m = authed.get("/api/v1/resources/meta").json()
    first = {c["key"]: c["id"] for c in m["categories"]}
    assert {"offensive", "defensive", "purple", "redteam", "blueteam", "cti", "malware", "dfir", "maldev", "scripting", "coding"} <= set(first)
    authed.delete(f"/api/v1/resources/categories/{first['maldev']}")
    keys = {c["key"] for c in authed.get("/api/v1/resources/meta").json()["categories"]}
    assert "maldev" not in keys                                                  # a deleted starter stays deleted


def test_validation_limits_and_permissions(authed):
    assert authed.post("/api/v1/resources/batch", json={"lines": []}).status_code == 422
    assert authed.post("/api/v1/resources/batch", json={"lines": ["x"] * 501}).status_code == 422
    assert authed.post("/api/v1/resources/import", json={"html": "no links in here"}).status_code == 422
    assert authed.get("/api/v1/resources?kind=evil").status_code == 422
    assert authed.post("/api/v1/resources/categories", json={"name": "x", "color": "red;}"}).status_code == 422
    big = "<DT><A HREF=\"https://e.com/{}\">x</A>\n"
    body = {"html": "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n" + "".join(big.format(i) for i in range(40000))}   # ~1.6 MB: allowed here
    assert authed.post("/api/v1/resources/import", json=body).status_code == 200
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    csrf = authed.headers.pop("X-CSRF-Token")
    cookies = dict(authed.cookies)
    authed.cookies.clear()
    try:
        assert authed.get("/api/v1/resources", headers=read).status_code == 200
        for method, path, payload in (("post", "/api/v1/resources/batch", {"lines": ["https://e.com"]}), ("post", "/api/v1/resources/import", {"html": BOOKMARKS}),
                                      ("post", "/api/v1/resources/categories", {"name": "x"}), ("post", "/api/v1/resources/reclassify", None),
                                      ("post", "/api/v1/resources/bulk", {"ids": [1], "action": "delete"})):
            kw = {"headers": read} | ({"json": payload} if payload is not None else {})
            assert getattr(authed, method)(path, **kw).status_code == 403, path
        assert authed.get("/api/v1/resources").status_code == 401
    finally:
        authed.headers["X-CSRF-Token"] = csrf
        authed.cookies.update(cookies)


def test_import_preview_and_left_out_folders(authed):
    pv = authed.post("/api/v1/resources/import", json={"html": BOOKMARKS, "preview": True}).json()
    folders = {f["path"]: f for f in pv["folders"]}
    assert folders["Cyber"]["count"] >= 7 and folders["Cyber / Training"]["depth"] == 1
    assert folders["Cyber / Training / CTF"]["count"] == 2
    assert authed.get("/api/v1/resources/meta").json()["total"] == 0                # preview saves nothing
    r = authed.post("/api/v1/resources/import", json={"html": BOOKMARKS, "skip_folders": ["Cyber / Training"]}).json()
    assert r["left_out"] == 3 and r["added"] == 5                                    # 2 CTFs + TryHackMe left out with their folder
    hosts = {i["host"] for i in authed.get("/api/v1/resources?limit=100").json()["items"]}
    assert "picoctf.org" not in hosts and "ctf.hackthebox.com" not in hosts and "kroll.com" in hosts
    # a sibling folder whose name only starts the same isn't skipped by accident
    assert authed.post("/api/v1/resources/import", json={"html": BOOKMARKS, "skip_folders": ["Cyber / Train"]}).json()["left_out"] == 0


NESTED = """<!DOCTYPE NETSCAPE-Bookmark-file-1>
<DL><p>
  <DT><H3 PERSONAL_TOOLBAR_FOLDER="true">Bookmarks bar</H3>
  <DL><p>
    <DT><H3>Cyber</H3>
    <DL><p>
      <DT><H3>Training</H3>
      <DL><p>
        <DT><A HREF="https://tryhackme.com/">TryHackMe</A>
        <DT><H3>CTF</H3>
        <DL><p><DT><A HREF="https://picoctf.org/">picoCTF</A></DL><p>
      </DL><p>
      <DT><H3>AI Course/Others</H3>
      <DL><p><DT><A HREF="https://tryhackme.com">TryHackMe (also here)</A></DL><p>
    </DL><p>
    <DT><H3>Personal</H3>
    <DL><p><DT><A HREF="https://mail.example.com/">Inbox</A></DL><p>
  </DL><p>
  <DT><A HREF="https://loose.example.com/">Loose link</A>
</DL><p>
"""


def _folders(authed):
    return {f["name"]: f for f in authed.get("/api/v1/resources/folders").json()["folders"]}


def test_import_recreates_folders_and_files_links(authed):
    pv = authed.post("/api/v1/resources/import", json={"html": NESTED, "preview": True}).json()
    assert [f["path"] for f in pv["folders"]][:2] == ["Cyber", "Cyber / Training"]          # the browser's "Bookmarks bar" is dropped
    r = authed.post("/api/v1/resources/import", json={"html": NESTED, "skip_folders": ["Personal"]}).json()
    assert r["added"] == 3 and r["left_out"] == 1 and r["folders_made"] == 4
    f = _folders(authed)
    assert set(f) == {"Cyber", "Training", "CTF", "AI Course/Others"}
    assert f["Training"]["parent_id"] == f["Cyber"]["id"] and f["CTF"]["parent_id"] == f["Training"]["id"]
    assert f["Cyber"]["total"] == 3 and f["Training"]["count"] == 1 and f["CTF"]["count"] == 1
    tree = authed.get("/api/v1/resources/tree").json()
    thm = [i for i in tree["items"] if i["host"] == "tryhackme.com"][0]
    assert sorted(thm["folders"]) == sorted([f["Training"]["id"], f["AI Course/Others"]["id"]])   # bookmarked twice: in both folders
    assert tree["unfiled"] == 1                                                            # the loose link at the top
    assert authed.get(f"/api/v1/resources?folder_id={f['Cyber']['id']}&include_sub=true").json()["total"] == 2
    assert authed.get(f"/api/v1/resources?folder_id={f['Cyber']['id']}").json()["total"] == 0
    # without folders: links only
    authed.post("/api/v1/resources/import", json={"html": NESTED, "make_folders": False})
    assert len(_folders(authed)) == 4


def test_folder_editing(authed):
    authed.post("/api/v1/resources/import", json={"html": NESTED})
    f = _folders(authed)
    top = authed.post("/api/v1/resources/folders", json={"name": "Exam prep"}).json()
    sub = authed.post("/api/v1/resources/folders", json={"name": "OSCP", "parent_id": top["id"]}).json()
    assert authed.post("/api/v1/resources/folders", json={"name": "OSCP", "parent_id": top["id"]}).status_code == 409
    assert authed.patch(f"/api/v1/resources/folders/{top['id']}", json={"parent_id": sub["id"]}).status_code == 422   # not into itself
    assert authed.patch(f"/api/v1/resources/folders/{f['CTF']['id']}", json={"parent_id": top["id"], "name": "CTFs"}).json()["parent_id"] == top["id"]
    ids = [i["id"] for i in authed.get("/api/v1/resources/tree").json()["items"]]
    assert authed.post(f"/api/v1/resources/folders/{sub['id']}/items", json={"resource_ids": ids}).json()["changed"] == len(ids)
    assert authed.post(f"/api/v1/resources/folders/{top['id']}/items", json={"resource_ids": ids[:1], "action": "move", "from_folder_id": sub["id"]}).json()["changed"] == 1
    assert _folders(authed)["OSCP"]["count"] == len(ids) - 1
    # delete keeping links, then delete with links (only links not filed elsewhere go)
    assert authed.delete(f"/api/v1/resources/folders/{f['AI Course/Others']['id']}").json()["links_deleted"] == 0
    r = authed.delete(f"/api/v1/resources/folders/{top['id']}?with_links=true").json()
    assert r["folders"] == 3                                                                # Exam prep, OSCP, CTFs
    left = {i["host"] for i in authed.get("/api/v1/resources/tree").json()["items"]}
    assert "tryhackme.com" in left                                                          # also in Cyber / Training: kept


def test_folder_validation_and_permissions(authed):
    assert authed.post("/api/v1/resources/folders", json={"name": ""}).status_code == 422
    assert authed.post("/api/v1/resources/folders", json={"name": "x" * 121}).status_code == 422
    assert authed.post("/api/v1/resources/folders", json={"name": "x", "parent_id": 999999}).status_code == 404
    assert authed.post("/api/v1/resources/folders/999999/items", json={"resource_ids": [1]}).status_code == 404
    fid = authed.post("/api/v1/resources/folders", json={"name": "<b>bold</b>"}).json()["id"]     # stored as text, shown as text
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r", "scope": "read"}).json()["token"]}
    csrf = authed.headers.pop("X-CSRF-Token")
    cookies = dict(authed.cookies)
    authed.cookies.clear()
    try:
        assert authed.get("/api/v1/resources/tree", headers=read).status_code == 200
        for method, path, payload in (("post", "/api/v1/resources/folders", {"name": "y"}), ("patch", f"/api/v1/resources/folders/{fid}", {"name": "z"}),
                                      ("delete", f"/api/v1/resources/folders/{fid}", None), ("post", f"/api/v1/resources/folders/{fid}/items", {"resource_ids": [1]})):
            kw = {"headers": read} | ({"json": payload} if payload is not None else {})
            assert getattr(authed, method)(path, **kw).status_code == 403, path
    finally:
        authed.headers["X-CSRF-Token"] = csrf
        authed.cookies.update(cookies)


def test_mind_map_relations(authed):
    """🧠 "Goes well with" between two folders: stored once per pair (a < b), note kept as text, gone with the folder."""
    mk = lambda name: authed.post("/api/v1/resources/folders", json={"name": name}).json()["id"]  # noqa: E731
    py, mal, ps = mk("Python"), mk("Malware Analysis"), mk("PowerShell")
    r = authed.post("/api/v1/resources/relations", json={"a": mal, "b": py, "note": "automate triage <i>fast</i>"})
    assert r.status_code == 201 and (r.json()["a"], r.json()["b"]) == tuple(sorted((py, mal)))
    rid = r.json()["id"]
    assert authed.post("/api/v1/resources/relations", json={"a": py, "b": mal}).status_code == 409        # same pair, either order
    assert authed.post("/api/v1/resources/relations", json={"a": py, "b": py}).status_code == 422
    assert authed.post("/api/v1/resources/relations", json={"a": py, "b": 999999}).status_code == 404
    assert authed.post("/api/v1/resources/relations", json={"a": py, "b": ps, "note": "x" * 301}).status_code == 422
    assert authed.post("/api/v1/resources/relations", json={"a": py, "b": ps, "extra": 1}).status_code == 422
    assert authed.patch(f"/api/v1/resources/relations/{rid}", json={"note": "parse samples"}).json()["note"] == "parse samples"
    assert authed.patch("/api/v1/resources/relations/999999", json={"note": "x"}).status_code == 404
    rel = authed.get("/api/v1/resources/relations").json()["relations"]
    assert [x["note"] for x in rel if x["id"] == rid] == ["parse samples"]
    ps_rel = authed.post("/api/v1/resources/relations", json={"a": ps, "b": py}).json()["id"]
    assert authed.delete(f"/api/v1/resources/folders/{ps}").status_code == 200                            # folder gone → its connections too
    assert ps_rel not in [x["id"] for x in authed.get("/api/v1/resources/relations").json()["relations"]]
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r2", "scope": "read"}).json()["token"]}
    csrf = authed.headers.pop("X-CSRF-Token")
    cookies = dict(authed.cookies)
    authed.cookies.clear()
    try:
        assert authed.get("/api/v1/resources/relations", headers=read).status_code == 200
        assert authed.post("/api/v1/resources/relations", headers=read, json={"a": py, "b": mal}).status_code == 403
        assert authed.patch(f"/api/v1/resources/relations/{rid}", headers=read, json={"note": "y"}).status_code == 403
        assert authed.delete(f"/api/v1/resources/relations/{rid}", headers=read).status_code == 403
    finally:
        authed.headers["X-CSRF-Token"] = csrf
        authed.cookies.update(cookies)
    assert authed.delete(f"/api/v1/resources/relations/{rid}").status_code == 200
    assert authed.delete(f"/api/v1/resources/relations/{rid}").status_code == 404


def test_resource_summary(authed):
    """A short "what it's for / what you get" summary: saved as text, searchable, in the tree, length-capped."""
    authed.post("/api/v1/resources/batch", json={"lines": ["OverTheWire | https://overthewire.org/wargames/"]})
    rid = authed.get("/api/v1/resources?q=overthewire").json()["items"][0]["id"]
    s = "Wargames that teach the Linux shell <b>level by level</b>. Expect: Bandit first."
    assert authed.patch(f"/api/v1/resources/{rid}", json={"summary": s}).json()["summary"] == s
    assert [r["id"] for r in authed.get("/api/v1/resources?q=Bandit").json()["items"]] == [rid]          # search covers it
    assert next(i for i in authed.get("/api/v1/resources/tree").json()["items"] if i["id"] == rid)["summary"] == s
    assert authed.patch(f"/api/v1/resources/{rid}", json={"summary": "x" * 601}).status_code == 422
    assert authed.patch(f"/api/v1/resources/{rid}", json={"summary": ""}).json()["summary"] == ""


def test_folder_repo_links(authed):
    """📦 Repos from the Repos tab linked to a Resources topic: listed per folder, searchable, removable, skipped when gone."""
    from app.db import get_db, now
    with get_db() as db:
        rid = db.execute("INSERT INTO repos (full_name, owner, name, description, added_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                         ("EricZimmerman/evtx", "EricZimmerman", "evtx", "C# based evtx parser <b>x</b>", now(), now())).lastrowid
        doc = db.execute("INSERT INTO repos (full_name, owner, name, description, kind, url, added_at, updated_at) VALUES (?, ?, ?, ?, 'doc', ?, ?, ?)",
                         ("doc:abc", "doc", "abc", "GitHub Docs › Getting started with Git", "https://docs.github.com/x", now(), now())).lastrowid
    fid = authed.post("/api/v1/resources/folders", json={"name": "Digital Forensics"}).json()["id"]
    assert authed.post(f"/api/v1/resources/folders/{fid}/repos", json={"repo_ids": [rid, doc, rid]}).json()["changed"] == 2
    assert authed.post(f"/api/v1/resources/folders/{fid}/repos", json={"repo_ids": [rid]}).json()["changed"] == 0     # once per folder
    out = authed.get("/api/v1/resources/repos").json()
    assert sorted(x[1] for x in out["links"] if x[0] == fid) == sorted([rid, doc])
    view = {r["id"]: r for r in out["repos"]}
    assert view[rid]["url"] == "https://github.com/EricZimmerman/evtx" and view[rid]["description"].startswith("C# based")
    assert view[doc]["title"].startswith("GitHub Docs") and view[doc]["url"] == "https://docs.github.com/x"
    assert [r["id"] for r in authed.get("/api/v1/resources/repo-search?q=evtx").json()["items"]] == [rid]
    assert authed.get("/api/v1/resources/repo-search?q=" + "x" * 101).status_code == 422
    assert authed.post(f"/api/v1/resources/folders/{fid}/repos", json={"repo_ids": [999999]}).status_code == 404
    assert authed.post("/api/v1/resources/folders/999999/repos", json={"repo_ids": [rid]}).status_code == 404
    assert authed.post(f"/api/v1/resources/folders/{fid}/repos", json={"repo_ids": []}).status_code == 422
    assert authed.post(f"/api/v1/resources/folders/{fid}/repos", json={"repo_ids": [rid], "action": "remove"}).json()["changed"] == 1
    with get_db() as db:                                        # removed in the Repos tab → drops out of the topic…
        db.execute("DELETE FROM repos WHERE id = ?", (doc,))
    assert authed.get("/api/v1/resources/repos").json()["links"] == []
    with get_db() as db:                                        # …and comes back when it's added again (with a new id)
        db.execute("INSERT INTO repos (full_name, owner, name, added_at, updated_at) VALUES ('other/x', 'other', 'x', ?, ?)", (now(), now()))
        new_doc = db.execute("INSERT INTO repos (full_name, owner, name, description, kind, url, added_at, updated_at) VALUES (?, ?, ?, ?, 'doc', ?, ?, ?)",
                             ("DOC:ABC", "doc", "abc", "GitHub Docs › Getting started with Git", "https://docs.github.com/x", now(), now())).lastrowid
    assert new_doc != doc and authed.get("/api/v1/resources/repos").json()["links"] == [[fid, new_doc]]
    read = {"Authorization": "Bearer " + authed.post("/api/v1/tokens", json={"name": "r3", "scope": "read"}).json()["token"]}
    csrf = authed.headers.pop("X-CSRF-Token")
    cookies = dict(authed.cookies)
    authed.cookies.clear()
    try:
        assert authed.get("/api/v1/resources/repos", headers=read).status_code == 200
        assert authed.post(f"/api/v1/resources/folders/{fid}/repos", headers=read, json={"repo_ids": [rid]}).status_code == 403
    finally:
        authed.headers["X-CSRF-Token"] = csrf
        authed.cookies.update(cookies)
    assert authed.delete(f"/api/v1/resources/folders/{fid}").status_code == 200   # folder gone → its repo links too


def test_auto_file_into_topics(authed, monkeypatch):
    """New links land in the topic folders that fit them (same website, folder words, categories, training type), the page's
    own title / description are used when read (simulated here - no network), and "add here" puts links in that folder."""
    from app import resources as res
    mk = lambda name, parent=None: authed.post("/api/v1/resources/folders", json={"name": name, **({"parent_id": parent} if parent else {})}).json()["id"]  # noqa: E731
    dfir = mk("DFIR & Malware Analysis")
    df = mk("Digital Forensics", dfir)
    off = mk("Offensive Security")
    learn = mk("Learn & Practice")
    wg = mk("Wargames & CTFs", learn)
    # a link already filed in Digital Forensics → another page from the same site follows it there
    authed.post("/api/v1/resources/batch", json={"lines": ["https://forensicsite.example/kape"], "folder_id": df})
    r = authed.post("/api/v1/resources/batch", json={"lines": ["Registry tips | https://forensicsite.example/registry"]}).json()
    assert r["results"][0]["folders"] == ["DFIR & Malware Analysis › Digital Forensics"]
    # its category (offensive) → Offensive Security
    r = authed.post("/api/v1/resources/batch", json={"lines": ["Reverse shell cheat sheet | https://shells.example/rev"]}).json()
    assert any("Offensive Security" in f for f in r["results"][0]["folders"])
    # a wargame (training type) → Learn & Practice › Wargames & CTFs
    r = authed.post("/api/v1/resources/batch", json={"lines": ["OverTheWire wargames | https://overthewire.org/wargames/"]}).json()
    assert "Learn & Practice › Wargames & CTFs" in r["results"][0]["folders"]
    # "add here": an explicit folder wins, and a link that's already here is filed there too
    r = authed.post("/api/v1/resources/batch", json={"lines": ["https://forensicsite.example/registry"], "folder_id": wg}).json()
    assert r["duplicates"] == 1 and r["placed"] == 1
    # read the page: its title and description are used (simulated page_info, nothing fetched)
    calls = []
    monkeypatch.setattr(res, "page_info", lambda url, ua, timeout=10: calls.append(url) or {"title": "Memory Forensics Handbook",
                                                                                             "description": "Learn volatility <b>memory</b> forensics."})
    r = authed.post("/api/v1/resources/batch", json={"lines": ["https://newsite.example/mem"], "read_pages": True}).json()
    row = r["results"][0]
    assert r["pages_read"] == 1 and calls == ["https://newsite.example/mem"] and row["title"] == "Memory Forensics Handbook"
    assert "DFIR & Malware Analysis › Digital Forensics" in row["folders"]
    item = authed.get("/api/v1/resources?q=Handbook").json()["items"][0]
    assert item["summary"].startswith("Learn volatility memory forensics.") and "<b>" not in item["summary"]
    # pages are read only for new links, at most READ_PAGES_MAX per batch
    calls.clear()
    authed.post("/api/v1/resources/batch", json={"lines": [f"https://bulk.example/{i}" for i in range(30)] + ["https://newsite.example/mem"], "read_pages": True})
    assert len(calls) == 20 and "https://newsite.example/mem" not in calls
    assert authed.post("/api/v1/resources/batch", json={"lines": ["https://x.example/"], "folder_id": 999999}).status_code == 404
    assert off and dfir
