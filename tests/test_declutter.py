"""Ad / site-promotion clean-up of article bodies (app/declutter.py)."""

from app import declutter
from app.db import get_db, now
from app.sanitize import sanitize_html

OWN = frozenset({"news.example"})
STORY = ("<p>Researchers found a flaw in a widely used router that lets an attacker run commands without logging in.</p>"
         "<p>The vendor published a fix on Tuesday and asks customers to install it as soon as they can.</p>")


def cleaned(html, **kw):
    return declutter.clean(sanitize_html(html), own_sites=kw.pop("own", OWN), **kw)


def test_fixed_rules_remove_promotion_and_keep_the_story():
    promo = ('<p>The post <a href="https://news.example/a">Router flaw</a> appeared first on <a href="https://news.example">News</a>.</p>'
             '<p><strong>Follow me on Twitter: </strong><a href="https://twitter.com/x">@x</a> and <a href="https://facebook.com/x">Facebook</a></p>'
             '<p><a href="https://news.example/buy">Try it free →</a></p>'
             '<h2>Daily Debrief Newsletter</h2><p>Advertisement</p>'
             "<div>Buyer's Guide: <a href=\"https://buy.news.example/#r\">Router (Buy Now)</a></div>"
             '<p>Power up with unlimited access. Subscribe Today.</p>'
             '<img src="https://ad.doubleclick.net/x.gif" width="300" height="250"><img src="https://news.example/p.gif" width="1" height="1">')
    html, n = cleaned(STORY + promo)
    assert n == 9
    assert html == STORY


def test_ordinary_sentences_with_the_same_words_are_kept():
    body = (STORY + '<p>The company told customers in its newsletter that people who subscribe to the paid tier and follow the '
            'hardening guide on <a href="https://docs.other.example/guide">its documentation site</a> are not affected, and that '
            'anyone can sign up for the beta programme to try the fix early before it reaches every customer next month.</p>'
            '<h2>Get started</h2><p>Comments from the vendor were not available.</p>'
            '<p>Source: <a href="https://other.example/report">The Guardian</a></p>')
    html, n = cleaned(body)
    assert n == 0 and html == sanitize_html(body)


def test_footer_after_a_line_break_is_found_and_plain_text_is_untouched():
    html, n = cleaned('Apple is working on a new phone, the report says, with a thinner design and a better camera.'
                      '<div>Related Roundup: <a href="https://news.example/r">Phone</a></div><br>'
                      'This article, "<a href="https://news.example/a">New phone</a>" first appeared on <a href="https://news.example">News</a><br><br>'
                      '<a href="https://forums.news.example/t">Discuss this article</a> in our forums')
    assert n == 2 and "first appeared" not in html and "Discuss" not in html and "thinner design" in html and "Related Roundup" in html
    plain = "Just one sentence of summary text without any markup at all."
    assert declutter.clean(plain) == (plain, 0)


def test_repeated_block_needs_an_outside_link_or_a_promotion_cue():
    ad = '<p><strong>Give your SOC the alert context.</strong> <a href="https://vendor.example/?utm_source=news&amp;utm_campaign=w26">Integrate Threat Intel from 16K SOCs</a>.</p>'
    advice = '<p>Refer to <a href="https://news.example/tips">our standing advice</a> for more information on avoiding scams.</p>'
    more = "<p>Customers who cannot update yet should switch off remote management until they can, the vendor says.</p>"
    body = STORY + advice + more + ad          # the advice is inside the story, the ad closes it
    rep = frozenset(declutter.signatures(sanitize_html(ad + advice)))
    html, n = cleaned(body, repeated=rep)
    assert n == 1 and "16K SOCs" not in html and "standing advice" in html
    assert cleaned(body)[1] == 0                                        # not repeated in the feed: kept
    assert cleaned(body, repeated=rep, own=frozenset())[1] == 0         # site unknown: nothing is "outside"


def test_tail_of_a_multi_part_ad_goes_with_it():
    tail = ('<h3>Something feel off? Check it before you click.</h3><p>Scam Guard helps you analyse suspicious links instantly.</p>'
            '<p><a href="https://news.example/scam-guard">Try it free →</a></p>')
    rep = frozenset(declutter.signatures(sanitize_html(STORY + tail)))
    html, n = cleaned(STORY + tail, repeated=rep - frozenset(declutter.signatures(sanitize_html(STORY))))
    assert n == 3 and html == STORY
    # repeated closing blocks WITHOUT promotion (a standing legal notice) stay
    legal = "<h3>Legal notice</h3><p>This product is provided subject to the notification and privacy policy.</p>"
    assert cleaned(STORY + legal, repeated=frozenset(declutter.signatures(sanitize_html(STORY + legal))))[1] == 0


def _feed():
    with get_db() as db:
        return db.execute("INSERT INTO feeds (title, url, site_url, created_at) VALUES ('News', 'https://news.example/rss', 'https://news.example', ?)",
                          (now(),)).lastrowid


def _article(db, fid, i, html):
    return db.execute("INSERT INTO articles (feed_id, guid, url, title, content_html, text_content, fetched_at, sort_ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (fid, f"g{i}", f"https://news.example/{i}", f"Story {i}", html, declutter.to_text(html), now(), now() + i)).lastrowid


def test_feed_learns_its_repeated_ad_and_stored_articles_are_cleaned_once(client):
    fid = _feed()
    ad = '<p>Protect every endpoint today. <a href="https://vendor.example/edr?utm_campaign=q4-push">See how Vendor EDR stops ransomware</a>.</p>'
    with get_db() as db:
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (fid,)).fetchone()
        first = [_article(db, fid, i, sanitize_html(f"<p>Unique paragraph number {'x' * i} about incident {i} with enough words.</p>" + ad)) for i in range(2)]
        assert declutter.clean_new(db, feed, first) == 0               # seen twice: not yet "repeated"
        third = [_article(db, fid, 5, sanitize_html("<p>Another unique paragraph, about a third and different incident.</p>" + ad))]
        assert declutter.clean_new(db, feed, third) == 1
        assert "Vendor EDR" not in db.execute("SELECT text_content FROM articles WHERE id = ?", (third[0],)).fetchone()[0]
        assert "Vendor EDR" in db.execute("SELECT content_html FROM articles WHERE id = ?", (first[0],)).fetchone()[0]
    assert declutter.rebuild() == {"articles": 3, "changed": 2}        # the two stored before the feed had learned it
    with get_db() as db:
        assert not db.execute("SELECT 1 FROM articles WHERE content_html LIKE '%Vendor EDR%'").fetchone()
        assert db.execute("SELECT 1 FROM articles_fts WHERE articles_fts MATCH 'incident'").fetchone()
        assert not db.execute("SELECT 1 FROM articles_fts WHERE articles_fts MATCH 'ransomware'").fetchone()
        assert db.execute("SELECT value FROM sync_state WHERE key = 'declutter_rev'").fetchone()[0] == declutter.REV
    assert declutter.ensure_current() is False                          # done for this rule revision


def test_there_is_no_switch_and_an_old_stored_value_is_ignored(authed):
    assert authed.patch("/api/v1/settings", json={"strip_promos": False}).status_code == 422      # not a setting any more
    with get_db() as db:
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('strip_promos', 'false')")  # left by an earlier version
        assert declutter.enabled(db) is True
    assert "strip_promos" not in authed.get("/api/v1/settings").json()
    fid = _feed()
    html = sanitize_html(STORY + '<p><a href="https://news.example/buy">Buy now</a></p>')
    with get_db() as db:
        feed = db.execute("SELECT * FROM feeds WHERE id = ?", (fid,)).fetchone()
        aid = _article(db, fid, 1, html)
        assert declutter.clean_new(db, feed, [aid]) == 1


def test_output_is_still_sanitised_markup():
    dirty = sanitize_html(STORY + '<p><a href="https://news.example/x" onclick="x()">Try it free</a></p><script>alert(1)</script>')
    html, n = declutter.clean(dirty, own_sites=OWN)
    assert n == 1 and sanitize_html(html) == html and "script" not in html


def test_outside_link_without_campaign_needs_a_large_share_and_advisory_lines_stay():
    cwe = '<p>Relevant CWE: <a href="https://cwe.other.example/306">CWE-306 Missing Authentication for Critical Function</a></p>'
    more = "<p>Customers who cannot update yet should switch off remote management until they can, the vendor says.</p>"
    rep = frozenset(declutter.signatures(sanitize_html(cwe)))
    assert cleaned(STORY + cwe + more, repeated=rep)[1] == 0            # repeated, links out, but no campaign link
    html, n = cleaned(STORY + cwe + more, repeated=rep, common=rep)      # in a third of the feed's articles: a placement
    assert n == 1 and "CWE-306" not in html
    once = '<p><a href="https://other.example/report.pdf">Download the full report</a></p>'
    assert cleaned(STORY + once)[1] == 0                                # the article's own link
    assert cleaned(STORY + once, repeated=frozenset(declutter.signatures(sanitize_html(once))))[1] == 1


def test_rotating_ad_text_is_caught_by_where_its_campaign_link_leads():
    def ad(words):
        return f'<p>{words} <a href="https://vendor.example/feeds/?utm_source=news&amp;utm_campaign=w1#sales">Integrate our feeds</a>.</p>'
    learned = frozenset(declutter.signatures(sanitize_html(ad("First wording of the placement, never seen again."))))
    html, n = cleaned(STORY + ad("A brand new wording that no other article has carried so far."), repeated=learned)
    assert n == 1 and "vendor.example" not in html
    own_link = '<p>Read our earlier coverage <a href="https://news.example/feeds/?utm_source=rss">of the same flaw</a> for the background.</p>'
    assert cleaned(STORY + own_link, repeated=frozenset(declutter.signatures(sanitize_html(own_link))))[1] == 0   # the site's own link


def test_hostile_markup_is_cheap_and_left_alone():
    import time

    deep = "<div>" * 15000 + '<p><a href="https://news.example/x">Buy now</a></p>' + "</div>" * 15000
    wide = STORY + "<p><span></span></p>" * 8000 + '<p><a href="https://news.example/x">Buy now</a></p>'
    start = time.monotonic()
    for html in (deep, wide, "<" * 200000):
        declutter.signatures(html)
        declutter.clean(html, own_sites=OWN)
    assert time.monotonic() - start < 6
    assert declutter.clean("<div>" * 25000 + "x" + "</div>" * 25000)[1] == 0      # over the cost guard: untouched


# ------------------------------------------------------------------ REV 2 (2026-11-26)
def test_paid_placement_box_goes_with_its_heading_and_sales_lines():
    paid = "https://vendor.example/lp/scan?utm_source=display_network&utm_medium=paid_display&utm_campaign=q4"
    box = (f'<div><div><a href="{paid}"><img alt="ad" src="https://cdn.news.example/ad.jpg"></a></div>'
           f'<div><h2><a href="{paid}">Uncover email threats your defenses miss.</a></h2>'
           '<p>Vendor agents analyze email intent to uncover phishing and invoice fraud.</p>'
           f'<p>See what gets through with a 14-day scan.</p><a href="{paid}">Start your free scan.</a></div></div>')
    inline = ('<p><strong>Give your SOC the context it needs -&gt; <a href="https://sandbox.example/ti?utm_medium=link+placement">'
              'Integrate Threat Intel</a></strong>:</p>')
    html, n = cleaned(STORY + box + "<h3>Related Articles:</h3>" + inline)
    assert n >= 2 and "Vendor agents" not in html and "Threat Intel" not in html and "14-day" not in html
    assert "Researchers found a flaw" in html and "The vendor published a fix" in html


def test_editorial_links_with_ordinary_campaign_tags_stay():
    body = STORY + '<p>Details are in <a href="https://other.example/report?utm_source=twitter&utm_medium=social">the report</a>.</p>'
    html, n = cleaned(body)
    assert n == 0 and "the report" in html


def test_paid_link_inside_a_short_summary_never_takes_the_whole_article():
    body = ('<div><p>A short summary of the story, a few lines long.</p>'
            '<p><a href="https://vendor.example/x?utm_medium=sponsored">Sponsored: try Vendor</a></p></div>')
    html, n = cleaned(body)
    assert n == 1 and "short summary" in html and "Vendor" not in html


def test_disclosures_paywall_and_audio_player_go():
    pic = ('<p><img src="https://news.example/mac.jpg" width="800" height="400"><em><small>Note: News is an affiliate partner with '
           'some of these vendors. When you click a link and make a purchase, we may receive a small payment.</small></em></p>')
    body = ('<div><div><p>Listen to this article</p><p></p></div><div><span>0:00</span></div><div>Speed</div>'
            '<p>Press play to start listening</p></div>' + STORY + pic +
            "<div><div>You’re out of free articles for this month</div><div>To continue reading the rest of this article, please log in.</div></div>"
            '<p>When you purchase through links in our articles, we may earn a small commission. This doesn’t affect our editorial independence.</p>')
    html, n = cleaned(body)
    assert "mac.jpg" in html, "the picture stays, only the disclosure goes"
    for gone in ("affiliate partner", "free articles", "please log in", "small commission", "Listen to this article", "Press play"):
        assert gone not in html
    assert "Researchers found a flaw" in html


def test_closing_product_plug_after_the_last_rule():
    plug = ('<hr><p><strong>From reporting threats to removing them.</strong></p>'
            '<p>Keep threats off your devices by <a href="https://news.example/for-home">downloading Vendor today</a>.</p>')
    html, n = cleaned(STORY + "<p>" + "More of the story. " * 20 + "</p>" + plug)
    assert n == 2 and "downloading Vendor" not in html and "<hr" not in html and "More of the story" in html
    notes = '<hr><p>Acknowledgements: thanks to <a href="https://other.example/team">the research team</a>.</p>'
    html, n = cleaned(STORY + notes)
    assert n == 0 and "Acknowledgements" in html                      # no download / install link: not a plug


def test_rev2_is_idempotent_and_keeps_long_paragraphs():
    long_para = ("<p>The lawsuit says affiliates may earn a commission on every sale and that the company hid this from "
                 + "buyers for years, " * 12 + "according to the filing.</p>")
    html, n = cleaned(STORY + long_para)
    assert n == 0
    once, _ = cleaned(STORY + '<p>Add on Google</p><p>[link] [comments]</p>')
    again, n2 = declutter.clean(once, own_sites=OWN)
    assert "Add on Google" not in once and "[link]" not in once and n2 == 0 and again == once
