"""🔗 Resources tab: your websites, training platforms, courses, labs, cheat sheets, tools and docs - imported from your
browser's bookmark export (or pasted) and sorted into categories (offensive, defensive, DFIR, threat intel…) and a type
(course, labs, CTF, cheat sheet, tool…), so the right material is one click away.

* Sorting is by keyword rules on the bookmark folder trail (the strongest hint: your own folders), the title and the
  address. A link can be in up to three categories. Anything you change by hand (``manual``) is never re-sorted.
* Bookmark files are parsed with the standard-library HTML parser (no scripts, entities not expanded, size-capped).
  Only http / https links are kept; credentials in links are dropped; text is stored without markup.
* Nothing here makes an outbound request: titles come from the bookmark, or from the address when there is none.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from app import netguard
from app.db import now
from app.sanitize import to_text

# built-in starter categories: key, name, emoji, colour (order = position). Rename, recolour, delete or add your own.
CATEGORIES: list[tuple[str, str, str, str]] = [
    ("offensive", "Offensive security", "⚔️", "#dc2626"),
    ("redteam", "Red teaming", "🟥", "#b91c1c"),
    ("defensive", "Defensive security", "🛡️", "#2563eb"),
    ("blueteam", "Blue team & SOC", "🟦", "#1d4ed8"),
    ("purple", "Purple (both sides)", "🟪", "#7c3aed"),
    ("cti", "Threat intelligence", "🕵️", "#0f766e"),
    ("malware", "Malware analysis", "🦠", "#65a30d"),
    ("dfir", "DFIR & forensics", "🔬", "#0891b2"),
    ("maldev", "Malware development", "🧪", "#9f1239"),
    ("scripting", "Scripting", "📜", "#ca8a04"),
    ("coding", "Coding", "💻", "#4f46e5"),
    ("appsec", "AppSec & web", "🧱", "#ea580c"),
    ("cloud", "Cloud", "☁️", "#0ea5e9"),
    ("networking", "Networking", "🌐", "#0284c7"),
    ("linux", "Linux & operating systems", "🐧", "#a16207"),
    ("otics", "OT / ICS", "🏭", "#78716c"),
    ("osint", "OSINT & recon", "🔎", "#059669"),
    ("privacy", "Privacy & anonymity", "🕶️", "#475569"),
    ("hardware", "Hardware & Flipper", "🐬", "#f97316"),
    ("homelab", "Homelab", "🏠", "#16a34a"),
    ("careers", "Certs & careers", "🎓", "#6d28d9"),
    ("grc", "GRC, standards & policy", "📋", "#64748b"),
    ("news", "News & blogs", "📰", "#334155"),
]
KINDS: dict[str, str] = {
    "course": "Courses & training", "platform": "Training platforms", "labs": "Labs & ranges", "ctf": "CTFs & wargames",
    "cheatsheet": "Cheat sheets", "docs": "Docs, references & standards", "tool": "Tools", "repo": "Code repositories",
    "blog": "News & blogs", "video": "Videos", "community": "People & communities", "site": "Websites",
}
TRAINING_KINDS = ("course", "platform", "labs", "ctf", "cheatsheet")
MAX_IMPORT_BYTES = 5 * 1024 * 1024
MAX_IMPORT_ITEMS = 10_000
MAX_CATS_PER_LINK = 3

# ---------------------------------------------------------------- sorting rules
# (category, words in your folder names, words in the title / address); every match counts, folder matches first.
CATEGORY_RULES: list[tuple[str, list[str], list[str]]] = [
    ("maldev", ["maldev", "malware dev"], ["maldev", "malware development", "maldev academy", "rat collection", "av evasion", "shellter"]),
    ("malware", ["malware analysis"], ["malware analysis", "remnux", "flare-vm", "flare vm", "malwarebazaar", "virusshare", "malware traffic", "malware-traffic",
                                       "reverse engineering", "crackmes", "vx underground", "malwareunicorn", "objective-see", "malcore", "virussign",
                                       "malware village", "opensourcemalware", "malware trends", "malware sample"]),
    ("dfir", ["digital forensics", "forensics", "dfir", "sleuth", "sift", "sysinternals", "windows event logs", "sysmon", "useful logs", "ez"],
     ["forensic", "forensics", "dfir", "kape", "eric zimmerman", "ez tools", "registry explorer", "autopsy", "sleuth kit", "volatility", "sift workstation",
      "shimcache", "amcache", "security log event", "event id", "sysmon", "exiftool", "hayabusa", "incident response", "cyber triage", "evtx",
      "digital evidence", "swgde", "utmp", "plaso", "velociraptor"]),
    ("otics", ["ot/ics", "ics", "scada", "labshock", "grfics", "ics pcap"], ["scada", "modbus", "dnp3", "iec 61850", "purdue", "62443", "pipedream",
                                                                              "industroyer", "triton", "havex", "dragos", "labshock", "grfics", "conpot",
                                                                              "industrial control", "ics security", "ics/ot", "ot/ics", "scadahacker"]),
    ("cti", ["cti", "actors", "attacks/ttps", "standards formats", "vendor"], ["threat intelligence", "threat intel", "stix", "taxii", "misp", "otx",
                                                                               "threatfox", "greynoise", "unit42", "unit 42", "talos", "hudson rock", "isac",
                                                                               "threat exchange", "hacktivist", "threatfeeds", "analyst1", "maltiverse",
                                                                               "spamhaus", "internet storm center", "exploit database", "exploit-db"]),
    ("osint", ["osint", "recon", "reconnaissance", "enumeration"], ["osint", "shodan", "fofa", "whatsmyname", "maltego", "crt.sh",
                                                                                          "subdomain", "censys", "have i been pwned", "osintleak", "data leak"]),
    ("redteam", ["red team", "redteam", "redteam-pentesting"], ["red team", "red teaming", "redteam", "adversary emulation", "cobalt strike"]),
    ("purple", ["purple"], ["purple team", "purple academy", "attackiq", "atomic red team"]),
    ("blueteam", ["blue team", "blueteam", "soc", "siem", "siem-soar", "threat hunting", "ms sentinel", "elastic stack",
                  "honeypots", "yara", "iocs", "waf", "lolbins", "blueteam-soc"],
     ["blue team", "soc analyst", "siem", "soar", "sentinel", "splunk", "kibana", "logstash", "winlogbeat", "filebeat", "graylog", "wazuh",
      "security onion", "zeek", "suricata", "threat hunting", "letsdefend", "blue team labs", "cyberchef", "virustotal", "abuseipdb", "urlscan",
      "helk", "lolbins", "honeypot", "cowrie", "yara", "openioc", "modsecurity", "crs", "metadefender", "ipqs", "talos file reputation"]),
    ("defensive", ["defensive security", "defensive", "email security", "security keys"],
     ["defensive", "defence", "defense", "hardening", "dmarc", "dkim", "spf", "backup", "sdelete", "cipher.exe", "data breach detection"]),
    ("appsec", ["app/web security", "owasp", "bug bounty", "mobile top 10"], ["owasp", "appsec", "devsecops", "bug bounty", "hackerone", "bugcrowd",
                                                                               "intigriti", "portswigger", "web security academy", "burp", "api security",
                                                                               "apisec", "juice shop", "secure coding", "checkmarx", "snyk", "bsimm",
                                                                               "samm", "mobile application security", "mastg", "masvs"]),
    ("offensive", ["offensive security", "exploitation", "privilege escalation", "reverse shell", "vulnerable machines", "metasploit", "password cracking",
                   "wifi", "android for hackers", "pentesting gadgets", "proxies", "exploits", "ad-windows exploit", "mac for hackers", "web scraping",
                   "social engineering", "reconnaissance/enumeration"],
     ["pentest", "penetration testing", "pentester", "exploit", "exploitation", "privilege escalation", "reverse shell", "metasploit", "gtfobins",
      "lolbas", "hacktricks", "payloadsallthethings", "internal all the things", "null byte", "hacking articles", "kali", "nethunter", "aircrack",
      "john the ripper", "gobuster", "vulnhub", "dirty cow", "dirtycow", "oscp", "offsec", "ethical hacking", "hackers-arise", "pentestmonkey",
      "pentest book", "sn1per", "pentester land", "hacker101", "hack the box", "tryhackme", "overthewire", "wargames",
      "pwn.college", "picoctf", "root-me", "root me", "hack this site", "smashthestack", "underthewire", "vulnmachines", "hackxpert"]),
    ("hardware", ["flipper", "esp32", "unleashed", "momentum", "roguemaster", "xtreme", "ghostesp", "sdr"],
     ["flipper", "esp32", "esp8266", "marauder", "ghostesp", "rfid", "nfc", "ntag", "subghz", "hak5", "o.mg", "proxmark", "pcpartpicker", "motherboard",
      "graphics card", "keyboard switch"]),
    ("homelab", ["home lab", "homelab", "nas", "servers", "proxmox", "pfsense", "opnsense", "firewall", "virtualisation", "switches",
                 "nextcloud", "security onion", "zeek", "wazuh", "elk"],
     ["homelab", "home lab", "home server", "proxmox", "pfsense", "opnsense", "truenas", "unraid", "synology", "nextcloud", "pi-hole", "heimdall",
      "server rack", "netgate", "ubiquiti", "openvpn", "virtualbox", "hyper-v", "portainer", "protectli", "openwrt"]),
    ("privacy", ["anon", "dark web", "proton", "password manager", "gpg4win", "keepassxc", "bitwarden"],
     ["privacy", "anonymity", "anonymous", "tor browser", "proton", "yubikey", "nitrokey", "keepass", "bitwarden", "browserleaks", "leak test",
      "authenticator", "privacy guides", "privacyaffairs", "privacy affairs", "dark web", "wasabi", "bisq", "gpg", "veracrypt", "passkey", "torguard"]),
    ("networking", ["networking", "network", "ssh", "ha"], ["networking", "tcp", "osi model", "routing protocol", "wireshark",
                                                                                       "tcpdump", "pcap", "ssh", "ethernet", "computer networking", "tls",
                                                                                       "failover", "mx lookup", "traceroute", "nslookup"]),
    ("linux", ["linux", "kali", "parrot os", "distros", "shells", "dual booting - live usb", "live usb", "vm", "gui (de/dm)"],
     ["linux", "ubuntu", "debian", "fedora", "centos", "red hat", "parrot", "blackarch", "pentoo", "wsl", "zsh", "korn", "tcsh", "distro", "selinux",
      "rufus", "ventoy", "man7", "kali linux", "virtualbox", "distrowatch", "lightdm", "gdm3"]),
    ("scripting", ["scripting", "powershell", "ps scripting", "maintain", "commands", "winget"], ["powershell", "bash scripting", "scripting", "winget",
                                                                                                 "pstools", "cmdlet", "ss64"]),
    ("coding", ["coding", "c/c++", "python", "ide", "platforms"], ["python", "c++", "cplusplus", "cppreference", "javascript", "golang", "leetcode",
                                                                   "hackerrank", "pycharm", "visual studio code", "pypi", "programming", "w3schools",
                                                                   "learncpp", "pythontutor", "zed", "learn python"]),
    ("cloud", ["cloud", "cloud/storage/remoteconnection", "providers"], ["cloud security", "azure", "aws", "gcp", "google cloud", "iaas", "paas",
                                                                         "saas", "wiz", "orca security", "prisma cloud", "kubernetes"]),
    ("careers", ["certs-courses-training", "all certs", "career/roadmap", "jobs",
                 "redteam-pentesting certs", "blueteam-soc certs"],
     ["certification", "certifications", "comptia", "security+", "cissp", "isc2", "giac", "ccna", "ccnp", "pearson vue", "careers", "career",
      "roadmap", "job details", "jobs", "cyberseek", "pen-200", "pen-300", "exp-301", "web-300", "web-200", "pen-210"]),
    ("grc", ["governance", "grc", "frameworks", "standards", "nist", "fips", "business",
             "iam", "ttx", "guide/standard/framework", "ics standards", "standards/guides"],
     ["nist", "iso 27001", "essential eight", "cis controls", "center for internet security", "pci", "gdpr", "privacy principles", "soci",
      "compliance", "governance", "risk management", "fips", "sp 800", "d3fend", "mitre att&ck", "attack.mitre", "cyber security strategy",
      "oaic", "tabletop exercise", "ciso", "c2m2", "execution standard", "maturity model", "csrc"]),
    ("news", ["news", "tech_news"],
     ["news", "krebs", "the hacker news", "bleepingcomputer", "the record", "dark reading", "securityweek", "wired", "the register", "techcrunch",
      "cybernews", "infosecurity magazine", "csoonline", "cso online", "hackread", "security affairs", "zdnet", "newsletter", "magazine", "substack",
      "databreachtoday", "it security guru", "esecurity planet", "cyber daily"]),
]
KIND_RULES: list[tuple[str, list[str], list[str]]] = [
    ("ctf", ["ctf"], ["ctf", "capture the flag", "wargame", "wargames", "overthewire", "picoctf", "smashthestack", "underthewire", "hack this site",
                      "ctftime", "crackmes", "cryptohack"]),
    ("labs", ["machines/labs/ctfs", "vulnerable machines", "labs", "labshock", "grfics"], ["vulnhub", "cyber range", "rangeforce", "blue team labs",
                                                                                           "vulnmachines", "labs.", "malware-traffic-analysis", "lab", "labs",
                                                                                           "pentesterlab", "juice shop", "dojo", "hackviser", "barracks"]),
    ("platform", [], ["tryhackme", "hack the box", "hackthebox", "letsdefend", "pwn.college", "root me", "root-me", "hacker101", "try2hack",
                           "cybrary", "coursera", "antisyphon", "picus", "attackiq", "metactf", "yeswehack", "boson", "class central"]),
    ("course", ["training", "certs-courses-training", "all certs", "redteam-pentesting certs", "blueteam-soc certs"],
     ["course", "courses", "training", "academy", "tutorial", "tutorials", "unleashed", "lessons", "bootcamp", "university", "pathway",
      "certification", "certified", "comptia", "security+", "cissp", "giac", "ccna", "pen-200", "pen-300", "linux journey",
      "learn python", "learning path", "learn to"]),
    ("cheatsheet", ["cheat", "reverse shell"], ["cheat sheet", "cheatsheet", "cheatsheets", "gtfobins", "lolbas", "hacktricks", "payloadsallthethings",
                                                "internal all the things", "ss64", "explainshell", "explain command"]),
    ("video", [], ["youtube.com", "youtu.be", "- youtube", "vimeo.com"]),
    ("repo", [], ["github.com/", "gitlab.com/", "codeberg.org/"]),
    ("community", ["channels", "youtube", "podcasts"],
     ["linkedin.com", "| linkedin", "discord", "reddit.com", "twitter.com", "podcast", "darknet diaries", "community", "forum", "meetup"]),
    ("blog", ["news", "tech_news"], ["news", "blog", "magazine", "newsletter", "krebs",
                                                                                                "bleepingcomputer", "the hacker news", "dark reading",
                                                                                                "wired", "substack", "medium.com", "securelist"]),
    ("docs", ["standards", "frameworks", "guide/standard/framework", "standards formats", "ics standards", "fips", "nist", "documentation",
              "useful logs", "windows event logs", "standards/guides"],
     ["documentation", "docs", "reference", "wiki", "manual", "guide", "handbook", "event id", "security log event", "man page", "learn.microsoft.com",
      "encyclopedia", "standard", "framework", "nist", "fips", "sp 800", "stix version", "mitre att&ck", "d3fend", "owasp top 10", "62443",
      "essential eight", "maturity model"]),
    ("tool", ["tools", "password manager", "remote access", "antivirus", "proxies", "keepassxc", "bitwarden", "gpg4win"],
     ["tool", "tools", "download", "cyberchef", "virustotal", "shodan", "wireshark", "nmap", "burp", "ghidra", "keepass", "putty", "winscp", "rufus",
      "ventoy", "exiftool", "urlscan", "abuseipdb", "scanner", "generator", "lookup", "checker", "parser", "detection tool"]),
]


def _pat(words: list[str]) -> re.Pattern | None:
    words = [w for w in words if w]
    if not words:
        return None
    def one(w: str) -> str:   # word edges only where the word itself starts / ends with a letter or digit ("github.com/" too)
        return ((r"(?<![a-z0-9])" if w[0].isalnum() else "") + re.escape(w) + (r"(?![a-z0-9])" if w[-1].isalnum() else ""))
    alts = sorted((one(w.lower()) for w in words), key=len, reverse=True)
    return re.compile("(?:" + "|".join(alts) + ")")


_CAT = [(k, _pat(f), _pat(t)) for k, f, t in CATEGORY_RULES]
_KIND = [(k, _pat(f), _pat(t)) for k, f, t in KIND_RULES]


def _folders(trail: str) -> list[str]:
    return [p.strip().lower().replace("_", " ") for p in re.split(r"\s*/\s*", trail or "") if p.strip()]


def classify(title: str, url: str, trail: str = "") -> tuple[list[str], str]:
    """(category keys - best first, up to three; kind) for one link. ``trail`` = its bookmark folders, e.g.
    "Cyber / Defensive Security / Digital Forensics" - the innermost folder is the strongest hint."""
    folders = _folders(trail)
    text = f"{(title or '').lower()} {url.lower()}"
    cats: list[str] = []
    for folder in reversed(folders):                  # innermost folder first
        for key, fp, _ in _CAT:
            if fp is not None and fp.search(folder) and key not in cats:
                cats.append(key)
    for key, _, tp in _CAT:
        if tp is not None and tp.search(text) and key not in cats:
            cats.append(key)
    kind = "site"
    for folder in reversed(folders):
        hit = next((k for k, fp, _ in _KIND if fp is not None and fp.search(folder)), None)
        if hit:
            kind = hit
            break
    title_kind = next((k for k, _, tp in _KIND if tp is not None and tp.search(text)), None)
    if title_kind in ("video", "repo", "ctf", "cheatsheet") or (kind == "site" and title_kind):
        kind = title_kind                             # what the link itself is beats a generic folder
    return cats[:MAX_CATS_PER_LINK], kind


# ---------------------------------------------------------------- links
def clean_url(raw: str) -> str | None:
    """An http(s) link without credentials, or None. Never fetched."""
    s = (raw or "").strip()
    if not s or len(s) > netguard.MAX_URL_LENGTH:
        return None
    try:
        parts = urlsplit(s)
        port = parts.port
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        return None
    netloc = parts.hostname.lower() + (f":{port}" if port else "")
    return urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, parts.fragment))


def url_key(url: str) -> str:
    """Same page whatever the scheme, "www.", trailing slash or #fragment (for spotting duplicates)."""
    p = urlsplit(url)
    host = (p.hostname or "").lower().removeprefix("www.")
    path = p.path.rstrip("/") or "/"
    return f"{host}{path}?{p.query}" if p.query else f"{host}{path}"


def host_of(url: str) -> str:
    return (urlsplit(url).hostname or "").lower().removeprefix("www.")


def tidy_title(title: str, url: str) -> str:
    t = to_text(title or "", 300)
    t = re.sub(r"^\(\d+\)\s*", "", t)              # "(312) Talk - YouTube": notification counters dropped
    if not t or t.lower() in ("just a moment...", "untitled", "new tab"):
        p = urlsplit(url)
        t = (p.hostname or "").removeprefix("www.") + (p.path.rstrip("/") if p.path not in ("", "/") else "")
    return t[:300]


# ---------------------------------------------------------------- bookmark files and pasted lines
class _Bookmarks(HTMLParser):
    """Netscape bookmark files (what browsers export): <DT><H3>folder</H3><DL>…</DL> and <DT><A HREF=… ADD_DATE=…>title</A>."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.path: list[str] = []
        self.pending: str | None = None
        self.stack: list[bool] = []
        self.in_h3 = self.in_a = False
        self.href = ""
        self.added: int | None = None
        self.text = ""
        self.items: list[dict[str, Any]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "h3":
            self.in_h3, self.text = True, ""
        elif tag == "a":
            a = dict(attrs)
            self.in_a, self.text, self.href = True, "", a.get("href") or ""
            d = a.get("add_date") or ""
            self.added = int(d) if d.isdigit() and 0 < int(d) < 2**40 else None
        elif tag == "dl":
            opened = self.pending is not None
            if opened:
                self.path.append(self.pending)
            self.stack.append(opened)
            self.pending = None

    def handle_endtag(self, tag: str) -> None:
        if tag == "h3" and self.in_h3:
            self.in_h3 = False
            self.pending = to_text(self.text, 120) or "Folder"
        elif tag == "a" and self.in_a:
            self.in_a = False
            if len(self.items) < MAX_IMPORT_ITEMS:
                path = self.path[1:] if self.path and self.path[0].strip().lower() in BROWSER_ROOTS else self.path
                self.items.append({"url": self.href, "title": self.text, "trail": " / ".join(p.replace(" / ", " - ") for p in path),
                                   "bookmarked_at": self.added, "order": len(self.items)})
        elif tag == "dl" and self.stack:
            if self.stack.pop() and self.path:
                self.path.pop()

    def handle_data(self, data: str) -> None:
        if self.in_h3 or self.in_a:
            self.text += data


# folders every browser puts at the top of an export (not folders you made)
BROWSER_ROOTS = {"bookmarks bar", "bookmarks toolbar", "bookmarks menu", "other bookmarks", "mobile bookmarks", "favorites bar",
                 "favourites bar", "other favorites", "other favourites", "bookmarks", "favorites", "favourites"}

_MD_LINK = re.compile(r"\[([^\]]{0,300})\]\((https?://[^)\s]{1,2048})\)")
_BARE = re.compile(r"https?://[^\s<>\"'|]{1,2048}")


def parse_bookmarks(content: str) -> list[dict[str, Any]]:
    """Links from a browser bookmark export (HTML). Falls back to a plain list (one link per line, "title | link",
    "title - link" or Markdown [title](link)) when the content isn't a bookmark file."""
    if len(content.encode("utf-8", "ignore")) > MAX_IMPORT_BYTES:
        raise ValueError("That file is too big (5 MB at most).")
    if re.search(r"<dt>\s*<a\s", content[:300_000], re.I) or "NETSCAPE-Bookmark-file" in content[:500]:
        p = _Bookmarks()
        p.feed(content)
        p.close()
        return p.items
    return parse_lines(content.splitlines()[:MAX_IMPORT_ITEMS * 2], keep_headings=True)


def parse_lines(lines: list[str], keep_headings: bool = False) -> list[dict[str, Any]]:
    """Pasted lines: "address", "title | address", "title - address" or Markdown. With ``keep_headings`` a short line
    without a link is read as a folder heading for the lines under it. Lines without a link are reported as invalid."""
    out: list[dict[str, Any]] = []
    trail = ""
    for raw in lines:
        line = (raw or "").strip()
        if not line:
            continue
        md = _MD_LINK.findall(line)
        if md:
            out += [{"url": u, "title": t, "trail": trail, "line": line} for t, u in md]
            continue
        bare = _BARE.findall(line)
        if bare:
            title = _BARE.sub("", line).strip(" -–|:\t")
            out += [{"url": u, "title": title, "trail": trail, "line": line} for u in bare]
            continue
        if keep_headings and len(line) <= 60 and " | " not in line and " - " not in line:
            trail = line
        else:
            out.append({"url": "", "title": line, "trail": trail, "line": line})   # no link: reported, not stored
    return out


# ---------------------------------------------------------------- categories and storing
def seed_categories(db) -> dict[str, int]:
    """Create the built-in starter categories once (a deleted one stays deleted). Returns {key: id} of those present."""
    if not db.execute("SELECT 1 FROM sync_state WHERE key = 'resource_categories_seeded'").fetchone():
        for pos, (key, name, emoji, color) in enumerate(CATEGORIES, start=1):
            if not db.execute("SELECT 1 FROM resource_categories WHERE key = ? OR name = ?", (key, name)).fetchone():
                db.execute("INSERT INTO resource_categories (key, name, emoji, color, position, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                           (key, name, emoji, color, pos, now()))
        db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('resource_categories_seeded', '1')")
    return {r[0]: r[1] for r in db.execute("SELECT key, id FROM resource_categories WHERE key IS NOT NULL")}


def folder_for(db, trail: str, cache: dict[str, int]) -> int | None:
    """The id of the folder for a bookmark trail ("Cyber / Training / CTF"), creating the folders that are missing."""
    parts = [p.strip()[:120] for p in (trail or "").split(" / ") if p.strip()][:12]
    if not parts:
        return None
    parent: int | None = None
    path = ""
    for i, name in enumerate(parts):
        path = f"{path} / {name}" if path else name
        if path in cache:
            parent = cache[path]
            continue
        row = db.execute("SELECT id FROM resource_folders WHERE name = ? AND parent_id IS ?", (name, parent)).fetchone()
        if row is None:
            pos = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM resource_folders WHERE parent_id IS ?", (parent,)).fetchone()[0]
            fid = db.execute("INSERT INTO resource_folders (parent_id, name, position, created_at) VALUES (?, ?, ?, ?)",
                             (parent, name, pos, now())).lastrowid
        else:
            fid = row[0]
        cache[path] = fid
        parent = fid
    return parent


def place(db, folder_id: int, resource_id: int) -> bool:
    pos = db.execute("SELECT COALESCE(MAX(position), 0) + 1 FROM resource_folder_items WHERE folder_id = ?", (folder_id,)).fetchone()[0]
    return db.execute("INSERT OR IGNORE INTO resource_folder_items (folder_id, resource_id, position) VALUES (?, ?, ?)",
                      (folder_id, resource_id, pos)).rowcount > 0


def store(db, items: list[dict[str, Any]], cats: dict[str, int], category_id: int | None = None,
          folders: bool = False, target_folder: int | None = None, auto_file: bool = False,
          pages: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    """Save links (sorted automatically; ``category_id`` = also put them in that category). Duplicates are reported.
    ``folders``: recreate each link's bookmark folders and put it there - a link bookmarked in two folders goes in both,
    and a link that's already here is also filed into its folder.
    ``target_folder``: put every link (new or already here) in that folder. ``auto_file``: file new links into the topic
    folders that fit them best (suggest_folders). ``pages``: what each page says about itself (page_info), used for the
    title, the sorting and the starter "what it's for"."""
    have = {url_key(r[0]): r[1] for r in db.execute("SELECT url, id FROM resources")}
    results, added, dupes, invalid, placed = [], 0, 0, 0, 0
    fcache: dict[str, int] = {}
    index = _folder_index(db) if auto_file and not target_folder else None
    t = now()
    for it in items:
        url = clean_url(it.get("url") or "")
        label = it.get("line") or it.get("url") or it.get("title") or ""
        if url is None:
            invalid += 1
            results.append({"line": label[:300], "status": "invalid", "detail": "No http(s) link on this line."})
            continue
        key = url_key(url)
        if key in have:
            dupes += 1
            if target_folder and place(db, target_folder, have[key]):
                placed += 1
            if folders:
                fid = folder_for(db, it.get("trail") or "", fcache)
                if fid and place(db, fid, have[key]):
                    placed += 1
            results.append({"line": label[:300], "status": "duplicate", "id": have[key]})
            continue
        info = (pages or {}).get(url) or {}
        typed = (it.get("title") or "").strip()
        title = tidy_title(typed if typed and typed != url else info.get("title") or typed, url)
        desc = info.get("description", "")
        trail = to_text(it.get("trail") or "", 500)
        keys, kind = classify(f"{title} {desc}".strip(), url, trail)
        rid = db.execute("INSERT INTO resources (url, title, host, kind, trail, bookmarked_at, added_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (url, title, host_of(url), kind, trail, it.get("bookmarked_at"), t, t)).lastrowid
        cids = [cats[k] for k in keys if k in cats]
        if category_id:
            cids = [category_id, *[c for c in cids if c != category_id]]
        db.executemany("INSERT OR IGNORE INTO resource_category_items (category_id, resource_id) VALUES (?, ?)", [(c, rid) for c in cids])
        have[key] = rid
        added += 1
        filed: list[int] = []
        if folders:
            fid = folder_for(db, trail, fcache)
            if fid and place(db, fid, rid):
                placed += 1
                filed.append(fid)
        if target_folder:
            if place(db, target_folder, rid):
                placed += 1
            filed.append(target_folder)
        elif auto_file and index is not None:
            for fid in suggest_folders(db, title, url, kind, desc, keys, index):
                if place(db, fid, rid):
                    placed += 1
                    filed.append(fid)
        names = [" › ".join(_path_of(db, f)) for f in filed]
        if pages is not None or auto_file or target_folder:   # a starter "what it's for" for links added by hand
            db.execute("UPDATE resources SET summary = ? WHERE id = ? AND summary = ''",
                       (default_summary(title, host_of(url), kind, names[0] if names else "", desc), rid))
        results.append({"line": label[:300], "status": "added", "id": rid, "title": title, "kind": kind, "categories": cids, "folders": names})
    return {"added": added, "duplicates": dupes, "skipped": dupes + invalid, "invalid": invalid, "placed": placed,
            "folders_made": len(set(fcache.values())), "results": results}


# ============================================================================ 📖 read a page + 🗂 file it into topics
PAGE_MAX = 512 * 1024
_GENERIC_HOSTS = {"github.com", "gist.github.com", "gitlab.com", "youtube.com", "youtube-nocookie.com", "youtu.be", "linkedin.com",
                  "medium.com", "reddit.com", "duckduckgo.com", "google.com", "en.wikipedia.org", "stackoverflow.com", "superuser.com",
                  "askubuntu.com", "serverfault.com", "learn.microsoft.com", "docs.github.com", "amazon.com.au", "amazon.com", "x.com",
                  "twitter.com", "facebook.com", "docs.google.com", "drive.google.com", "archive.org"}
_STOP = {"and", "the", "for", "with", "security", "tools", "tool", "guides", "guide", "resources", "other", "general", "more",
         "your", "all", "learning", "practice", "sites", "site", "programs", "ads", "boards", "non", "cyber", "topic", "notes", "here",
         "what", "how", "best", "free", "online", "page", "home", "official", "docs", "documentation"}
# your categories → the topic folder (path) they belong under
CATEGORY_FOLDER = {
    "offensive": "Offensive Security", "redteam": "Offensive Security", "maldev": "Offensive Security/Malware Development & Evasion",
    "hardware": "Offensive Security/Hardware Hacking & Flipper", "defensive": "Defensive Security & SOC", "blueteam": "Defensive Security & SOC",
    "purple": "Defensive Security & SOC", "dfir": "DFIR & Malware Analysis/Digital Forensics", "malware": "DFIR & Malware Analysis/Malware Analysis",
    "cti": "Threat Intelligence & OSINT", "osint": "Threat Intelligence & OSINT/OSINT", "appsec": "Web & App Security",
    "cloud": "Cloud Security & Platforms", "networking": "Networking", "linux": "Linux, Windows & Virtualisation/Linux",
    "otics": "OT/ICS Security", "privacy": "Privacy, Identity & Encryption", "grc": "GRC, Frameworks & Standards",
    "homelab": "Home Lab", "careers": "Learn & Practice/Careers & Roadmaps", "news": "Daily Check & News/News Sites",
    "scripting": "Learn & Practice/Scripting & Coding", "coding": "Learn & Practice/Scripting & Coding",
}
KIND_FOLDER = {"ctf": "Learn & Practice/Wargames & CTFs", "labs": "Learn & Practice/Hands-on Platforms", "platform": "Learn & Practice/Hands-on Platforms",
               "course": "Learn & Practice/Courses by Topic", "cheatsheet": "Learn & Practice/Cheat Sheets & Quick Reference"}


def _meta_tag(page: str, key: str) -> str:
    for pat in (rf'<meta[^>]+(?:property|name)=["\']{re.escape(key)}["\'][^>]*content=["\']([^"\']*)["\']',
                rf'<meta[^>]+content=["\']([^"\']*)["\'][^>]*(?:property|name)=["\']{re.escape(key)}["\']'):
        m = re.search(pat, page, re.I)
        if m:
            return m.group(1)
    return ""


def page_info(url: str, user_agent: str, timeout: float = 10.0) -> dict[str, str]:
    """The page's own title and description (what a link preview shows) - fetched through netguard (SSRF guard, size and
    time limits) with the app's honest User-Agent. A login wall, an error or a non-HTML answer just gives {}."""
    try:
        resp = netguard.request("GET", url, headers={"User-Agent": user_agent, "Accept": "text/html"}, timeout=timeout, max_bytes=PAGE_MAX)
    except (netguard.FetchError, netguard.UnsafeURLError, ValueError):
        return {}
    if resp.status_code >= 400 or "html" not in (resp.headers.get("content-type") or ""):
        return {}
    page = resp.content[:PAGE_MAX].decode("utf-8", "replace")
    m = re.search(r"<title[^>]*>(.*?)</title>", page, re.I | re.S)
    title = to_text(_meta_tag(page, "og:title") or (m.group(1) if m else ""), 300)
    desc = to_text(_meta_tag(page, "og:description") or _meta_tag(page, "description") or _meta_tag(page, "twitter:description"), 400)
    return {k: v for k, v in (("title", title), ("description", desc)) if v}


def _tokens(text: str) -> set[str]:
    out = set()
    for w in re.findall(r"[a-z0-9]+", (text or "").lower()):
        if len(w) < 3 or w in _STOP:
            continue
        out.add(w[:-1] if len(w) > 4 and w.endswith("s") else w)
    return out


def _folder_index(db) -> dict[str, Any]:
    rows = {r[0]: (r[1], r[2]) for r in db.execute("SELECT id, parent_id, name FROM resource_folders")}

    def path(fid):
        out = []
        while fid:
            out.append(rows[fid][1])
            fid = rows[fid][0]
        return list(reversed(out))
    paths = {fid: path(fid) for fid in rows}
    by_path = {"/".join(p): fid for fid, p in paths.items()}
    hosts: dict[str, dict[int, int]] = {}
    for host, fid in db.execute("SELECT r.host, i.folder_id FROM resource_folder_items i JOIN resources r ON r.id = i.resource_id"):
        hosts.setdefault(host, {}).setdefault(fid, 0)
        hosts[host][fid] += 1
    return {"paths": paths, "by_path": by_path, "hosts": hosts, "tokens": {fid: _tokens(p[-1]) for fid, p in paths.items()}}


def suggest_folders(db, title: str, url: str, kind: str, text: str, cat_keys: list[str], index: dict[str, Any] | None = None,
                    limit: int = 2) -> list[int]:
    """The best topic folders for a link, from: other links from the same website, words of a folder's name in the title /
    description / address, its categories and its type (training goes under Learn & Practice too). [] when nothing fits."""
    ix = index or _folder_index(db)
    paths, by_path = ix["paths"], ix["by_path"]
    words = _tokens(f"{title} {text} {urlsplit(url).path}")
    host = host_of(url)
    score: dict[int, float] = {}

    def add(fid, pts):
        if fid:
            score[fid] = score.get(fid, 0) + pts

    if host and host not in _GENERIC_HOSTS:                   # where links from this website already live
        for fid, n in sorted(ix["hosts"].get(host, {}).items(), key=lambda kv: -kv[1])[:3]:
            add(fid, 3 + min(n, 4) * 0.5)
    for fid, toks in ix["tokens"].items():                    # a folder's own name in the link's words
        hit = toks & words
        if hit:
            add(fid, 3 * len(hit) / max(len(toks), 1) + 0.3 * (len(paths[fid]) - 1))
    tops = {by_path[CATEGORY_FOLDER[k]] for k in cat_keys if CATEGORY_FOLDER.get(k) in by_path}
    for k in cat_keys:                                        # its categories: the mapped folder, and a nudge for its branch
        fid = by_path.get(CATEGORY_FOLDER.get(k, ""))
        add(fid, 3)
    for fid, p in paths.items():
        if any(p[:len(paths[t])] == paths[t] for t in tops) and fid not in tops:
            add(fid, 1) if fid in score else None
    if kind in KIND_FOLDER:                                   # training: also under Learn & Practice
        add(by_path.get(KIND_FOLDER[kind]), 3.5)
    else:                                                     # not training: keep Learn & Practice for learning material
        for fid, p in paths.items():
            if p[0] == "Learn & Practice" and fid in score:
                score[fid] -= 1.5
    for fid, p in paths.items():                              # personal folders only on a clear match
        if p[0] == "Personal & Business" and fid in score:
            score[fid] -= 2
    ranked = [fid for fid, s in sorted(score.items(), key=lambda kv: (-kv[1], -len(paths[kv[0]]))) if s >= 3]
    chosen: list[int] = []
    for fid in ranked:
        p = paths[fid]
        if any(paths[c][:len(p)] == p or p[:len(paths[c])] == paths[c] for c in chosen):
            continue                                          # not a folder and its own parent / child
        if chosen and (score[fid] < 0.8 * score[chosen[0]] or p[0] == paths[chosen[0]][0]):
            continue                                          # a second home only if nearly as good, in another topic
        chosen.append(fid)
        if len(chosen) >= limit:
            break
    return chosen


_KIND_EXPECT = {"course": ("Course", "structured lessons you can work through"), "platform": ("Platform", "a learning or practice platform you sign in to"),
                "labs": ("Labs", "hands-on lab exercises"), "ctf": ("Challenges", "challenges to practise with"),
                "cheatsheet": ("Cheat sheet", "a quick reference to keep open while you work"), "docs": ("Reference", "documentation to look things up in"),
                "tool": ("Tool", "a tool or service you use directly"), "repo": ("Code repository", "the code, readme and releases"),
                "blog": ("Article", "something to read: news, analysis or a write-up"), "video": ("Video", "a video to watch"),
                "community": ("Community page", "posts and updates to follow"), "site": ("Website", "a site to visit for this topic")}


def default_summary(title: str, host: str, kind: str, folder: str = "", description: str = "") -> str:
    """A starter "what it's for": the page's own description when there is one, else built from the title, type and folder."""
    label, expect = _KIND_EXPECT.get(kind, _KIND_EXPECT["site"])
    if description:
        return to_text(f"{description} (Filed under {folder}.)" if folder else description, 600)
    where = f" Filed under {folder}." if folder else ""
    return to_text(f"{label}: {title} ({host}).{where} Expect: {expect}.", 600)


def _path_of(db, fid: int) -> list[str]:
    out = []
    while fid:
        row = db.execute("SELECT parent_id, name FROM resource_folders WHERE id = ?", (fid,)).fetchone()
        if not row:
            break
        out.append(row[1])
        fid = row[0]
    return list(reversed(out))


def reclassify(db) -> int:
    """Sort again every link whose categories you haven't set yourself (built-in categories and type only)."""
    cats = seed_categories(db)
    builtin = set(cats.values())
    n = 0
    for r in db.execute("SELECT id, url, title, trail FROM resources WHERE manual = 0").fetchall():
        keys, kind = classify(r["title"], r["url"], r["trail"])
        if builtin:
            db.execute(f"DELETE FROM resource_category_items WHERE resource_id = ? AND category_id IN ({','.join('?' * len(builtin))})",  # nosec B608
                       (r["id"], *builtin))
        db.executemany("INSERT OR IGNORE INTO resource_category_items (category_id, resource_id) VALUES (?, ?)",
                       [(cats[k], r["id"]) for k in keys if k in cats])
        db.execute("UPDATE resources SET kind = ? WHERE id = ?", (kind, r["id"]))
        n += 1
    return n
