"""Keyword topics across all sources (powers the YouTube library now and the topic hub later).

A topic is a name plus keywords; an article belongs to a topic when its title or text contains
one of the keywords as a whole word (case-insensitive). Built-in topics are seeded once and can
be edited, disabled or deleted; user topics are added in the library. Keywords are escaped into a
regex, so user input is never interpreted as a pattern.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import Counter

from app.db import get_db, placeholders

log = logging.getLogger("feedwarden.topics")

MAX_TOPICS = 100
TEXT_SCAN = 4000
MAX_KEYWORDS = 100  # per topic
# Precision rules. Video descriptions are mostly links, sponsors and channel boilerplate, so a video gets a topic only
# when its title matches. An article gets it when the title matches, or the topic's words appear at least twice
# in the opening of the text (one passing mention is not enough).
ARTICLE_LEAD = 800
ARTICLE_MIN_HITS = 2

BUILTIN: list[tuple[str, str, list[str]]] = [
    ("Vulnerabilities & exploits", "#dc2626", ["cve", "zero-day", "0day", "0-day", "exploit", "exploitation", "rce",
                                              "remote code execution", "proof of concept", "poc", "patch tuesday",
                                              "vulnerability", "vulnerabilities"]),
    ("Malware analysis", "#9333ea", ["malware", "reverse engineering", "reversing", "ghidra", "ida pro", "x64dbg",
                                     "yara", "unpacking", "decompile", "infostealer", "stealer", "loader", "trojan",
                                     "backdoor", "rootkit", "botnet"]),
    ("Ransomware", "#b91c1c", ["ransomware", "lockbit", "blackcat", "alphv", "akira", "clop", "extortion",
                               "double extortion", "data leak site"]),
    ("Web security", "#2563eb", ["xss", "cross-site scripting", "sql injection", "sqli", "ssrf", "csrf", "idor",
                                 "burp suite", "owasp", "web app", "web application", "deserialization", "xxe",
                                 "path traversal", "request smuggling", "php", "wordpress", "webshell", "web shell"]),
    ("Bug bounty", "#0891b2", ["bug bounty", "hackerone", "bugcrowd", "intigriti", "yeswehack", "responsible disclosure"]),
    ("Red team & pentesting", "#ea580c", ["red team", "red teaming", "pentest", "pentesting", "penetration test",
                                          "penetration testing", "privilege escalation", "privesc", "active directory",
                                          "kerberoasting", "kerberos", "cobalt strike", "sliver", "c2", "lateral movement",
                                          "hack the box", "hackthebox", "htb", "tryhackme", "oscp", "evasion"]),
    ("Blue team & DFIR", "#16a34a", ["incident response", "forensics", "dfir", "siem", "threat hunting", "detection engineering",
                                     "splunk", "sigma", "edr", "xdr", "soc", "blue team", "memory forensics", "volatility",
                                     "velociraptor", "log analysis"]),
    ("Threat intelligence", "#ca8a04", ["apt", "threat actor", "threat intel", "threat intelligence", "nation-state",
                                        "state-sponsored", "ioc", "iocs", "campaign", "espionage", "lazarus", "apt28",
                                        "apt29", "volt typhoon", "salt typhoon"]),
    ("Cloud & containers", "#0284c7", ["aws", "azure", "gcp", "google cloud", "kubernetes", "k8s", "docker", "container",
                                       "cloud security", "iam", "s3 bucket", "entra id", "serverless", "terraform"]),
    ("AI security", "#7c3aed", ["llm", "llms", "large language model", "prompt injection", "jailbreak", "ai security",
                                "artificial intelligence", "machine learning", "genai", "generative ai", "chatgpt",
                                "openai", "claude", "gemini", "copilot", "agentic", "ai agent", "ai agents",
                                "mcp server", "deepfake", "model poisoning", "adversarial"]),
    ("CTF & learning", "#db2777", ["ctf", "capture the flag", "picoctf", "writeup", "walkthrough", "tutorial",
                                   "beginner", "course", "learn", "roadmap", "certification", "career", "interview"]),
    ("OSINT & privacy", "#4f46e5", ["osint", "privacy", "reconnaissance", "recon", "surveillance", "spyware",
                                    "pegasus", "geolocation", "doxxing", "tracking"]),
    ("Hardware, IoT & radio", "#65a30d", ["hardware hacking", "iot", "firmware", "embedded", "uart", "jtag", "flipper zero",
                                          "sdr", "software defined radio", "rfid", "nfc", "bluetooth", "car hacking",
                                          "ics", "scada", "ot security"]),
    ("Mobile security", "#0d9488", ["android", "ios", "iphone", "mobile security", "apk", "frida", "mobile malware"]),
    ("Phishing & fraud", "#d97706", ["phishing", "smishing", "vishing", "scam", "fraud", "social engineering",
                                     "business email compromise", "bec", "credential harvesting", "crypto scam"]),
    ("Network security", "#475569", ["firewall", "vpn", "network security", "wireshark", "nmap", "ddos", "dns",
                                     "zero trust", "fortinet", "palo alto", "cisco", "ivanti", "citrix"]),
]


# v2 (2026-11): words the built-in topics were missing - about a quarter of videos matched no topic at all
# (e.g. "a worm moved through npm", "Amazon CloudFront", "Stuxnet", "JWT", "DEF CON badge", "self-hosted AI").
TOPIC_ADDITIONS: dict[str, list[str]] = {
    "Bug bounty": ["bugbounty", "bugbountytip", "bug bounties", "bounty", "hall of fame"],
    "Vulnerabilities & exploits": ["bug", "bugs", "flaw", "flaws", "patch", "patched", "security update", "kev"],
    "Malware analysis": ["worm", "worms", "wiper", "keylogger", "rat", "supply chain", "supply-chain", "npm", "pypi",
                         "malicious package", "malicious packages", "stuxnet", "virus", "viruses", "payload"],
    "Web security": ["jwt", "oauth", "api security", "graphql", "cookies", "session hijacking", "authentication bypass",
                     "browser", "browsers", "chrome extension", "cors"],
    "Red team & pentesting": ["hacking", "ethical hacking", "ethical hacker", "kali", "kali linux", "metasploit",
                              "exploit development", "adversary emulation", "purple team"],
    "Blue team & DFIR": ["detection", "defender", "wazuh", "security onion", "elastic", "monitoring", "logs",
                         "threat detection", "security operations"],
    "Threat intelligence": ["threat report", "hacktivist", "hacktivists", "cyber war", "cyberwar", "cyber warfare",
                            "attribution", "threat landscape"],
    "Cloud & containers": ["cloud", "cloudfront", "ec2", "lambda", "amazon web services", "microsoft 365", "m365",
                           "okta", "entra", "cloudflare", "devops", "devsecops", "ci/cd", "github actions", "saas"],
    "CTF & learning": ["free course", "for beginners", "lab", "labs"],  # career/study/explainer words: own topics since v3
    "OSINT & privacy": ["data broker", "data brokers", "anonymity", "tor", "metadata", "facial recognition"],
    "Hardware, IoT & radio": ["hardware", "wifi", "wi-fi", "wireless", "radio", "antenna", "lora", "zigbee", "badge",
                              "pcb", "soldering", "arduino", "raspberry pi", "esp32", "plc", "plcs", "stuxnet",
                              "industrial", "triton", "industroyer", "csi"],
    "Mobile security": ["smartphone", "smartphones", "samsung", "pixel", "sim swap", "sms"],
    "Phishing & fraud": ["scams", "scammer", "scammers", "impersonation", "fake", "romance scam", "pig butchering"],
    "Network security": ["expressvpn", "nordvpn", "protonvpn", "wireguard", "openvpn", "router", "routers", "networking",
                         "network", "subnet", "vlan", "proxy", "tailscale", "pfsense", "opnsense"],
}
NEW_BUILTIN: list[tuple[str, str, list[str]]] = [
    ("AI & machine learning", "#8b5cf6", ["ai", "a.i.", "llm", "llms", "local llm", "ollama", "chatgpt", "openai",
                                          "anthropic", "claude", "gemini", "copilot", "deepseek", "mistral", "llama",
                                          "small models", "ai model", "ai models", "machine learning", "deep learning",
                                          "neural network", "agentic", "ai agent", "ai agents", "self-hosted ai",
                                          "generative ai", "genai", "gpt", "gpt-5", "artificial intelligence"]),
    ("Conferences & talks", "#be185d", ["black hat", "blackhat", "def con", "defcon", "bsides", "rsac", "rsa conference",
                                        "keynote", "conference", "podcast", "livestream", "live stream", "open session", "office hours",
                                        "summit", "village", "fireside chat"]),
    # v3 (2026-11-15): topics for the videos no topic covered (news, careers, certifications, leadership...)
    ("Cyber news", "#f97316", [
        "news", "cyber news", "infosec news", "security news", "weekly news", "headlines", "this week in",
        "week in review", "threat briefing", "briefing", "roundup", "recap", "stormcast", "breaking", "swn",
        "hack naked news", "security now", "newsletter", "news now", "this week", "daily cyber",
        "cyber threat briefing", "threatwire", "cybersec weekly", "what you need to know", "cyber security news",
        "week in cyber",
    ]),
    ("Careers & development", "#14b8a6", [
        "career", "careers", "cybersecurity career", "cyber career", "job", "jobs", "job hunting", "interview",
        "interviews", "resume", "salary", "salaries", "hiring", "entry level", "entry-level", "first job",
        "into cybersecurity", "into cyber", "getting into", "how to become", "roadmap", "mentoring", "mentor",
        "mentors", "mentorship", "day in the life", "college", "degree", "university", "students",
        "imposter syndrome", "burnout", "soft skills", "personal brand", "cyber work", "career change", "job market",
        "internship", "promotion", "work from home", "remote work", "learn cybersecurity", "beginners", "beginner",
        "no experience", "self-taught", "bootcamp", "pivot", "origin story", "it to cybersecurity", "consulting",
        "freelance", "freelancing", "career advice", "how i got",
    ]),
    ("Certifications & study", "#0ea5e9", [
        "comptia", "security+", "a+", "network+", "cysa+", "pentest+", "casp+", "linux+", "ccna", "ccnp", "cissp",
        "ccsp", "cism", "cisa", "oscp", "oscp+", "osep", "oswe", "ceh", "gsec", "giac", "study group", "exam",
        "exams", "exam cram", "certification", "certifications", "cert", "certs", "study guide",
        "practice questions", "practice exam", "sy0-701", "sy0-601", "sy0-501", "sy0-401", "sy0-301", "220-1101",
        "220-1102", "220-1001", "220-1002", "220-901", "220-902", "220-801", "220-802", "220-701", "220-702",
        "220-601", "220-602", "n10-008", "n10-009", "n10-007", "pnpt", "ejpt", "az-900", "az-500", "sc-900",
    ]),
    ("Security leadership & GRC", "#64748b", [
        "ciso", "cisos", "leadership", "leader", "governance", "risk", "risk management", "compliance", "grc",
        "gdpr", "nist", "iso 27001", "soc 2", "audit", "auditing", "budget", "metrics", "security program",
        "security culture", "enterprise security", "business security", "executive", "executives", "vendor risk",
        "third-party risk", "cyber insurance", "regulation", "regulations", "cmmc", "hipaa", "pci dss",
        "security awareness", "bsw", "esw", "resilience", "privacy law", "sec rules", "legislation",
    ]),
    ("AppSec & DevSecOps", "#22c55e", [
        "appsec", "application security", "devsecops", "secure code", "secure coding", "code review", "sast", "dast",
        "sbom", "software security", "threat modeling", "threat model", "shift left", "secure development", "sdlc",
        "ci/cd", "github", "gitlab", "open source security", "software supply chain", "asw", "product security",
        "secure by design", "memory safety", "rust", "security champions", "vulnerability management",
        "pull request", "dependency", "dependencies",
    ]),
    ("Identity, passwords & crypto", "#eab308", [
        "password", "passwords", "passkey", "passkeys", "mfa", "2fa", "multi-factor", "authentication", "identity",
        "identities", "sso", "single sign-on", "credential", "credentials", "encryption", "encrypted",
        "cryptography", "cipher", "hashing", "hash", "hashes", "tls", "ssl", "certificate", "certificates", "pki",
        "post-quantum", "keepass", "bitwarden", "1password", "lastpass", "yubikey", "access control",
        "password manager", "zero knowledge", "end-to-end", "e2ee", "signal",
    ]),
    ("Windows & endpoint", "#3b82f6", [
        "windows", "windows 10", "windows 11", "microsoft", "powershell", "sysinternals", "intune", "endpoint",
        "endpoints", "antivirus", "anti-virus", "bitlocker", "registry", "group policy", "macos", "apple", "chrome",
        "browser", "browsers", "firefox", "antimalware", "security software", "kaspersky", "norton", "bitdefender",
        "malwarebytes", "eset", "avast", "mcafee", "windows defender", "patching",
    ]),
    ("Computer science & explainers", "#a855f7", [
        "computerphile", "explained", "how it works", "how does", "algorithm", "algorithms", "computer science",
        "programming", "coding", "compiler", "cpu", "data structures", "maths", "math", "binary", "unicode",
        "operating system", "quantum computing", "javascript", "c++", "assembly", "golang", "java", "explainer",
    ]),
    ("Gear & setups", "#78716c", [
        "unboxing", "review", "gear", "setup", "desk setup", "keyboard", "keycaps", "gadget", "gadgets",
        "hacking tools", "m5stick", "raspberry pi", "esp32", "what's on my", "budget build", "server rack", "nas",
        "mini pc",
    ]),
    ("Breaches & incidents", "#e11d48", [
        "breach", "breaches", "data breach", "leaked", "leak", "leaks", "hacked", "outage", "outages", "stolen",
        "incident", "incidents", "compromised", "got hacked", "was hacked", "database leaked", "exposed",
        "cyber attack", "cyberattack", "cyberattacks", "takedown", "arrested", "seized", "crowdstrike outage",
    ]),
    ("Crypto & blockchain", "#ca8a04", [
        "crypto", "cryptocurrency", "bitcoin", "ethereum", "blockchain", "nft", "nfts", "web3", "defi", "wallet",
        "wallets", "solana", "binance", "coinbase", "crypto hack", "crypto heist",
    ]),
    ("Podcasts & interviews", "#0891b2", [
        "security weekly", "podcast", "podcasts", "interview", "interviews", "unsupervised learning",
        "cyber insecurity", "infoseclive", "conversation", "a conversation with", "fireside chat", "guest",
        "tea with a hacker", "talkin' bout infosec", "security now", "darknet diaries", "risky business",
    ]),
    ("General", "#94a3b8", []),  # v4: no keywords - the last resort for videos no topic or channel topic fits
]
GENERAL_TOPIC = "General"

# v3 (2026-11-15): words found missing when 46% of videos had no topic. Merged into the built-in topics once.
TOPIC_ADDITIONS_V3: dict[str, list[str]] = {
    "Conferences & talks": [
        "psw", "scw", "talks", "webcast", "webinar", "presentation", "bhis", "talkin' bout infosec", "appsec global",
        "global appsec", "appsec usa", "appsec eu", "bh2015", "bh2016", "bh2017", "bh2018", "bh2019", "bh2020",
        "bh2021", "bh2022", "bh2023", "bh2024", "bh2025", "bh2026", "bhusa", "bheu", "bhasia", "fireside",
        "paul's security weekly", "secure digital life",
        "episode",
    ],
    "CTF & learning": [
        "walkthrough", "walkthroughs", "writeup", "write-up", "proving grounds", "pg-play", "holiday hack",
        "advent of cyber", "vulnhub", "hackthebox",
    ],
    "Vulnerabilities & exploits": [
        "fuzzing", "fuzzer", "afl", "exploit development", "bug", "bugs", "flaw", "flaws", "patch", "patched",
        "security update",
    ],
    "Blue team & DFIR": [
        "backup", "backups", "cis controls", "cis 18", "detecting", "detection", "logging", "logs", "incident",
        "defense", "defenders", "hardening",
    ],
    "Network security": [
        "gns3", "routing", "switching", "ospf", "bgp", "tcp", "tcp/ip", "ip address", "ipv6", "ipv4", "packet",
        "packets", "subnetting", "ethernet", "switch", "switches", "nat", "dhcp", "osi model", "port", "ports",
    ],
    "Linux & Virtualization": [
        "ubuntu", "debian", "arch", "fedora", "linux mint", "terminal", "command line", "shell", "distro", "kernel",
        "proxmox", "vmware", "virtualbox", "virtual machine", "vm", "vms", "gnome", "kde", "systemd",
    ],
    "Red team & pentesting": [
        "ethical hacking", "ethical hacker", "kali", "kali linux", "metasploit", "hashcat", "john the ripper",
        "wordlist", "brute force", "payload", "reverse shell", "exploit dev", "netexec", "crackmapexec",
        "bloodhound", "mimikatz", "responder", "impacket", "hacking", "pwn", "offensive security", "evasion",
    ],
    "OSINT & privacy": [
        "data privacy", "anonymous", "tracked", "tiktok",
    ],
    "Web security": [
        "directory traversal", "command injection", "file upload", "portswigger", "web security academy",
        "authentication bypass",
    ],
    "Phishing & fraud": [
        "crypto scam", "cryptoscams", "scamming", "fraudsters", "deepfake",
    ],
    "Cloud & containers": [
        "cloud security podcast", "saas", "csp", "kubernetes security",
    ],
}
for _name, _words in TOPIC_ADDITIONS_V3.items():
    TOPIC_ADDITIONS[_name] = list(dict.fromkeys([*TOPIC_ADDITIONS.get(_name, []), *_words]))
# v3: words that moved out of a built-in topic into the new ones (removed once from existing installs).
TOPIC_REMOVALS_V3: dict[str, list[str]] = {
    "CTF & learning": ["cybersecurity career", "jobs", "job", "salary", "entry level", "get into cybersecurity", "study",
                       "explained", "how to", "guide", "exam", "exam prep", "study guide", "cryptography", "encryption"],
}
TOPICS_VERSION = 4


def upgrade_builtin(db) -> bool:
    """Once per install: add TOPIC_ADDITIONS to the built-in topics (merged with any words you added; words you
    removed may come back once) and create the NEW_BUILTIN topics. Your own topics are never touched.
    Returns True when something changed (the caller then re-tags all articles)."""
    row = db.execute("SELECT value FROM sync_state WHERE key = 'topics_version'").fetchone()
    if row is not None and int(row["value"] or 0) >= TOPICS_VERSION:
        return False
    changed = False
    for name, gone in (TOPIC_REMOVALS_V3.items() if row is None or int(row["value"] or 0) < 3 else ()):
        r = db.execute("SELECT id, keywords FROM topics WHERE name = ? AND builtin = 1", (name,)).fetchone()
        if r is not None:
            words = json.loads(r["keywords"])
            kept = [w for w in words if w not in set(gone)]
            if kept and kept != words:
                db.execute("UPDATE topics SET keywords = ? WHERE id = ?", (json.dumps(kept), r["id"]))
                changed = True
    for name, extra in TOPIC_ADDITIONS.items():
        r = db.execute("SELECT id, keywords FROM topics WHERE name = ? AND builtin = 1", (name,)).fetchone()
        if r is None:
            continue
        words = json.loads(r["keywords"])
        merged = list(dict.fromkeys([*words, *extra]))[:MAX_KEYWORDS]
        if merged != words:
            db.execute("UPDATE topics SET keywords = ? WHERE id = ?", (json.dumps(merged), r["id"]))
            changed = True
    for name, color, words in NEW_BUILTIN:
        cur = db.execute("INSERT OR IGNORE INTO topics (name, keywords, color, builtin) VALUES (?, ?, ?, 1)",
                         (name, json.dumps(words), color))
        if cur.rowcount:
            changed = True
            continue
        r = db.execute("SELECT id, keywords FROM topics WHERE name = ? AND builtin = 1", (name,)).fetchone()
        if r is not None:  # already there (e.g. an earlier upgrade): merge in any words added since
            have = json.loads(r["keywords"])
            merged = list(dict.fromkeys([*have, *words]))[:MAX_KEYWORDS]
            if merged != have:
                db.execute("UPDATE topics SET keywords = ? WHERE id = ?", (json.dumps(merged), r["id"]))
                changed = True
    db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('topics_version', ?)", (str(TOPICS_VERSION),))
    return changed


def validate_keywords(words: list[str]) -> list[str]:
    out: list[str] = []
    for w in words:
        w = " ".join(str(w).split()).lower()
        if not 1 <= len(w) <= 60:
            raise ValueError("keywords must be 1-60 characters")
        if w not in out:
            out.append(w)
    if not 1 <= len(out) <= MAX_KEYWORDS:
        raise ValueError(f"give 1-{MAX_KEYWORDS} keywords")
    return out


def _pattern(words: list[str]) -> re.Pattern:
    alts = sorted((re.escape(w) for w in words), key=len, reverse=True)
    return re.compile(r"(?<![\w-])(?:" + "|".join(alts) + r")(?![\w-])", re.IGNORECASE)


def seed_builtin(db) -> int:
    """Insert built-in topics once (a deleted built-in stays deleted)."""
    if db.execute("SELECT value FROM sync_state WHERE key = 'topics_seeded'").fetchone():
        return 0
    added = 0
    for name, color, words in [*BUILTIN, *NEW_BUILTIN]:
        words = list(dict.fromkeys([*words, *TOPIC_ADDITIONS.get(name, [])]))[:MAX_KEYWORDS]
        cur = db.execute("INSERT OR IGNORE INTO topics (name, keywords, color, builtin) VALUES (?, ?, ?, 1)",
                         (name, json.dumps(words), color))
        added += cur.rowcount
    db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('topics_seeded', '1')")
    db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES ('topics_version', ?)", (str(TOPICS_VERSION),))
    return added


def _compiled(db) -> list[tuple[int, re.Pattern]]:
    out = []
    for row in db.execute("SELECT id, keywords FROM topics WHERE enabled = 1"):
        try:
            words = json.loads(row["keywords"])
        except ValueError:
            continue
        if words:
            out.append((row["id"], _pattern(words)))
    return out


_CHUNK_SPLIT = re.compile(r"(?<=[.!?:|])\s+|\s+(?=https?://)|\s*[•·|]\s*")
BOILERPLATE_SAMPLE = 40


def _chunks(text: str | None) -> list[str]:
    return [c.strip().lower() for c in _CHUNK_SPLIT.split(text or "") if len(c.strip()) >= 12]


def _boilerplate(db, feed_id: int) -> set[str]:
    """Sentences repeated across a feed's recent items (sponsor blurbs, "follow us" footers, link lists).

    They say nothing about the item itself, so they are ignored when matching topics - otherwise a
    channel whose every description plugs a "SOC / blue team" course tags every video Blue team."""
    rows = db.execute(f"SELECT substr(COALESCE(text_content, ''), 1, {TEXT_SCAN}) FROM articles WHERE feed_id = ? "  # nosec B608 - constant
                      "ORDER BY sort_ts DESC LIMIT ?", (feed_id, BOILERPLATE_SAMPLE)).fetchall()
    if len(rows) < 4:
        return set()
    counts: Counter = Counter()
    for (body,) in rows:
        counts.update(set(_chunks(body)))
    threshold = max(3, int(len(rows) * 0.3))
    return {c for c, n in counts.items() if n >= threshold}


def classify(db, article_ids: list[int], compiled: list[tuple[int, re.Pattern]] | None = None,
             boiler_cache: dict[int, set[str]] | None = None) -> int:
    if not article_ids:
        return 0
    compiled = compiled if compiled is not None else _compiled(db)
    if not compiled:
        return 0
    boiler_cache = boiler_cache if boiler_cache is not None else {}
    fmt = _format_topics(db)   # format topics never given to podcast episodes (looked up once)
    links = 0
    for start in range(0, len(article_ids), 500):
        chunk = article_ids[start:start + 500]
        rows = db.execute(f"SELECT id, feed_id, title, substr(COALESCE(text_content, ''), 1, {TEXT_SCAN}) AS body, "  # nosec B608 - constant
                          "(SELECT kind FROM feeds WHERE feeds.id = articles.feed_id) AS feed_kind, "
                          "EXISTS (SELECT 1 FROM videos v WHERE v.article_id = articles.id) AS is_video, "
                          "(SELECT v.channel_title FROM videos v WHERE v.article_id = articles.id) AS channel "
                          f"FROM articles WHERE id IN ({placeholders(len(chunk))})", chunk).fetchall()
        for row in rows:
            title = row["title"] or ""
            if row["is_video"] and row["channel"]:
                title = f"{title}\n{row['channel']}"  # the channel name counts for videos
            lead = ""
            if not row["is_video"]:
                if row["feed_id"] not in boiler_cache:
                    boiler_cache[row["feed_id"]] = _boilerplate(db, row["feed_id"])
                boiler = boiler_cache[row["feed_id"]]
                body = " ".join(c for c in _chunks(row["body"]) if c not in boiler) if boiler else (row["body"] or "")
                lead = body[:ARTICLE_LEAD]
            matched = False
            for topic_id, pattern in compiled:
                if row["feed_kind"] == "podcast" and topic_id in fmt:
                    continue  # every episode is a podcast / a talk: those topics would say nothing
                if pattern.search(title) or (lead and len(pattern.findall(lead)) >= ARTICLE_MIN_HITS):
                    if not matched:  # a keyword topic replaces a channel / General fallback
                        db.execute("DELETE FROM article_topics WHERE article_id = ? AND source != 'keyword'", (row["id"],))
                        matched = True
                    db.execute("INSERT OR REPLACE INTO article_topics (article_id, topic_id, source) VALUES (?, ?, 'keyword')",
                               (row["id"], topic_id))
                    links += 1
    return links


# Topics about a format, not a subject - a book titled "System Design Interview" is not a podcast.
NOT_FOR_BOOKS = ("Podcasts & interviews", "Conferences & talks", "Cyber news")
NOT_FOR_EPISODES = ("Podcasts & interviews", "Conferences & talks")   # every episode is one; Cyber news fits daily shows


def _format_topics(db) -> set[int]:
    return {r[0] for r in db.execute(f"SELECT id FROM topics WHERE name IN ({placeholders(len(NOT_FOR_EPISODES))})", NOT_FOR_EPISODES)}  # nosec B608


def apply_category_topics(db, article_ids: list[int] | None = None) -> int:
    """A show's own categories add topics too ("Ransomware" → Ransomware), marked source = 'publisher' - rebuilt from
    the stored categories after every re-tag, so a full re-tag doesn't lose them."""
    where = f" WHERE c.article_id IN ({placeholders(len(article_ids))})" if article_ids else ""
    rows = db.execute(f"SELECT c.article_id, group_concat(c.category, ' · ') AS cats FROM episode_categories c{where} "  # nosec B608
                      "GROUP BY c.article_id", article_ids or []).fetchall()
    compiled = [c for c in _compiled(db) if c[0] not in _format_topics(db)]
    links = 0
    for r in rows:
        db.execute("DELETE FROM article_topics WHERE article_id = ? AND source IN ('show', 'general')", (r["article_id"],))  # a real topic now
        for topic_id, pattern in compiled:
            if pattern.search(r["cats"] or ""):
                db.execute("INSERT OR IGNORE INTO article_topics (article_id, topic_id, source) VALUES (?, ?, 'publisher')", (r["article_id"], topic_id))
                links += 1
    return links


def fill_episode_topics(db, article_ids: list[int] | None = None) -> int:
    """Every podcast episode gets a topic: no keyword match → its show's main topic (the topic most of the show's
    matched episodes have), else General. Fallback links are marked source = 'show' / 'general' and go away when a
    keyword matches later. ``article_ids``: only these (new) episodes; None = all, dropping stale fallbacks."""
    if article_ids is not None and not article_ids:
        return 0
    scope, params = "", []
    if article_ids is not None:
        scope = f" AND a.id IN ({placeholders(len(article_ids))})"
        params = list(article_ids)
    else:
        db.execute(f"DELETE FROM article_topics WHERE source = 'show' AND (topic_id NOT IN ({_ENABLED}) OR article_id IN "  # nosec B608
                   f"(SELECT article_id FROM article_topics WHERE source IN ('keyword', 'publisher') AND topic_id IN ({_ENABLED})))")
    untagged = ("NOT EXISTS (SELECT 1 FROM article_topics y JOIN topics ty ON ty.id = y.topic_id AND ty.enabled = 1 "
                "WHERE y.article_id = a.id)")
    main = ("SELECT feed_id, topic_id FROM (SELECT a.feed_id, x.topic_id, ROW_NUMBER() OVER (PARTITION BY a.feed_id ORDER BY COUNT(*) DESC, x.topic_id) AS rn "
            "FROM articles a JOIN feeds f ON f.id = a.feed_id AND f.kind = 'podcast' "
            "JOIN article_topics x ON x.article_id = a.id AND x.source = 'keyword' "
            f"JOIN topics t ON t.id = x.topic_id AND t.enabled = 1 GROUP BY 1, 2) WHERE rn = 1")
    added = db.execute(
        "INSERT OR IGNORE INTO article_topics (article_id, topic_id, source) "  # nosec B608 - fixed fragments, values bound
        f"SELECT a.id, m.topic_id, 'show' FROM articles a JOIN feeds f ON f.id = a.feed_id AND f.kind = 'podcast' "
        f"JOIN ({main}) m ON m.feed_id = a.feed_id WHERE {untagged}{scope}", params).rowcount
    general = db.execute("SELECT id FROM topics WHERE name = ? AND builtin = 1 AND enabled = 1", (GENERAL_TOPIC,)).fetchone()
    if general is not None:
        added += db.execute(
            "INSERT OR IGNORE INTO article_topics (article_id, topic_id, source) "  # nosec B608 - fixed fragments
            f"SELECT a.id, ?, 'general' FROM articles a JOIN feeds f ON f.id = a.feed_id AND f.kind = 'podcast' WHERE {untagged}{scope}",
            [general[0], *params]).rowcount
    return added



_ENABLED = "SELECT id FROM topics WHERE enabled = 1"
_CHANNEL_KEY = "COALESCE(v.channel_id, 'feed:' || a.feed_id)"
_UNTAGGED = ("NOT EXISTS (SELECT 1 FROM article_topics y JOIN topics ty ON ty.id = y.topic_id AND ty.enabled = 1 "
             "WHERE y.article_id = v.article_id)")


def fill_video_topics(db, article_ids: list[int] | None = None) -> int:
    """Every video gets at least one topic. A video no keyword matched takes its channel's main topic (the topic
    most of the channel's keyword-matched videos have); a channel with none takes "General". These fallback links
    are marked (source = 'channel' / 'general') and go away when a keyword topic matches later.
    ``article_ids``: only these (new) videos; None = all, also dropping fallbacks that are no longer needed."""
    if article_ids is not None and not article_ids:
        return 0
    scope, params = "", []
    if article_ids is not None:
        scope = f" AND v.article_id IN ({placeholders(len(article_ids))})"
        params = list(article_ids)
    else:
        db.execute(f"DELETE FROM article_topics WHERE source != 'keyword' AND (topic_id NOT IN ({_ENABLED}) OR article_id IN "  # nosec B608
                   f"(SELECT article_id FROM article_topics WHERE source = 'keyword' AND topic_id IN ({_ENABLED})))")
    # each channel's main keyword topic (only the channels involved, when filling a few new videos)
    only = (f" AND {_CHANNEL_KEY} IN (SELECT {_CHANNEL_KEY} FROM videos v JOIN articles a ON a.id = v.article_id "
            f"WHERE 1 = 1{scope})") if scope else ""
    main = (f"SELECT ck, topic_id FROM (SELECT {_CHANNEL_KEY} AS ck, x.topic_id, "
            f"ROW_NUMBER() OVER (PARTITION BY {_CHANNEL_KEY} ORDER BY COUNT(*) DESC, x.topic_id) AS rn "
            "FROM videos v JOIN articles a ON a.id = v.article_id "
            "JOIN article_topics x ON x.article_id = v.article_id AND x.source = 'keyword' "
            f"JOIN topics t ON t.id = x.topic_id AND t.enabled = 1 WHERE 1 = 1{only} GROUP BY 1, 2) WHERE rn = 1")
    added = db.execute(
        "INSERT OR IGNORE INTO article_topics (article_id, topic_id, source) "  # nosec B608 - fixed fragments, values bound
        f"SELECT v.article_id, m.topic_id, 'channel' FROM videos v JOIN articles a ON a.id = v.article_id "
        f"JOIN ({main}) m ON m.ck = {_CHANNEL_KEY} WHERE {_UNTAGGED}{scope}", params + params).rowcount
    general = db.execute("SELECT id FROM topics WHERE name = ? AND builtin = 1 AND enabled = 1", (GENERAL_TOPIC,)).fetchone()
    if general is not None:
        added += db.execute(
            "INSERT OR IGNORE INTO article_topics (article_id, topic_id, source) "  # nosec B608 - fixed fragments
            f"SELECT v.article_id, ?, 'general' FROM videos v JOIN articles a ON a.id = v.article_id WHERE {_UNTAGGED}{scope}",
            [general[0], *params]).rowcount
    return added


ALL_TOPICS = None  # Reclassifier job meaning "every topic"
RETAG_BATCH = 500


class Reclassifier:
    """Re-tags articles after topics change, in a background thread, one job at a time.

    Work is done in short transactions of RETAG_BATCH articles with a pause between them, so feed fetching and the UI
    keep writing while it runs (one long transaction used to lock the database for minutes). Adding or editing a topic
    re-tags only that topic; ``start()`` with no topic re-tags everything (built-in topic changes, "Re-tag all")."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._pending: set[int] | None = set()   # topic ids waiting, or ALL_TOPICS

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, topic_id: int | None = None) -> None:
        with self._lock:
            if topic_id is None:
                self._pending = ALL_TOPICS
            elif self._pending is not ALL_TOPICS:
                self._pending.add(int(topic_id))
            if self.running:
                return  # the running thread picks the new work up
            self._thread = threading.Thread(target=self._run, name="topics", daemon=True)
            self._thread.start()

    def _run(self) -> None:
        while True:
            with self._lock:
                job, self._pending = self._pending, set()
                if job is not ALL_TOPICS and not job:
                    self._thread = None  # nothing left; a later start() launches a new thread
                    return
            try:
                self._retag(job)
            except Exception:
                log.exception("Topic reclassification failed")

    @staticmethod
    def _retag(job: set[int] | None) -> None:
        with get_db() as db:
            compiled = _compiled(db)
            ids = [r[0] for r in db.execute("SELECT id FROM articles ORDER BY feed_id, id")]
        if job is not ALL_TOPICS:
            compiled = [c for c in compiled if c[0] in job]
            with get_db() as db:  # drop the old links of the changed topics (a disabled topic just loses them)
                db.execute(f"DELETE FROM article_topics WHERE topic_id IN ({placeholders(len(job))})", sorted(job))  # nosec B608
            if not compiled:
                with get_db() as db:
                    fill_video_topics(db)
                return
        boiler: dict[int, set[str]] = {}
        for start in range(0, len(ids), RETAG_BATCH):
            chunk = ids[start:start + RETAG_BATCH]
            with get_db() as db:
                if job is ALL_TOPICS:
                    db.execute(f"DELETE FROM article_topics WHERE article_id IN ({placeholders(len(chunk))})", chunk)  # nosec B608
                classify(db, chunk, compiled, boiler)
            time.sleep(0.02)  # let other writers in
        with get_db() as db:
            fill_video_topics(db)  # videos no keyword matched: their channel's topic, else General
            apply_category_topics(db)  # a show's own categories add their topics back
            fill_episode_topics(db)  # podcast episodes likewise: their show's topic, else General


reclassifier = Reclassifier()
