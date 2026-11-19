"""Sub-techniques, recognised in the context of their technique.

A sub-technique's official name is often an everyday phrase ("Cloud Accounts", "Browser Extensions", "Impersonation",
"Malicious Link"). Matching those in every article would be noise, so the watchlist only matches them through their
ID. But in an article that ALREADY names the technique (Valid Accounts, Software Extensions, Social Engineering,
Phishing) the same words do tell which sub-technique is meant. This module adds that second look:

    for every article that names a technique: which of that technique's sub-techniques does its text also name,
    by the sub-technique's official name or by one of the context terms below?

The result is stored like any other mention (``article_entities`` of the sub-technique's entity), so the tactic
tag's list, the sub-technique's page and its article list all show it. Nothing is guessed: an article that names
no sub-technique keeps the technique alone. "Not this technique" rejections are respected.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading

from app import entities
from app.cve_sync import get_state, set_state
from app.db import get_db, placeholders

log = logging.getLogger("eos.ttp")

REV = "1"  # bump when CONTEXT_TERMS / SKIP_NAMES change: the sub-technique entities are re-indexed once
SLUGS = ("mitre-attack-techniques", "mitre-atlas-techniques")
SUB_ID = re.compile(r"\(((?:AML\.)?T\d{4}\.\d{3})\)$")
PARENT_ID = re.compile(r"\(((?:AML\.)?T\d{4})\)$")
# One-word official names that say nothing even next to their technique ("Server", "Tool", "Direct").
SKIP_NAMES = {n for n in """direct indirect triggered tool malware server domains memory thread software hardware at exploits
vulnerabilities implementation compression serverless botnet python lua""".split()}

# Wording that names a sub-technique once its technique is established (sub-technique ID -> terms).
CONTEXT_TERMS: dict[str, tuple[str, ...]] = {
    # --- ATT&CK Enterprise
    "T1566.001": ("malicious attachment", "malicious attachments", "malicious document", "malicious documents", "malicious PDF",
                  "email attachment", "attached file"),
    "T1566.002": ("malicious link", "malicious links", "phishing link", "phishing links", "phishing URL", "phishing URLs",
                  "phishing page", "phishing pages", "phishing site", "phishing sites"),
    "T1566.003": ("LinkedIn message", "LinkedIn messages", "WhatsApp message", "WhatsApp messages", "Telegram message",
                  "direct message", "direct messages", "social media message", "social media messages"),
    "T1566.004": ("phone call", "phone calls", "callback phishing", "vishing", "voice phishing"),
    "T1684.001": ("impersonating", "impersonate", "impersonates", "impersonated", "impersonation", "posing as", "pretending to be",
                  "masquerading as"),
    "T1684.002": ("spoofed email", "spoofed emails", "email spoofing", "spoofed sender", "spoofed address"),
    "T1498.001": ("SYN flood", "UDP flood", "ICMP flood", "volumetric attack", "volumetric attacks", "volumetric DDoS"),
    "T1498.002": ("amplification attack", "amplification attacks", "reflection attack", "reflection attacks", "DNS amplification",
                  "amplification"),
    "T1499.002": ("HTTP flood", "Slowloris"),
    "T1499.003": ("application-layer", "application layer", "layer 7"),
    "T1499.004": ("denial of service vulnerability", "denial-of-service vulnerability", "DoS vulnerability", "DoS flaw", "crash the"),
    "T1195.001": ("malicious npm package", "malicious npm packages", "malicious PyPI package", "malicious PyPI packages",
                  "malicious package", "malicious packages", "npm package", "npm packages", "PyPI package", "PyPI packages",
                  "dependency confusion", "typosquatted package", "typosquatted packages", "malicious dependency"),
    "T1195.002": ("trojanized", "trojanised", "compromised update", "malicious update", "software update", "build pipeline",
                  "build system"),
    "T1195.003": ("hardware supply chain", "hardware implant", "hardware implants"),
    "T1078.001": ("default credentials", "default password", "default passwords", "default account", "default accounts"),
    "T1078.002": ("domain account", "domain accounts", "domain admin", "domain administrator", "Active Directory account",
                  "Active Directory accounts"),
    "T1078.003": ("local account", "local accounts", "local admin", "local administrator"),
    "T1078.004": ("cloud account", "cloud accounts", "cloud credentials", "AWS account", "AWS credentials", "Azure account",
                  "Microsoft 365 account", "Microsoft 365 accounts", "Google Workspace account", "service principal"),
    "T1557.001": ("LLMNR", "NBT-NS", "NTLM relay", "SMB relay"),
    "T1557.002": ("ARP spoofing", "ARP poisoning"),
    "T1557.003": ("rogue DHCP",),
    "T1219.001": ("VS Code tunnel", "VS Code tunnels", "dev tunnel", "dev tunnels"),
    "T1219.002": ("AnyDesk", "TeamViewer", "ScreenConnect", "Atera", "Splashtop", "RustDesk", "remote desktop software", "RMM tool",
                  "RMM tools", "remote monitoring and management"),
    "T1176.001": ("browser extension", "browser extensions", "Chrome extension", "Chrome extensions", "Firefox extension",
                  "Firefox extensions", "Edge extension", "Edge extensions"),
    "T1176.002": ("VS Code extension", "VS Code extensions", "IDE extension", "IDE extensions", "Open VSX", "Visual Studio Code extension"),
    "T1496.001": ("cryptojacking", "cryptominer", "cryptominers", "cryptomining", "XMRig", "Monero miner", "coin miner"),
    "T1496.002": ("proxyjacking", "residential proxy", "residential proxies"),
    "T1496.004": ("LLMjacking",),
    "T1027.002": ("packer", "packers", "packed with", "UPX"),
    "T1027.003": ("steganography",),
    "T1027.010": ("obfuscated PowerShell", "obfuscated command", "obfuscated commands"),
    "T1027.013": ("encrypted payload", "encrypted payloads", "Base64-encoded", "Base64 encoded", "XOR-encrypted", "XOR encrypted"),
    "T1027.016": ("junk code",),
    "T1685.001": ("disable event logging", "disabled event logging"),
    "T1055.001": ("DLL injection", "reflective DLL injection"),
    "T1055.002": ("PE injection",),
    "T1055.004": ("APC injection", "Early Bird"),
    "T1497.001": ("virtual machine detection", "VM detection", "sandbox detection", "checks for virtual machines", "anti-VM"),
    "T1497.003": ("time-based evasion", "delayed execution", "sleep timer"),
    "T1021.001": ("RDP", "Remote Desktop"),
    "T1021.004": ("SSH",),
    "T1583.003": ("VPS", "virtual private servers"),
    "T1584.001": ("hijacked domain", "hijacked domains", "domain hijacking"),
    "T1584.004": ("compromised server", "compromised servers"),
    "T1584.005": ("botnet", "botnets"),
    "T1584.008": ("compromised routers", "hacked routers", "SOHO routers", "compromised edge devices", "compromised network devices"),
    "T1588.005": ("exploit kit", "exploit kits", "exploit broker", "exploit brokers", "purchased exploit"),
    "T1588.007": ("generative AI", "AI-generated", "used ChatGPT"),
    "T1003.002": ("SAM database", "SAM hive"),
    "T1003.003": ("NTDS.dit",),
    "T1003.006": ("DCSync",),
    "T1059.002": ("AppleScript", "osascript"),
    "T1059.003": ("cmd.exe", "batch script", "batch file", "batch files"),
    "T1059.004": ("bash script", "shell script", "shell scripts"),
    "T1059.005": ("VBScript", "VBA macro", "VBA macros", "VBA"),
    "T1059.006": ("Python script", "Python scripts"),
    "T1059.007": ("JavaScript", "JScript", "Node.js"),
    "T1204.001": ("malicious link", "malicious links", "clicking a link", "clicks a link"),
    "T1204.002": ("malicious file", "malicious files", "malicious document", "malicious documents"),
    "T1555.001": ("Keychain",),
    "T1555.004": ("Credential Manager",),
    "T1555.005": ("password manager", "password managers", "KeePass", "LastPass", "1Password", "Bitwarden"),
    "T1053.005": ("scheduled task", "scheduled tasks", "schtasks"),
    "T1550.001": ("access token", "access tokens", "OAuth token", "OAuth tokens"),
    "T1550.004": ("session cookie", "session cookies"),
    "T1056.003": ("fake login page", "fake login pages"),
    "T1087.004": ("cloud account", "cloud accounts"),
    # --- ATLAS
    "AML.T0051.000": ("direct prompt injection",),
    "AML.T0051.001": ("indirect prompt injection", "hidden instructions", "hidden prompt", "hidden prompts", "embedded instructions"),
    "AML.T0052.000": ("AI-generated phishing", "LLM-generated phishing", "AI phishing", "AI-powered phishing", "AI-written phishing"),
    "AML.T0052.001": ("deepfake phishing", "deepfake vishing", "deepfake scam", "deepfake scams", "deepfake fraud", "voice cloning",
                      "deepfake video call"),
    "AML.T0010.001": ("malicious package", "malicious packages", "malicious library", "malicious libraries"),
    "AML.T0010.002": ("poisoned dataset", "poisoned datasets", "malicious dataset", "malicious datasets"),
    "AML.T0010.003": ("Hugging Face", "model hub", "model repository", "malicious model", "malicious models"),
    "AML.T0010.004": ("container registry", "Docker Hub"),
    "AML.T0010.005": ("MCP server", "MCP servers", "malicious MCP", "AI agent tool", "AI agent tools"),
    "AML.T0043.000": ("white-box",),
    "AML.T0043.001": ("black-box",),
    "AML.T0043.004": ("backdoor trigger", "backdoor triggers"),
    "AML.T0080.000": ("memory poisoning", "agent memory", "long-term memory", "poisoned memory"),
    "AML.T0110.000": ("tool description", "tool descriptions", "tool definitions"),
    "AML.T0017.001": ("AI-generated exploit", "AI-generated exploits", "autonomous exploit"),
    "AML.T0017.003": ("AI-generated malware", "AI-written malware", "LLM-generated malware", "AI-developed malware"),
}
_lock = threading.Lock()


def _name_ok(name: str) -> bool:
    tokens = entities.TOKEN.findall(name)
    return len(tokens) >= 2 or (len(tokens) == 1 and len(tokens[0]) >= 3 and tokens[0].lower() not in SKIP_NAMES)


def _load(db: sqlite3.Connection) -> tuple[entities.Matcher, dict[int, int]]:
    """(a matcher over the sub-techniques' context names, {sub-technique entity: its technique's entity})."""
    parents: dict[str, int] = {}
    subs: list[sqlite3.Row] = []
    for r in db.execute("SELECT e.id, e.name, e.aliases, e.muted FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                        "WHERE w.slug IN (?, ?)", SLUGS):
        m = PARENT_ID.search(r["name"])
        if m:
            parents[m.group(1)] = r["id"]
        elif SUB_ID.search(r["name"]):
            subs.append(r)
    rows: list[tuple] = []
    parent_of: dict[int, int] = {}
    for r in subs:
        sid = SUB_ID.search(r["name"]).group(1)
        parent = parents.get(sid.rsplit(".", 1)[0])
        if parent is None:
            continue
        official = r["name"][: r["name"].rfind("(")].strip()
        have = {a.lower() for a in json.loads(r["aliases"]) if isinstance(a, str)}  # already matched everywhere
        names = [n for n in ([official] if _name_ok(official) else []) + list(CONTEXT_TERMS.get(sid, ())) if n.lower() not in have]
        if names:
            rows.append((r["id"], "", json.dumps(names), r["muted"]))
            parent_of[r["id"]] = parent
    return entities.Matcher(rows), parent_of


def assign(db: sqlite3.Connection, article_ids: list[int] | None = None) -> int:
    """Add the sub-technique mentions that the text supports for articles naming the technique. Returns rows added.
    ``article_ids`` None = every article that names a technique with sub-techniques."""
    if article_ids is not None and not article_ids:
        return 0
    matcher, parent_of = _load(db)
    if matcher.empty:
        return 0
    wanted_parents = sorted(set(parent_of.values()))
    by_article: dict[int, set[int]] = {}
    chunks = [None] if article_ids is None else [article_ids[i : i + 500] for i in range(0, len(article_ids), 500)]
    for chunk in chunks:
        for start in range(0, len(wanted_parents), 400):
            part = wanted_parents[start : start + 400]
            scope, args = ("", []) if chunk is None else (f" AND article_id IN ({placeholders(len(chunk))})", list(chunk))
            for r in db.execute(f"SELECT article_id, entity_id FROM article_entities WHERE entity_id IN ({placeholders(len(part))}){scope}",  # nosec B608
                                [*part, *args]):
                by_article.setdefault(r["article_id"], set()).add(r["entity_id"])
    added = 0
    ids = sorted(by_article)
    for start in range(0, len(ids), 300):
        chunk = ids[start : start + 300]
        marks = placeholders(len(chunk))
        rejected = {(r[0], r[1]) for r in db.execute(f"SELECT article_id, entity_id FROM entity_rejections WHERE article_id IN ({marks})", chunk)}  # nosec B608
        pairs = []
        for row in db.execute(f"SELECT id, title, substr(text_content, 1, 60000) AS body FROM articles WHERE id IN ({marks})", chunk):  # nosec B608
            mine = by_article[row["id"]]
            for sub in matcher.match(f"{row['title']}\n{row['body']}"):
                if parent_of[sub] in mine and (row["id"], sub) not in rejected:
                    pairs.append((row["id"], sub))
        if pairs:
            added += db.executemany("INSERT OR IGNORE INTO article_entities (article_id, entity_id) VALUES (?, ?)", pairs).rowcount
    return added


def assign_all() -> int:
    """Every stored article, in short transactions (called when the mention index was rebuilt)."""
    with _lock:
        with get_db() as db:
            _matcher, parent_of = _load(db)
            parents = sorted(set(parent_of.values()))
            ids: list[int] = []
            for start in range(0, len(parents), 400):
                part = parents[start : start + 400]
                ids += [r[0] for r in db.execute(
                    f"SELECT DISTINCT article_id FROM article_entities WHERE entity_id IN ({placeholders(len(part))})", part)]  # nosec B608
            ids = sorted(set(ids))
        added = 0
        for start in range(0, len(ids), 1000):
            with get_db() as db:
                added += assign(db, ids[start : start + 1000])
        with get_db() as db:
            set_state(db, "ttp_subs_rev", REV)
    if added:
        log.info("Sub-techniques in context: %d mentions added over %d articles", added, len(ids))
    return added


def after_reindex(entity_ids: list[int] | None) -> None:
    """The entity re-indexer rebuilt mentions from the watchlist names alone: put the context matches back - when
    a technique or sub-technique was among the re-indexed entities (or everything was)."""
    if entity_ids is not None:
        with get_db() as db:
            touched = db.execute(
                f"SELECT 1 FROM entities e JOIN watchlists w ON w.id = e.watchlist_id WHERE w.slug IN (?, ?) "  # nosec B608
                f"AND e.id IN ({placeholders(len(entity_ids))}) LIMIT 1", [*SLUGS, *entity_ids]).fetchone() if entity_ids else None
        if not touched:
            return
    assign_all()


def ensure_current() -> bool:
    """After the term list changed (REV): re-index the sub-technique entities once, so mentions the old list
    supported and the new one does not are dropped; the re-indexer then calls after_reindex()."""
    with get_db() as db:
        if get_state(db, "ttp_subs_rev", "") == REV:
            return False
        _matcher, parent_of = _load(db)
    if not parent_of:
        return False
    entities.reindexer.request(sorted(parent_of))
    return True
