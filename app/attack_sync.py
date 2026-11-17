"""MITRE ATT&CK sync: threat groups and techniques (TTPs) from MITRE's official STIX 2.1 data.

Source: https://github.com/mitre-attack/attack-stix-data (the files attack.mitre.org is built from).
  * index.json lists the current release of each domain (Enterprise, ICS, Mobile). A sync first reads
    the index; when the releases are unchanged, nothing else is downloaded.
  * Bundle URLs from the index are only followed when they point inside that repository.

What a sync updates (one transaction for the tables, short transactions for re-filing):
  * attack_groups / attack_techniques / attack_group_techniques: replaced from the new release.
  * Watchlist "MITRE ATT&CK groups" (slug mitre-attack-groups): one entity per group, "Name (G0007)", with
    MITRE's aliases. Entities ending in "(Gxxxx)" are managed by the sync; others you add are left alone.
  * attack_tactics: the tactics of each domain, in the order of MITRE's matrix.
  * Watchlist "MITRE ATT&CK techniques" (slug mitre-attack-techniques): one entity per technique "Name (T1566)"
    (matching its ID, its name, everyday terms and its sub-techniques), one per sub-technique
    "Name (T1566.001)", and one per Enterprise tactic "Name (TA0001)".
  * The "ATT&CK: <tactic>" collections follow the Enterprise matrix and are filed from those entities
    (app/ttp_filing.py) - only when the ATT&CK collection pack is installed.
  * A change report (new / removed / updated groups and techniques) shown in Settings.

Deleting one of the two watchlists stops the sync from re-creating it.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from typing import Any

from app import app_settings, entities, netguard, ttp_filing
from app.config import get_settings
from app.cve_sync import get_state, set_state
from app.db import get_db, now

log = logging.getLogger("feedwarden.attack")

REPO = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
INDEX_URL = REPO + "index.json"
DOMAINS = {"Enterprise ATT&CK": "enterprise-attack", "ICS ATT&CK": "ics-attack", "Mobile ATT&CK": "mobile-attack"}
MAX_BUNDLE = 200 * 1024 * 1024
INTERVALS = {"daily": 86400, "weekly": 7 * 86400}
GROUPS_SLUG, TECH_SLUG = "mitre-attack-groups", "mitre-attack-techniques"
GROUP_ID = re.compile(r"^G\d{4}$")
TECH_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
TACTIC_ID = re.compile(r"^TA\d{4}$")
MANAGED = re.compile(r"\((G\d{4}|TA\d{4}|T\d{4}(?:\.\d{3})?)\)$")
CITATION = re.compile(r"\(Citation:[^)]*\)")
MD_LINK = re.compile(r"\[([^\]]+)\]\([^)]+\)")

# Single words that are also ordinary English (or chemistry) words: as an alias on their own they would
# match unrelated text, so they are only matched as part of "<word> (G0123)" and longer aliases.
COMMON_WORDS = set("""
silence machete inception equation leviathan sidewinder patchwork honeybee strider rancor dragonfly whitefly thrip
elderwood poseidon cobalt ghost shadow phantom turbine wolf spider panda bear kitten typhoon blizzard sleet tempest
storm sandstorm dust frost ember flax scarab comet orion apollo venus mars saturn jupiter titan atlas hydra chimera
sphinx oracle sapphire ruby emerald onyx amber jade obsidian garnet opal pearl topaz diamond crystal granite marble
tropic mustang cobra viper python mamba scorpion hornet wasp moth beetle mantis termite cicada cricket firefly dragon
phoenix griffin pirate ninja samurai shogun warrior knight crusader raven crow falcon hawk eagle owl sparrow magpie
pelican heron swan desert ocean river lake mountain valley forest canyon sandman wizard witch goblin troll gnome
giant kraken behemoth gorgon medusa siren banshee wraith specter spectre vampire zombie reaper moonlight twilight
dawn dusk midnight eclipse nebula galaxy cosmos meteor asteroid satellite rocket torpedo sword dagger spear arrow
shield lion tiger leopard jaguar cheetah lynx puma fox hyena jackal elephant rhino buffalo bison moose camel horse
goat ram boar bull rabbit squirrel beaver otter badger weasel ferret raccoon hedgehog porcupine bat mole mouse rat
operation team group gang unit actor hacker hackers lazarus winnti play karma mirage snake tick axiom armageddon
cleaver confucius newscaster rattlesnake webmasters lyceum pinkpanther
gold silver copper iron tin lead zinc platinum mercury nickel cobalt carbon silicon sulfur boron helium neon argon
xenon krypton radon lithium sodium potassium calcium magnesium titanium chromium manganese aluminum aluminium
hydrogen oxygen nitrogen fluorine chlorine iodine bromine uranium thorium plutonium polonium radium strontium barium
zirconium gallium bismuth phosphorus holmium bohrium iridium neodymium promethium thallium tellurium cerium europium
lanthanum osmium rhenium ruthenium hafnium tantalum vanadium tungsten cadmium indium antimony caesium cesium
gadolinium terbium dysprosium erbium thulium ytterbium lutetium praseodymium samarium niobium molybdenum technetium
rhodium palladium beryllium francium astatine actinium protactinium neptunium americium curium berkelium californium
einsteinium fermium mendelevium nobelium lawrencium rutherfordium dubnium seaborgium hassium meitnerium germanium
arsenic selenium rubidium yttrium scandium copernicium nihonium moscovium livermorium tennessine oganesson
""".split())


# Sub-technique names that are everyday phrases in security news ("Social Media", "Email Accounts"): matching them
# would credit the parent technique for unrelated articles, so they only count through their T-ID.
GENERIC_SUBNAMES = {n.strip().lower() for n in """
artificial intelligence|social media|social media accounts|search engines|code repositories|web services|network devices
|ip addresses|digital certificates|email addresses|email accounts|email account|cloud accounts|cloud account|local accounts
|local account|domain accounts|domain account|default accounts|default credentials|business relationships|employee names
|client configurations|dns server|virtual private server|network topology|domain properties|determine physical locations
|identify roles|identify business tempo|cloud services|cloud api|container api|control panel|contact list|call log
|chat messages|sms messages|calendar entries|download all|online edit|web protocols|mail protocols|file transfer protocols
|visual basic|unix shell|scheduled task|windows service|private keys|multi-factor authentication|remote desktop protocol
|remote desktop software|wi-fi|web cookies|messaging applications|electron applications|password managers
|installer packages|component firmware|system firmware|module firmware|junk data|standard encoding|code signing
|cloud groups|domain groups|local groups|hybrid identity|written content|audio-visual content|threat intel vendors
|purchase technical data|scan databases|vulnerability scanning|port scan|file deletion|internal proxy|external proxy
|command message|reporting message|link target|malicious file|malicious link|malicious image|malicious library
|upload malware|upload tool|device registration|device lockout|office test|program append|serial com
|one-way communication|bidirectional communication|network security appliances|remote access hardware|cloud firewall
|hidden users|hidden window|system checks|user evasion|create snapshot|time providers|port monitors|login items
|startup items|shell history|asymmetric cryptography|symmetric cryptography|embedded payloads|polymorphic code
|credentials in files|cloud secrets management stores|code signing certificates|domain controller authentication
""".replace("\n", "").split("|") if n.strip()}


# Official names (technique or sub-technique) that are ordinary phrases in tech news: "Wi-Fi Networks", "Web Service",
# "Browser Extensions". They still match through their T-ID; ATTACK_TERMS adds the wording articles really use.
GENERIC_NAMES = GENERIC_SUBNAMES | {n.strip().lower() for n in """
wi-fi networks|web service|browser extensions|software extensions|ide extensions|video capture|conditional access policies
|location tracking|container service|system services|graphical user interface|remote services|linked devices|loss of control
|inter-process communication|component object model|generate content|power settings|add-ins|accessibility features
|browser fingerprint|virtualization solution|protected user data|bind mounts|native api|create account|systemd service
|launch agent|launch daemon|thread local storage|service execution|out of band data|unauthorized message
|application access token|web session cookie|security account manager|windows credential manager|automated collection
|encrypted channel|denial of service|loss of availability|loss of view|data from local system|user execution|active scanning
|trusted relationship|process discovery|template injection|input injection|pluggable authentication modules
""".replace("\n", "").split("|") if n.strip()}

# The wording security news uses, per technique or sub-technique ID of the current release (matched like an
# alias; switch off in Settings → Appearance & reading). A term on a sub-technique also counts for its technique.
# IDs MITRE has retired are skipped with a log line (see _terms).
ATTACK_TERMS: dict[str, tuple[str, ...]] = {
    # Reconnaissance
    "T1595": ("port scanning", "mass scanning", "internet-wide scanning"),
    "T1595.002": ("vulnerability scanning",),
    # Resource Development
    "T1583": ("bulletproof hosting",),
    "T1583.001": ("typosquatting", "typosquatted domain", "typosquatted domains", "lookalike domain", "lookalike domains"),
    "T1583.005": ("botnet infrastructure",),
    "T1583.008": ("malvertising", "malvertising campaign", "malvertising campaigns"),
    "T1584": ("compromised infrastructure",),
    "T1588.001": ("malware-as-a-service", "MaaS"),
    "T1588.002": ("phishing-as-a-service", "PhaaS"),
    "T1588.003": ("stolen code signing certificate", "stolen code-signing certificate", "stolen certificate"),
    "T1650": ("initial access broker", "initial access brokers"),
    "T1608.006": ("SEO poisoning",),
    # Initial Access
    "T1566": ("spearphishing", "spear phishing", "phishing campaign", "phishing campaigns", "phishing email",
              "phishing emails", "phishing attack", "phishing attacks", "phishing kit"),
    "T1566.001": ("malicious attachment", "malicious attachments"),
    "T1566.004": ("vishing", "voice phishing"),
    "T1195": ("supply chain attack", "supply chain attacks"),
    "T1195.002": ("software supply chain attack", "software supply chain attacks"),
    "T1189": ("drive-by download", "watering hole attack", "watering hole"),
    "T1133": ("exposed RDP",),
    "T1078": ("stolen credentials", "compromised credentials"),
    "T1669": ("rogue access point", "nearest neighbor attack"),
    "T1451": ("SIM swapping", "SIM swap"),
    # Execution
    "T1059.001": ("malicious PowerShell", "PowerShell script", "PowerShell command", "PowerShell commands"),
    "T1204.002": ("malicious macro", "malicious macros"),
    "T1204.004": ("ClickFix", "FileFix"),
    "T1047": ("WMI",),
    # Persistence
    "T1547.001": ("registry run key", "registry run keys", "run keys", "startup folder"),
    "T1505.003": ("webshell", "webshells", "web shells"),
    "T1542.003": ("bootkit", "bootkits"),
    "T1053.003": ("cron job", "cron jobs"),
    "T1136": ("backdoor account", "backdoor accounts"),
    "T1176": ("malicious browser extension", "malicious browser extensions", "malicious extension", "malicious extensions",
              "malicious VS Code extension", "malicious VS Code extensions"),
    # Privilege Escalation
    "T1068": ("kernel exploit", "local privilege escalation", "privilege escalation vulnerability", "privilege escalation flaw",
              "privilege escalation bug", "elevation of privilege vulnerability"),
    "T1548.002": ("UAC bypass",),
    "T1134.001": ("token impersonation",),
    # Stealth
    "T1218": ("LOLBin", "LOLBins", "living off the land", "living-off-the-land"),
    "T1218.005": ("mshta",),
    "T1218.011": ("rundll32",),
    "T1620": ("fileless malware",),
    "T1055": ("DLL injection",),
    "T1574.001": ("DLL side-loading", "DLL sideloading", "DLL hijacking", "DLL search order hijacking"),
    "T1014": ("rootkit", "rootkits"),
    "T1070.006": ("timestomping",),
    "T1497": ("sandbox evasion", "anti-analysis"),
    "T1027": ("obfuscated code", "code obfuscation", "obfuscated JavaScript", "obfuscated PowerShell", "heavily obfuscated",
              "obfuscated payload", "obfuscated script"),
    # Defense Impairment
    "T1685": ("EDR killer", "EDR killers", "BYOVD", "bring your own vulnerable driver", "disable antivirus", "AMSI bypass"),
    "T1685.005": ("log clearing", "cleared event logs", "clearing event logs"),
    # Credential Access
    "T1003": ("credential dumping",),
    "T1003.001": ("Mimikatz", "LSASS"),
    "T1056.001": ("keylogger", "keyloggers", "keylogging"),
    "T1110": ("brute-force attack", "brute-force attacks", "brute force attack", "brute force attacks"),
    "T1558.003": ("Kerberoasting",),
    "T1555.003": ("infostealer", "infostealers", "info-stealer", "info-stealers", "information stealer", "information stealers"),
    "T1539": ("session hijacking", "cookie theft", "stolen session cookies", "session cookie theft"),
    "T1528": ("token theft", "OAuth token theft", "stolen OAuth tokens"),
    "T1557": ("man-in-the-middle", "MitM attack", "AiTM"),
    "T1621": ("MFA fatigue", "MFA bombing", "push bombing"),
    "T1606.002": ("Golden SAML", "forged SAML"),
    # Discovery
    "T1087.002": ("Active Directory enumeration", "AD enumeration", "BloodHound", "SharpHound", "AdFind"),
    "T1046": ("network scanning",),
    # Lateral Movement
    "T1550.002": ("pass-the-hash",),
    "T1550.003": ("pass-the-ticket",),
    "T1021.002": ("PsExec",),
    "T1021.006": ("WinRM",),
    # Command and Control
    "T1219": ("remote access trojan", "remote access trojans"),
    "T1572": ("DNS tunneling", "DNS tunnelling"),
    # Exfiltration
    "T1567.002": ("Rclone", "MEGAsync"),
    # Impact
    "T1486": ("ransomware", "ransomware attack", "ransomware attacks"),
    "T1485": ("wiper malware", "data wiper", "data wipers"),
    "T1561": ("disk wipe", "disk wiper"),
    "T1491": ("website defacement", "defaced website", "defaced websites"),
    "T1498": ("DDoS", "DDoS attack", "DDoS attacks", "distributed denial of service"),
    "T1499": ("denial of service attack", "denial of service vulnerability", "DoS attack"),
    "T1490": ("shadow copies", "deleted shadow copies"),
    "T1496": ("cryptojacking", "cryptomining malware", "cryptominer", "cryptominers"),
    "T1657": ("double extortion", "data extortion"),
}
# Wording that names a tactic without naming a technique (Enterprise tactic name -> terms). The official name is
# added when it is two words or more ("Lateral Movement"); one-word names (Impact, Execution) only match through
# their TA-ID. Such an article is filed under the tactic and shown as "tactic named, no specific technique".
TACTIC_TERMS: dict[str, tuple[str, ...]] = {
    "reconnaissance": ("reconnaissance",),
    "privilege escalation": ("escalate privileges", "escalated privileges", "elevation of privilege"),
    "stealth": ("evade detection", "evading detection", "evades detection", "detection evasion"),
    "persistence": ("maintain persistence", "establish persistence", "persistence mechanism", "persistence mechanisms",
                    "persistent access"),
    "credential access": ("credential theft", "steal credentials", "credential harvesting"),
    "discovery": ("internal reconnaissance",),
    "lateral movement": ("move laterally", "moved laterally", "moving laterally"),
    "command and control": ("command-and-control", "C2 server", "C2 servers", "C2 infrastructure", "C2 channel", "C&C server"),
    "exfiltration": ("exfiltration", "exfiltrate", "exfiltrated", "exfiltrating", "data exfiltration"),
}
ALIAS_REV = 3  # bump when GENERIC_NAMES / ATTACK_TERMS / TACTIC_TERMS change: stored watchlist entities are rebuilt once


def matchable(name: str) -> bool:
    """Can this official name be matched in text? (one word, or an everyday phrase: only through the T-ID)"""
    return len(entities.TOKEN.findall(name)) >= 2 and name.lower() not in GENERIC_NAMES


def muted_names(db, slug: str) -> set[str]:
    """Names the user muted on the entities of one watchlist ("stop matching this name")."""
    out: set[str] = set()
    for r in db.execute("SELECT e.muted FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                        "WHERE w.slug = ? AND e.muted != '[]'", (slug,)):
        out |= {str(m).lower() for m in json.loads(r["muted"])}
    return out


class AttackError(Exception):
    pass


def _get(url: str, max_bytes: int) -> bytes:
    cfg = get_settings()
    resp = netguard.request("GET", url, headers={"User-Agent": cfg.user_agent, "Accept": "application/json"},
                            timeout=max(cfg.fetch_timeout, 60), max_bytes=max_bytes)
    if resp.status_code != 200:
        raise AttackError(f"{url.rsplit('/', 1)[-1]}: HTTP {resp.status_code}")
    return resp.content


def releases() -> dict[str, dict]:
    """{domain: {"version", "url", "modified"}} from MITRE's index (URLs restricted to the repository)."""
    try:
        index = json.loads(_get(INDEX_URL, 5 * 1024 * 1024))
    except ValueError as exc:
        raise AttackError("The ATT&CK index is not valid JSON") from exc
    out = {}
    for coll in index.get("collections", []):
        domain = DOMAINS.get(coll.get("name"))
        versions = coll.get("versions") or []
        if not domain or not versions:
            continue
        latest = versions[0]
        url = str(latest.get("url", ""))
        if not (url.startswith(f"{REPO}{domain}/") and url.endswith(".json") and ".." not in url):
            raise AttackError(f"Unexpected bundle location for {domain}")
        out[domain] = {"version": str(latest.get("version", ""))[:20], "url": url,
                       "modified": str(latest.get("modified", ""))[:40]}
    if not out:
        raise AttackError("No ATT&CK releases found in the index")
    return out


def _ext_id(obj: dict) -> tuple[str, str]:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack") and ref.get("external_id"):
            return str(ref["external_id"]), str(ref.get("url") or "")
    return "", ""


def _clean_text(text: Any, limit: int = 800) -> str:
    text = MD_LINK.sub(r"\1", CITATION.sub("", str(text or "")))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1].rsplit(" ", 1)[0] + "…"


def _live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def parse_bundle(domain: str, bundle: dict, acc: dict) -> None:
    """Merge one domain's bundle into acc = {"groups": {G: ...}, "techniques": {T: ...}, "uses": set()}."""
    objects = [o for o in bundle.get("objects", []) if isinstance(o, dict)]
    tactics = {o.get("x_mitre_shortname"): str(o.get("name", ""))[:80] for o in objects
               if o.get("type") == "x-mitre-tactic" and _live(o)}
    # the domain's tactics in the order of its matrix (x-mitre-matrix.tactic_refs)
    tactic_objs = {o["id"]: o for o in objects if o.get("type") == "x-mitre-tactic" and _live(o) and o.get("id")}
    order = [ref for o in objects if o.get("type") == "x-mitre-matrix" and _live(o) for ref in o.get("tactic_refs") or []]
    listed: list[dict] = []
    for ref in list(dict.fromkeys(order)) + [i for i in tactic_objs if i not in order]:
        o = tactic_objs.get(ref)
        ext, url = _ext_id(o) if o else ("", "")
        if o and TACTIC_ID.match(ext) and str(o.get("name", "")).strip():
            listed.append({"id": ext, "name": str(o["name"]).strip()[:80], "url": url})
    acc.setdefault("tactics", {})[domain] = listed
    by_stix: dict[str, str] = {}
    for o in objects:
        kind = o.get("type")
        if kind not in ("intrusion-set", "attack-pattern") or not _live(o):
            continue
        ext, url = _ext_id(o)
        name = str(o.get("name", "")).strip()[:120]
        if not name:
            continue
        if kind == "intrusion-set" and GROUP_ID.match(ext):
            g = acc["groups"].setdefault(ext, {"id": ext, "name": name, "aliases": [], "description": "", "domains": [],
                                               "url": url, "created": o.get("created"), "modified": o.get("modified")})
            for alias in o.get("aliases") or []:
                alias = " ".join(str(alias).split())[:80]
                if alias and alias.lower() != name.lower() and alias not in g["aliases"]:
                    g["aliases"].append(alias)
            g["description"] = g["description"] or _clean_text(o.get("description"))
            if domain not in g["domains"]:
                g["domains"].append(domain)
            g["modified"] = max(str(g["modified"] or ""), str(o.get("modified") or "")) or None
            by_stix[o["id"]] = ext
        elif kind == "attack-pattern" and TECH_ID.match(ext):
            names = [tactics.get(p.get("phase_name"), str(p.get("phase_name", "")).replace("-", " ").title())
                     for p in o.get("kill_chain_phases") or []]
            acc["techniques"][ext] = {"id": ext, "name": name, "tactics": sorted(set(n for n in names if n)), "domain": domain,
                                      "is_subtechnique": int(bool(o.get("x_mitre_is_subtechnique"))), "url": url,
                                      "description": _clean_text(o.get("description"), 600), "modified": o.get("modified")}
            by_stix[o["id"]] = ext
    for o in objects:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses" and _live(o):
            src, dst = by_stix.get(o.get("source_ref", "")), by_stix.get(o.get("target_ref", ""))
            if src and dst and GROUP_ID.match(src) and TECH_ID.match(dst):
                acc["uses"].add((src, dst))


# ------------------------------------------------------------------ aliases for the watchlists
def _risky(alias: str) -> bool:
    tokens = entities.TOKEN.findall(alias)
    if len(tokens) != 1:
        return False
    word = tokens[0]
    if len(word) <= 3:
        return True
    letters = [c for c in alias if c.isalpha()]
    if letters and all(c.isupper() for c in letters):
        return False  # ALL-CAPS aliases are matched case-sensitively (e.g. IRON TWILIGHT, NICKEL)
    return word.lower() in COMMON_WORDS


def group_entity(g: dict) -> tuple[str, list[str]]:
    aliases = [a for a in [g["name"], *g["aliases"]] if not _risky(a)]
    return f"{g['name']} ({g['id']})", entities.clean_aliases([g["id"], *aliases])


def _aliases(values: list[str], limit: int = 160) -> list[str]:
    """clean_aliases without its 40-name cap (a technique with many sub-techniques has more names than that)."""
    out: list[str] = []
    seen: set[str] = set()
    for start in range(0, len(values), entities.MAX_ALIASES):
        for a in entities.clean_aliases(values[start : start + entities.MAX_ALIASES]):
            if a.lower() not in seen:
                seen.add(a.lower())
                out.append(a)
    return out[:limit]


def _terms(tid: str, everyday: bool) -> tuple[str, ...]:
    return ATTACK_TERMS.get(tid, ()) if everyday else ()


def technique_entity(t: dict, subs: list[dict], everyday: bool = True) -> tuple[str, list[str]]:
    """A technique matches through its ID, its name, its everyday terms - and everything its sub-techniques match
    through, so naming a sub-technique always names the technique too."""
    aliases = [t["id"]] + ([t["name"]] if matchable(t["name"]) else []) + list(_terms(t["id"], everyday))
    for s in subs:
        aliases.append(s["id"])
        if matchable(s["name"]):
            aliases.append(s["name"])
        aliases += _terms(s["id"], everyday)
    return f"{t['name']} ({t['id']})", _aliases(aliases)


def subtechnique_entity(s: dict, everyday: bool = True) -> tuple[str, list[str]]:
    aliases = [s["id"]] + ([s["name"]] if matchable(s["name"]) else []) + list(_terms(s["id"], everyday))
    return f"{s['name']} ({s['id']})", _aliases(aliases)


def tactic_entity(tactic: dict, everyday: bool = True) -> tuple[str, list[str]]:
    name = tactic["name"]
    aliases = [tactic["id"]] + ([name] if len(entities.TOKEN.findall(name)) >= 2 else [])
    if everyday:
        aliases += TACTIC_TERMS.get(name.lower(), ())
    return f"{name} ({tactic['id']})", _aliases(aliases)


def _technique_entities(techniques: dict[str, dict], everyday: bool, tactics: list[dict] | None = None) -> dict[str, tuple[str, list[str]]]:
    """{MITRE id: (entity name, aliases)} for every technique, sub-technique and (Enterprise) tactic."""
    unknown = sorted(t for t in ATTACK_TERMS if t not in techniques)
    if unknown and techniques:
        log.info("ATT&CK terms for IDs that are not in this release (skipped): %s", ", ".join(unknown))
    subs: dict[str, list[dict]] = {}
    for t in techniques.values():
        if t["is_subtechnique"]:
            subs.setdefault(t["id"].split(".")[0], []).append(t)
    out = {t["id"]: technique_entity(t, sorted(subs.get(t["id"], []), key=lambda s: s["id"]), everyday)
           for t in techniques.values() if not t["is_subtechnique"]}
    out.update({t["id"]: subtechnique_entity(t, everyday) for t in techniques.values() if t["is_subtechnique"]})
    out.update({t["id"]: tactic_entity(t, everyday) for t in tactics or [] if t.get("id")})
    return out


# ------------------------------------------------------------------ apply
def _watchlist(db, slug: str, name: str, description: str) -> int | None:
    row = db.execute("SELECT id FROM watchlists WHERE slug = ?", (slug,)).fetchone()
    if row:
        return row["id"]
    if get_state(db, f"attack_list_created:{slug}"):
        return None  # the user deleted it: don't bring it back
    if db.execute("SELECT 1 FROM watchlists WHERE name = ?", (name,)).fetchone():
        return None  # a user list already has this name
    wid = db.execute("INSERT INTO watchlists (name, slug, description, position) VALUES (?, ?, ?, 90)",
                     (name, slug, description)).lastrowid
    set_state(db, f"attack_list_created:{slug}", "1")
    return wid


def _sync_entities(db, wid: int, wanted: dict[str, tuple[str, list[str]]],
                   managed: re.Pattern[str] = MANAGED) -> tuple[list[int], int]:
    """wanted: {MITRE id: (entity name, aliases)}. Returns (changed entity ids, removed count)."""
    current: dict[str, Any] = {}
    for row in db.execute("SELECT id, name, aliases FROM entities WHERE watchlist_id = ?", (wid,)):
        m = managed.search(row["name"])
        if m:
            current[m.group(1)] = row
    changed, removed = [], 0
    for mid, row in current.items():
        if mid not in wanted:
            db.execute("DELETE FROM entities WHERE id = ?", (row["id"],))
            removed += 1
    for mid, (name, aliases) in wanted.items():
        row = current.get(mid)
        blob = json.dumps(aliases)
        if row is None:
            db.execute("DELETE FROM entities WHERE watchlist_id = ? AND name = ?", (wid, name))  # same name, unmanaged
            changed.append(int(db.execute("INSERT INTO entities (watchlist_id, name, aliases) VALUES (?, ?, ?)",
                                          (wid, name, blob)).lastrowid))
        elif row["name"] != name or row["aliases"] != blob:
            db.execute("UPDATE entities SET name = ?, aliases = ? WHERE id = ?", (name, blob, row["id"]))
            changed.append(int(row["id"]))
    return changed, removed


def inherit_muted(db, wid: int) -> None:
    """A name you muted on a technique stays muted on its sub-techniques' entities (they share the name)."""
    for row in db.execute("SELECT name, muted FROM entities WHERE watchlist_id = ? AND muted != '[]'", (wid,)).fetchall():
        m = re.search(r"\(((?:AML\.)?T\d{4})\)$", row["name"])
        if not m:
            continue
        muted = [x for x in json.loads(row["muted"]) if isinstance(x, str)]
        for sub in db.execute("SELECT id, aliases, muted FROM entities WHERE watchlist_id = ? AND name LIKE ? ESCAPE '\\'",
                              (wid, f"%({m.group(1)}.___)")).fetchall():
            have = {a.lower() for a in json.loads(sub["aliases"]) if isinstance(a, str)}
            merged = list(dict.fromkeys([*json.loads(sub["muted"] or "[]"), *[x for x in muted if x.lower() in have]]))
            if merged != json.loads(sub["muted"] or "[]"):
                db.execute("UPDATE entities SET muted = ? WHERE id = ?", (json.dumps(merged[:40]), sub["id"]))


def _after_change(changed_entities: list[int], removed_entities: int) -> None:
    """Re-index changed entities (the tactic collections are re-filed when the index is ready) and re-file now."""
    if changed_entities:
        entities.invalidate()
        entities.reindexer.request(changed_entities)
    elif removed_entities:
        entities.invalidate()
    ttp_filing.refile_all()


def _stored(db) -> tuple[dict[str, dict], list[dict]]:
    techniques = {r["id"]: {**dict(r), "tactics": json.loads(r["tactics"])} for r in db.execute(
        "SELECT id, name, tactics, domain, is_subtechnique FROM attack_techniques WHERE domain != 'atlas'")}
    tactics = [dict(r) for r in db.execute(
        "SELECT id, name, url FROM attack_tactics WHERE domain = 'enterprise-attack' ORDER BY position")]
    return techniques, tactics


def refresh_aliases() -> dict:
    """Rebuild the technique watchlist from the stored release (no download): after the name lists in this file
    changed, or after the everyday-terms setting changed. The tactic collections are re-filed."""
    with get_db() as db:
        everyday = bool(app_settings.get_all(db)["ttp_everyday_terms"])
        techniques, tactics = _stored(db)
        changed: list[int] = []
        removed = 0
        if techniques:
            wl = db.execute("SELECT id FROM watchlists WHERE slug = ?", (TECH_SLUG,)).fetchone()
            if wl:
                changed, removed = _sync_entities(db, wl["id"], _technique_entities(techniques, everyday, tactics))
                inherit_muted(db, wl["id"])
        set_state(db, "attack_alias_rev", str(ALIAS_REV))
    _after_change(changed, removed)
    if changed or removed:
        log.info("ATT&CK names refreshed: %d entities changed, %d removed", len(changed), removed)
    return {"entities_changed": len(changed), "entities_removed": removed}


def refresh_if_stale() -> None:
    """Startup hook: apply a newer name list (ALIAS_REV) to the stored watchlist once."""
    try:
        with get_db() as db:
            stale = get_state(db, "attack_alias_rev", "1") != str(ALIAS_REV)
            have = db.execute("SELECT 1 FROM attack_techniques WHERE domain != 'atlas' LIMIT 1").fetchone()
        if stale and have:
            refresh_aliases()
    except Exception:
        log.exception("Refreshing ATT&CK names failed")


def set_muted(db, entity_id: int, alias: str, on: bool) -> bool:
    """Mute / restore one of an entity's names. Returns False when the entity has no such name."""
    row = db.execute("SELECT aliases, muted FROM entities WHERE id = ?", (entity_id,)).fetchone()
    if row is None:
        return False
    known = {a.lower(): a for a in json.loads(row["aliases"]) if isinstance(a, str)}
    muted = [m for m in json.loads(row["muted"] or "[]") if isinstance(m, str)]
    low = alias.lower()
    if on:
        if low not in known or TECH_ID.match(known[low]) or TACTIC_ID.match(known[low]) or known[low].startswith("AML."):
            return False  # IDs always match
        if low not in {m.lower() for m in muted}:
            muted.append(known[low])
    else:
        if low not in {m.lower() for m in muted}:
            return False
        muted = [m for m in muted if m.lower() != low]
    db.execute("UPDATE entities SET muted = ? WHERE id = ?", (json.dumps(muted[:40]), entity_id))
    return True


def apply(acc: dict) -> dict:
    """Write a parsed release to the database; returns the change report."""
    groups, techniques, uses = acc["groups"], acc["techniques"], acc["uses"]
    with get_db() as db:
        old_groups = {r["id"]: r for r in db.execute("SELECT id, name, aliases, modified FROM attack_groups")}
        old_techs = {r["id"]: r for r in db.execute("SELECT id, name, modified FROM attack_techniques WHERE domain != 'atlas'")}
        db.execute("DELETE FROM attack_group_techniques")
        db.execute("DELETE FROM attack_groups")
        db.execute("DELETE FROM attack_techniques WHERE domain != 'atlas'")  # MITRE ATLAS rows belong to app/atlas_sync.py
        db.executemany("INSERT INTO attack_groups (id, name, aliases, description, domains, url, created, modified) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       [(g["id"], g["name"], json.dumps(g["aliases"]), g["description"], json.dumps(sorted(g["domains"])),
                         g["url"], g["created"], g["modified"]) for g in groups.values()])
        db.executemany("INSERT INTO attack_techniques (id, name, tactics, domain, is_subtechnique, url, description, modified) "
                       "VALUES (?,?,?,?,?,?,?,?)",
                       [(t["id"], t["name"], json.dumps(t["tactics"]), t["domain"], t["is_subtechnique"], t["url"],
                         t["description"], t["modified"]) for t in techniques.values()])
        db.executemany("INSERT OR IGNORE INTO attack_group_techniques (group_id, technique_id) VALUES (?, ?)", sorted(uses))
        for domain in DOMAINS.values():
            if acc.get("tactics", {}).get(domain):
                ttp_filing.store_tactics(db, domain, acc["tactics"][domain])
        tactics = [dict(r) for r in db.execute(
            "SELECT id, name, url FROM attack_tactics WHERE domain = 'enterprise-attack' ORDER BY position")]

        changed_entities: list[int] = []
        removed_entities = 0
        wid = _watchlist(db, GROUPS_SLUG, "MITRE ATT&CK groups",
                         "Threat groups from MITRE ATT&CK with their aliases. Kept up to date automatically "
                         "(Settings → Watchlists → MITRE ATT&CK); entities ending in (Gxxxx) are replaced on each sync.")
        if wid:
            c, r = _sync_entities(db, wid, {g["id"]: group_entity(g) for g in groups.values()})
            changed_entities += c
            removed_entities += r
        wid = _watchlist(db, TECH_SLUG, "MITRE ATT&CK techniques",
                         "ATT&CK tactics, techniques and sub-techniques (TTPs), matched by ID (T1566, T1566.001), name "
                         "and everyday terms. Kept up to date automatically; entities ending in (Txxxx), (Txxxx.xxx) or "
                         "(TAxxxx) are replaced on each sync.")
        if wid:
            c, r = _sync_entities(db, wid, _technique_entities(techniques, bool(app_settings.get_all(db)["ttp_everyday_terms"]), tactics))
            changed_entities += c
            removed_entities += r
            inherit_muted(db, wid)
        set_state(db, "attack_alias_rev", str(ALIAS_REV))

    def names(ids, table):
        return sorted(f"{table[i]['name']} ({i})" for i in ids)[:100]

    updated = [g for g in groups if g in old_groups and (old_groups[g]["name"] != groups[g]["name"]
               or json.loads(old_groups[g]["aliases"]) != groups[g]["aliases"] or old_groups[g]["modified"] != groups[g]["modified"])]
    report = {
        "groups": len(groups), "techniques": len(techniques), "relationships": len(uses),
        "groups_added": names([g for g in groups if g not in old_groups], groups) if old_groups else [],
        "groups_removed": sorted(f"{old_groups[g]['name']} ({g})" for g in old_groups if g not in groups)[:100],
        "groups_updated": names(updated, groups) if old_groups else [],
        "techniques_added": names([t for t in techniques if t not in old_techs], techniques) if old_techs else [],
        "techniques_removed": sorted(f"{old_techs[t]['name']} ({t})" for t in old_techs if t not in techniques)[:100],
        "entities_changed": len(changed_entities), "entities_removed": removed_entities,
        "tactics": [t["name"] for t in tactics],
        "first_sync": not old_groups,
    }
    _after_change(changed_entities, removed_entities)
    return report


# ------------------------------------------------------------------ job
class AttackSync:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.running = False
        self.phase = ""

    def start(self, force: bool = False) -> bool:
        with self._lock:
            if self.running:
                return False
            self.running = True
        threading.Thread(target=self._run, args=(force,), name="attack-sync", daemon=True).start()
        return True

    def maybe_start(self) -> None:
        """Scheduler hook: check for a new ATT&CK release when the chosen interval has passed."""
        if self.running:
            return
        with get_db() as db:
            every = INTERVALS.get(app_settings.get_all(db)["attack_sync"])
            last = int(get_state(db, "attack_checked_at", "0") or 0)
        if every and now() - last >= every:
            self.start()

    def _run(self, force: bool) -> None:
        started = now()
        result: dict[str, Any] = {"started": started}
        try:
            self.phase = "checking MITRE's release index"
            rel = releases()
            with get_db() as db:
                stored = {d: get_state(db, f"attack_version:{d}") for d in rel}
                have = db.execute("SELECT COUNT(*) FROM attack_groups").fetchone()[0]
            if not force and have and all(stored[d] == rel[d]["version"] for d in rel):
                result.update(status="up to date", versions={d: r["version"] for d, r in rel.items()})
            else:
                acc: dict = {"groups": {}, "techniques": {}, "uses": set()}
                for domain, info in rel.items():
                    self.phase = f"downloading {domain} {info['version']}"
                    try:
                        bundle = json.loads(_get(info["url"], MAX_BUNDLE))
                    except ValueError as exc:
                        raise AttackError(f"{domain}: not valid JSON") from exc
                    parse_bundle(domain, bundle, acc)
                    del bundle
                if len(acc["groups"]) < 20 or len(acc["techniques"]) < 100:
                    raise AttackError("The release looks incomplete - keeping the current data")
                self.phase = "updating groups, techniques, watchlists and rules"
                report = apply(acc)
                with get_db() as db:
                    for d, r in rel.items():
                        set_state(db, f"attack_version:{d}", r["version"])
                    set_state(db, "attack_synced_at", str(now()))
                result.update(status="updated", versions={d: r["version"] for d, r in rel.items()}, report=report)
                log.info("ATT&CK updated: %s groups, %s techniques", report["groups"], report["techniques"])
        except (AttackError, netguard.FetchError, netguard.UnsafeURLError) as exc:
            result.update(status="error", error=str(exc)[:300])
            log.warning("ATT&CK sync failed: %s", exc)
        except Exception as exc:  # never kill the scheduler
            log.exception("ATT&CK sync crashed")
            result.update(status="error", error=f"Unexpected error: {type(exc).__name__}")
        finally:
            result["finished"] = now()
            result["seconds"] = int(time.time()) - started
            with get_db() as db:
                set_state(db, "attack_checked_at", str(now()))
                if result.get("status") == "updated":
                    set_state(db, "attack_last_update", json.dumps(result))
                set_state(db, "attack_last_result", json.dumps(result))
            self.phase = ""
            self.running = False


attack_sync = AttackSync()


def status() -> dict:
    with get_db() as db:
        prefs = app_settings.get_all(db)
        state = {k: get_state(db, k) for k in ("attack_checked_at", "attack_synced_at", "attack_last_result", "attack_last_update")}
        versions = {d: get_state(db, f"attack_version:{d}") for d in DOMAINS.values()}
        counts = {"groups": db.execute("SELECT COUNT(*) FROM attack_groups").fetchone()[0],
                  "techniques": db.execute("SELECT COUNT(*) FROM attack_techniques WHERE domain != 'atlas'").fetchone()[0],
                  "relationships": db.execute("SELECT COUNT(*) FROM attack_group_techniques").fetchone()[0]}
        lists = {slug: (r["id"] if r else None) for slug in (GROUPS_SLUG, TECH_SLUG)
                 for r in [db.execute("SELECT id FROM watchlists WHERE slug = ?", (slug,)).fetchone()]}
    checked = int(state["attack_checked_at"] or 0)
    every = INTERVALS.get(prefs["attack_sync"])
    return {
        "schedule": prefs["attack_sync"], "running": attack_sync.running, "phase": attack_sync.phase,
        "checked_at": checked or None, "synced_at": int(state["attack_synced_at"] or 0) or None,
        "next_check": (checked + every) if every and checked else None,
        "versions": versions, "counts": counts, "watchlists": lists,
        "last_result": json.loads(state["attack_last_result"]) if state["attack_last_result"] else None,
        "last_update": json.loads(state["attack_last_update"]) if state["attack_last_update"] else None,
    }


def groups(q: str = "", limit: int = 50, offset: int = 0) -> dict:
    where, params = "", []
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        where = "WHERE g.id LIKE ? ESCAPE '\\' OR g.name LIKE ? ESCAPE '\\' OR g.aliases LIKE ? ESCAPE '\\'"
        params = [like, like, like]
    with get_db() as db:
        total = db.execute(f"SELECT COUNT(*) FROM attack_groups g {where}", params).fetchone()[0]  # nosec B608 - fixed clause
        rows = db.execute(
            f"SELECT g.id, g.name, g.aliases, g.domains, g.url, g.modified, "  # nosec B608 - fixed clause
            f"(SELECT COUNT(*) FROM attack_group_techniques x WHERE x.group_id = g.id) AS techniques "
            f"FROM attack_groups g {where} ORDER BY g.name COLLATE NOCASE LIMIT ? OFFSET ?", [*params, limit, offset]).fetchall()
    return {"total": total, "items": [{**dict(r), "aliases": json.loads(r["aliases"]), "domains": json.loads(r["domains"])} for r in rows]}


def group_detail(group_id: str) -> dict | None:
    with get_db() as db:
        g = db.execute("SELECT * FROM attack_groups WHERE id = ?", (group_id,)).fetchone()
        if g is None:
            return None
        techs = db.execute("SELECT t.id, t.name, t.tactics, t.domain, t.url FROM attack_group_techniques x "
                           "JOIN attack_techniques t ON t.id = x.technique_id WHERE x.group_id = ? ORDER BY t.id",
                           (group_id,)).fetchall()
        entity = db.execute("SELECT e.id FROM entities e JOIN watchlists w ON w.id = e.watchlist_id "
                            "WHERE w.slug = ? AND e.name LIKE ?", (GROUPS_SLUG, f"%({group_id})")).fetchone()
    return {**dict(g), "aliases": json.loads(g["aliases"]), "domains": json.loads(g["domains"]),
            "entity_id": entity["id"] if entity else None,
            "techniques": [{**dict(t), "tactics": json.loads(t["tactics"])} for t in techs]}

