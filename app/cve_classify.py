"""CVE classification into categories (edge devices, RCE, AI/ML, auth bypass, ...).

A CVE joins a category when ANY of these match:
* one of its CWE IDs is in the category's CWE list;
* its description contains one of the category's keywords (literal, whole word, case-insensitive:
  ``re.escape``-d like rules, so user input can never produce a pathological regex);
* one of its affected products matches the category's product patterns:
  ``vendor`` (any product), ``vendor:product``, ``*:product`` or a trailing ``*`` prefix wildcard
  (``microsoft:windows*``). Keys are normalised: lowercase letters and digits only.

OWASP Top Ten is not a category here: it is derived from CWE IDs via MITRE's official mapping
(CWE views 1344 / 1450) and exposed as its own dashboard dimension.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import threading
from dataclasses import dataclass

from app.db import get_db, placeholders
from app.rules import compile_keywords

log = logging.getLogger("feedwarden.cve")

SLUG_RE = re.compile(r"^[a-z0-9-]{1,40}$")
PRODUCT_PATTERN_RE = re.compile(r"^(?:[a-z0-9]{1,64}(?::[a-z0-9]{1,64}\*?)?|\*:[a-z0-9]{1,64}\*?|[a-z0-9]{1,64}\*)$")
MAX_CATEGORIES = 60
MAX_PATTERNS = 300


def norm_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (value or "").lower())[:64]


# (slug, name, description, cwe_ids, keywords, products)
BUILTIN: list[tuple[str, str, str, list[int], list[str], list[str]]] = [
    ("edge-firewall-vpn", "Edge: firewalls, VPNs & gateways",
     "Internet-facing security appliances - the most exploited class in CISA KEV.", [],
     ["SSL VPN", "SSL-VPN", "VPN gateway", "VPN server", "firewall", "secure gateway", "application delivery controller"],
     ["fortinet:fortios", "fortinet:fortiproxy", "fortinet:fortiweb", "fortinet:fortigate*", "fortinet:fortiadc",
      "fortinet:fortimail", "fortinet:fortimanager", "fortinet:fortianalyzer", "fortinet:fortiswitch*",
      "fortinet:fortisiem", "fortinet:fortivoice*", "paloaltonetworks", "paloaltonetworks:panos",
      "cisco:adaptivesecurityappliance*", "cisco:asa*", "cisco:firepower*", "cisco:securefirewall*",
      "cisco:iosxe*", "cisco:identityservicesengine*", "cisco:ise*", "ivanti:connectsecure",
      "ivanti:policysecure", "ivanti:neuronsforzta*", "ivanti:ztagateway", "ivanti:pulseconnectsecure",
      "pulsesecure", "citrix:netscaler*", "citrix:adc", "citrix:gateway", "citrix:applicationdelivery*",
      "sonicwall", "juniper", "checkpoint", "f5", "watchguard", "sophos:firewall", "sophos:sfos",
      "sophos:sophosfirewall", "barracuda", "barracudanetworks", "arraynetworks", "sangfor",
      "hillstonenetworks", "forcepoint", "versanetworks", "openvpn"]),
    ("edge-routers-iot", "Edge: routers, NAS & IoT",
     "SOHO/enterprise routers, NAS boxes, cameras and other connected devices.", [],
     ["router", "NAS device", "IP camera", "network video recorder", "firmware"],
     ["mikrotik", "tplink", "dlink", "netgear", "ubiquiti", "ui", "draytek", "zyxel", "linksys", "tenda", "totolink", "hikvision", "dahua", "qnap", "synology", "wdc", "westerndigital",
      "buffalo", "edimax", "ruijie", "fortinet:fortiwifi*", "cisco:rv*", "cisco:smallbusiness*"]),
    ("remote-access-file-transfer", "Remote access & file transfer",
     "MOVEit, GoAnywhere, CrushFTP, ScreenConnect and similar internet-facing services.", [],
     ["managed file transfer", "remote support", "remote desktop gateway"],
     ["progress:moveit*", "fortra:goanywhere*", "crushftp", "connectwise:screenconnect*", "beyondtrust",
      "citrix:sharefile*", "progress:wsftp*", "solarwinds:servu*", "kiteworks", "accellion",
      "anydesk", "teamviewer", "simplehelp", "microsoft:remotedesktop*"]),
    ("email-collab", "Email & collaboration servers",
     "Exchange, Zimbra, Roundcube, SharePoint, Confluence.", [], [],
     ["microsoft:exchangeserver*", "microsoft:exchange*", "synacor:zimbra*", "zimbra", "roundcube",
      "microsoft:sharepoint*", "atlassian:confluence*", "atlassian:jira*", "smartertools", "mdaemon"]),
    ("rce", "Remote code execution",
     "Code or command injection, unsafe deserialization and upload-to-execute bugs.",
     [94, 95, 96, 77, 78, 502, 917, 1336, 434],
     ["remote code execution", "arbitrary code execution", "execute arbitrary code", "execute arbitrary commands",
      "command injection", "code injection", "OS command injection"], []),
    ("auth-bypass", "Authentication bypass",
     "Missing or broken authentication.", [287, 288, 290, 294, 302, 306, 1390, 1391],
     ["authentication bypass", "bypass authentication", "bypass the authentication"], []),
    ("privilege-escalation", "Privilege escalation",
     "Gaining higher privileges.", [269, 250, 266, 268, 274],
     ["privilege escalation", "elevation of privilege", "escalate privileges", "escalate their privileges"], []),
    ("memory-corruption", "Memory corruption",
     "Overflows, use-after-free, out-of-bounds read/write.", [119, 120, 121, 122, 125, 190, 415, 416, 787, 788, 843],
     ["buffer overflow", "heap overflow", "stack overflow", "use-after-free", "use after free",
      "out-of-bounds write", "out-of-bounds read", "memory corruption"], []),
    ("injection-sqli", "SQL injection", "", [89, 564], ["SQL injection"], []),
    ("xss", "Cross-site scripting", "", [79, 80, 83, 87], ["cross-site scripting"], []),
    ("ssrf", "Server-side request forgery", "", [918], ["server-side request forgery", "SSRF"], []),
    ("path-traversal", "Path traversal / file read", "", [22, 23, 35, 36, 73, 98],
     ["path traversal", "directory traversal", "local file inclusion", "arbitrary file read"], []),
    ("xxe", "XML external entity", "", [611, 776], ["XML external entity", "XXE"], []),
    ("csrf", "Cross-site request forgery", "", [352], ["cross-site request forgery", "CSRF"], []),
    ("deserialization", "Unsafe deserialization", "", [502], ["deserialization"], []),
    ("dos", "Denial of service", "", [400, 770, 674, 835, 1333, 476, 404],
     ["denial of service", "denial-of-service"], []),
    ("info-disclosure", "Information disclosure", "", [200, 201, 209, 212, 532, 538, 552],
     ["information disclosure", "sensitive information", "information leak"], []),
    ("ai-ml", "AI / ML & LLM",
     "Vulnerabilities in AI frameworks, model servers, agents and LLM apps (incl. prompt injection).",
     [1426, 1427],
     ["large language model", "LLM", "prompt injection", "machine learning", "AI agent", "AI model",
      "model context protocol", "MCP server", "jailbreak", "inference server", "generative AI"],
     ["*:pytorch", "pytorch", "*:tensorflow", "google:tensorflow", "*:langchain*", "langchain", "*:llamaindex",
      "ollama", "*:ollama", "*:mlflow", "mlflow", "lfprojects:mlflow", "huggingface",
      "*:transformers", "gradio", "*:gradio", "vllm", "*:vllm", "anyscale:ray", "*:comfyui", "*:openwebui",
      "openwebui", "*:onnx*", "*:keras", "*:litellm", "berriai", "mintplexlabs", "*:anythingllm",
      "langgenius", "*:dify", "flowiseai", "*:flowise", "*:langflow", "langflowai", "significantgravitas",
      "nvidia:triton*", "nvidia:nemo*", "*:sglang", "*:llamacpp", "ggml", "*:localai", "*:lobechat",
      "*:librechat", "*:chatgptnextweb", "*:h2ogpt", "*:kserve", "*:bentoml", "bentoml", "*:jupyter*"]),
    ("operating-systems", "Operating systems",
     "Windows, Linux kernel, macOS, iOS, Android.", [], [],
     ["microsoft:windows*", "linux:linuxkernel", "linux", "apple:macos", "apple:iphoneos",
      "apple:ios", "apple:ipados", "apple:visionos", "apple:watchos", "google:android", "android"]),
    ("browsers", "Web browsers", "", [], [],
     ["google:chrome", "mozilla:firefox*", "apple:safari", "microsoft:edge*", "*:chromium", "opera:opera*",
      "brave:brave*"]),
    ("virtualization", "Virtualization & cloud infra",
     "Hypervisors, vCenter, Kubernetes & container runtimes.", [], ["hypervisor", "virtual machine escape"],
     ["vmware", "broadcom:vmware*", "*:esxi", "*:vcenter*", "citrix:hypervisor", "proxmox", "xen", "*:xen",
      "qemu", "*:hyperv", "kubernetes", "*:kubernetes", "*:containerd", "*:runc", "docker", "*:docker*"]),
    ("ics-ot", "ICS / OT", "Industrial control systems and operational technology.", [],
     ["SCADA", "programmable logic controller", "PLC", "industrial control", "HMI"],
     ["siemens", "schneiderelectric", "schneider", "rockwellautomation", "abb", "honeywell", "mitsubishielectric",
      "emerson", "omron", "deltaelectronics", "delta", "moxa", "phoenixcontact", "yokogawa", "wago", "ge",
      "gevernova", "inductiveautomation", "advantech", "beckhoff", "codesys", "festo", "hitachienergy"]),
    ("wordpress", "WordPress & plugins",
     "High-volume plugin/theme CVEs - useful to filter in or out.", [],
     ["WordPress", "plugin for WordPress", "WordPress plugin", "WordPress theme"], ["wordpress", "*:wordpress"]),
]


@dataclass
class CompiledCategory:
    id: int
    slug: str
    cwes: frozenset[int]
    keywords: re.Pattern[str] | None
    vendors: frozenset[str]
    pairs: frozenset[tuple[str, str]]
    any_vendor_products: frozenset[str]
    prefixes: tuple[tuple[str, str], ...]  # (vendor or "*", product prefix)


def validate_patterns(products: list[str]) -> list[str]:
    out = []
    for p in products[:MAX_PATTERNS]:
        p = p.strip().lower()
        if not p:
            continue
        if not PRODUCT_PATTERN_RE.match(p):
            raise ValueError(f"invalid product pattern: {p[:40]!r} (use vendor, vendor:product, *:product, prefix*)")
        out.append(p)
    return out


def compile_category(row: sqlite3.Row) -> CompiledCategory:
    vendors, pairs, any_vendor, prefixes = set(), set(), set(), []
    for pat in json.loads(row["products"] or "[]"):
        if ":" in pat:
            vendor, product = pat.split(":", 1)
        else:
            vendor, product = pat, ""
        if product.endswith("*") or (not product and vendor.endswith("*")):
            if product:
                prefixes.append((vendor, product[:-1]))
            else:
                prefixes.append((vendor[:-1], ""))  # vendor prefix
            continue
        if not product:
            vendors.add(vendor)
        elif vendor == "*":
            any_vendor.add(product)
        else:
            pairs.add((vendor, product))
    kws = tuple(str(k) for k in json.loads(row["keywords"] or "[]"))
    return CompiledCategory(
        id=row["id"], slug=row["slug"], cwes=frozenset(int(c) for c in json.loads(row["cwe_ids"] or "[]")),
        keywords=compile_keywords(kws), vendors=frozenset(vendors), pairs=frozenset(pairs),
        any_vendor_products=frozenset(any_vendor), prefixes=tuple(prefixes),
    )


def _product_match(cat: CompiledCategory, products: list[tuple[str, str]]) -> bool:
    for vendor, product in products:
        if vendor in cat.vendors or (vendor, product) in cat.pairs or product in cat.any_vendor_products:
            return True
        for pv, pp in cat.prefixes:
            if pp == "" and vendor.startswith(pv):
                return True
            if pp and (pv == "*" or pv == vendor) and product.startswith(pp):
                return True
    return False


def matches(cat: CompiledCategory, description: str, cwes: set[int], products: list[tuple[str, str]]) -> bool:
    if cat.cwes and cwes & cat.cwes:
        return True
    if products and _product_match(cat, products):
        return True
    return bool(cat.keywords and description and cat.keywords.search(description))


def load_categories(db: sqlite3.Connection) -> list[CompiledCategory]:
    return [compile_category(r) for r in db.execute("SELECT * FROM cve_categories WHERE enabled = 1 ORDER BY position, id")]


def classify(db: sqlite3.Connection, cve_ids: list[str], categories: list[CompiledCategory] | None = None) -> int:
    """(Re)compute category membership for the given CVEs. Returns rows written."""
    if not cve_ids:
        return 0
    cats = categories if categories is not None else load_categories(db)
    written = 0
    for start in range(0, len(cve_ids), 500):
        chunk = cve_ids[start:start + 500]
        ph = placeholders(len(chunk))
        desc = {r[0]: r[1] for r in db.execute(f"SELECT id, description FROM cves WHERE id IN ({ph})", chunk)}
        cwes: dict[str, set[int]] = {i: set() for i in chunk}
        for r in db.execute(f"SELECT cve_id, cwe_id FROM cve_cwes WHERE cve_id IN ({ph})", chunk):
            cwes[r[0]].add(r[1])
        prods: dict[str, list[tuple[str, str]]] = {i: [] for i in chunk}
        for r in db.execute(f"SELECT cve_id, vendor_key, product_key FROM cve_products WHERE cve_id IN ({ph})", chunk):
            prods[r[0]].append((r[1], r[2]))
        db.execute(f"DELETE FROM cve_category_map WHERE cve_id IN ({ph})", chunk)
        rows = [(cid, cat.id) for cid in chunk if cid in desc
                for cat in cats if matches(cat, desc[cid], cwes[cid], prods[cid])]
        db.executemany("INSERT OR IGNORE INTO cve_category_map (cve_id, category_id) VALUES (?, ?)", rows)
        written += len(rows)
    return written


def seed_builtin(db: sqlite3.Connection) -> int:
    """Insert built-in categories that do not exist yet (user edits/deletions are respected once seeded)."""
    seeded = {r[0] for r in db.execute("SELECT value FROM sync_state WHERE key LIKE 'cvecat_seeded:%'")}
    added = 0
    for pos, (slug, name, desc, cwes, kws, prods) in enumerate(BUILTIN):
        if slug in seeded:
            continue
        db.execute(
            "INSERT OR IGNORE INTO cve_categories (slug, name, description, builtin, cwe_ids, keywords, products, position) "
            "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
            (slug, name, desc, json.dumps(cwes), json.dumps(kws), json.dumps(validate_patterns(prods)), pos),
        )
        db.execute("INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, ?)", (f"cvecat_seeded:{slug}", slug))
        added += 1
    return added


class Reclassifier:
    """Background re-classification of every stored CVE (after category edits). Coalesces requests."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pending = False
        self._running = False

    @property
    def busy(self) -> bool:
        return self._running or self._pending

    def request(self) -> None:
        with self._lock:
            self._pending = True
            if self._running:
                return
            self._running = True
        threading.Thread(target=self._run, name="cve-reclassify", daemon=True).start()

    def _run(self) -> None:
        try:
            while True:
                with self._lock:
                    if not self._pending:
                        self._running = False
                        return
                    self._pending = False
                with get_db() as db:
                    ids = [r[0] for r in db.execute("SELECT id FROM cves ORDER BY id")]
                    cats = load_categories(db)
                total = 0
                for start in range(0, len(ids), 2000):
                    with get_db() as db:  # short transactions: never starve the fetcher or UI
                        total += classify(db, ids[start:start + 2000], cats)
                log.info("CVE categories rebuilt: %d memberships over %d CVEs", total, len(ids))
        except Exception:
            log.exception("CVE re-classification failed")
            with self._lock:
                self._running = False


reclassifier = Reclassifier()
