"""Ready-made collections: each pack is a set of collections plus the keyword rules that fill them.

A collection may have several rules (they are ORed: an article that matches any of them is filed).
Inside one rule: any of `keywords` AND any of `require` AND the CVE condition, and none of `exclude`.
Keywords are literal, case-insensitive and whole-word (see app.rules), never regular expressions.

Rule names are "Auto: <collection>" (plus " #2", " #3"... for extra rules), which is what makes
installing a pack idempotent: a rule whose name already exists is left alone, so edits survive.
"""

from __future__ import annotations

from typing import TypedDict


class RuleSpec(TypedDict, total=False):
    keywords: list[str]
    require: list[str]
    exclude: list[str]
    match_in: str            # "title" | "title_opening" (title + opening lines of the article) | "title_content" (default)
    title_keywords: bool     # `keywords` must be in the title; `require`/`exclude` follow match_in
    folder: str              # restrict to the folder with this name (created when missing)
    cve_severity: str        # CRITICAL | HIGH | MEDIUM | LOW
    cve_owasp: str           # "2025:A01"
    cve_category: str        # CVE-tracking category slug ("rce", ...) or "kev" / "kev-ransomware"


class CollectionSpec(TypedDict):
    name: str
    color: str
    rules: list[RuleSpec]


class Pack(TypedDict):
    slug: str
    title: str
    description: str
    collections: list[CollectionSpec]


# ------------------------------------------------------------------ shared vocabularies
OT = [
    "OT", "operational technology", "ICS", "industrial control system", "industrial control systems",
    "industrial control", "SCADA", "PLC", "PLCs", "programmable logic controller", "HMI", "DCS",
    "distributed control system", "Modbus", "DNP3", "IEC 61850", "IEC 62443", "IEC-104", "OPC UA", "Profinet",
    "BACnet", "EtherNet/IP", "safety instrumented system", "ICSA", "ICS-CERT", "Siemens SIMATIC", "SIMATIC",
    "Rockwell Automation", "Allen-Bradley", "Schneider Electric", "Modicon", "Triconex", "Honeywell Experion",
    "Emerson DeltaV", "Yokogawa", "Mitsubishi Electric", "Moxa", "Unitronics", "Stuxnet", "Triton", "Trisis",
    "Industroyer", "Industroyer2", "Pipedream", "Incontroller", "FrostyGoop", "Fuxnet", "IOCONTROL",
    "BlackEnergy", "Volt Typhoon", "water utility", "water utilities", "water treatment", "wastewater",
    "power grid", "electric grid", "substation", "pipeline operator", "manufacturing plant", "smart grid",
    "IIoT", "industrial IoT", "cyber-physical", "Purdue model", "Dragos", "Claroty", "Nozomi Networks",
]
AI = [
    "AI", "A.I.", "artificial intelligence", "LLM", "LLMs", "large language model", "large language models",
    "generative AI", "GenAI", "gen AI", "machine learning", "deep learning", "neural network", "ChatGPT",
    "OpenAI", "GPT-4", "GPT-5", "Claude", "Anthropic", "Gemini", "Copilot", "Llama", "Mistral", "DeepSeek",
    "Grok", "agentic", "AI agent", "AI agents", "AI model", "AI models", "foundation model", "chatbot",
    "chatbots", "MCP server", "Model Context Protocol", "deepfake", "deepfakes",
]
ATTACK_WORDS = [
    "attack", "attacks", "attacked", "attacker", "attackers", "breach", "breached", "compromise", "compromised",
    "intrusion", "intrusions", "hack", "hacked", "hackers", "hacktivist", "hacktivists", "ransomware", "malware",
    "wiper", "sabotage", "disruption", "disrupted", "outage", "threat actor", "threat actors", "campaign",
    "targeted", "targeting", "espionage", "cyberattack", "cyberattacks", "cyber attack", "incident", "botnet",
]
VULN_WORDS = [
    "vulnerability", "vulnerabilities", "CVE", "CVEs", "advisory", "advisories", "flaw", "flaws", "patch",
    "patches", "patched", "security update", "firmware update", "exploit", "exploitable", "zero-day", "0-day",
    "ICSA", "CVSS", "bug", "bugs", "remote code execution", "authentication bypass", "denial of service",
]
DEFENCE_WORDS = [
    "forensics", "forensic", "DFIR", "incident response", "detection", "detect", "monitoring", "visibility",
    "defense", "defence", "defensive", "defender", "defenders", "hardening", "segmentation", "network segmentation",
    "asset inventory", "asset visibility", "threat hunting", "anomaly detection", "engineering", "engineers",
    "safety", "resilience", "best practices", "guidance", "framework", "IEC 62443", "NIST", "Purdue model",
    "secure by design", "zero trust", "tabletop", "training", "lessons learned", "case study", "architecture",
]
OFFENSIVE_WORDS = [
    "pentest", "pentesting", "pen test", "penetration test", "penetration testing", "penetration tester",
    "red team", "red teaming", "red teamer", "ethical hacking", "ethical hacker", "offensive security",
    "bug bounty", "bug hunting", "exploit development", "exploit generation", "vulnerability discovery",
    "vulnerability research", "fuzzing", "fuzzer", "adversary emulation", "purple team", "CTF",
    "capture the flag", "hacking agent", "autonomous hacking", "AI hacking", "XBOW",
]
SOC_WORDS = [
    "SOC", "SOCs", "security operations", "security operations center", "security operations centre",
    "incident response", "incident responders", "detection engineering", "detection rule", "detection rules",
    "threat hunting", "threat hunt", "threat hunter", "SIEM", "SOAR", "EDR", "XDR", "MDR", "NDR", "Sigma rule",
    "Sigma rules", "YARA", "YARA rule", "DFIR", "digital forensics", "blue team", "triage", "alert fatigue",
    "KQL", "Splunk", "Microsoft Sentinel", "Elastic Security", "Velociraptor", "detection-as-code",
]
CRYPTO = [
    "blockchain", "crypto", "cryptocurrency", "cryptocurrencies", "bitcoin", "BTC", "ethereum", "ETH",
    "Solana", "stablecoin", "stablecoins", "USDT", "Tether", "DeFi", "decentralized finance", "NFT", "NFTs",
    "Web3", "smart contract", "smart contracts", "crypto exchange", "cryptocurrency exchange", "Binance",
    "Coinbase", "Kraken", "Bybit", "crypto wallet", "hot wallet", "cold wallet", "MetaMask", "altcoin",
    "memecoin", "cross-chain bridge", "blockchain bridge", "layer 2", "on-chain",
]
CRYPTO_HACK_WORDS = [
    "hack", "hacked", "hackers", "heist", "stolen", "stole", "theft", "drained", "drainer", "wallet drainer",
    "exploit", "exploited", "exploiter", "rug pull", "scam", "scams", "scammers", "pig butchering", "breach",
    "compromised", "flash loan", "private key", "private keys", "laundered", "laundering", "Lazarus",
    "TraderTraitor", "phishing", "address poisoning",
]


# Threat advisories: advisories, alerts, guidance and reports from governments, CERTs, vendors and research teams.
# Matched in the title, so news that merely mentions an agency is not pulled in; CVE listings stay out (they have
# their own CVEs collections).
ADVISORY_WORDS = ["advisory", "advisories", "joint advisory", "cybersecurity advisory", "security advisory",
                  "threat advisory", "security alert", "cybersecurity alert", "flash alert", "FLASH", "bulletin",
                  "guidance", "joint guidance", "best practices", "warns", "warn", "urges", "threat report",
                  "threat assessment", "threat landscape", "annual report", "activity report", "threat intelligence report",
                  "incident response report", "global threat report", "M-Trends", "DBIR", "factsheet", "fact sheet",
                  "mitigations", "hardening guide"]
ADVISORY_ISSUERS = ["CISA", "FBI", "NSA", "DHS", "IC3", "Five Eyes", "NCSC", "ACSC", "ASD", "Cyber Centre",
                    "Canadian Centre for Cyber Security", "CCCS", "ENISA", "CERT", "CERT-EU", "CERT-UA", "CERT-FR",
                    "CERT-In", "CERT Polska", "CSIRT", "BSI", "ANSSI", "JPCERT", "KISA", "Europol", "Interpol",
                    "Secret Service", "Treasury", "OFAC", "HHS", "HC3", "GCHQ", "NCA", "MS-ISAC", "ISAC",
                    "Microsoft", "MSTIC", "Google", "GTIG", "Mandiant", "Unit 42", "Palo Alto Networks", "Talos",
                    "Cisco", "CrowdStrike", "SentinelOne", "Kaspersky", "ESET", "Check Point", "Sophos", "Trend Micro",
                    "Proofpoint", "Recorded Future", "Rapid7", "Tenable", "Fortinet", "FortiGuard", "Dragos",
                    "Claroty", "Nozomi", "IBM X-Force", "X-Force", "Secureworks", "Huntress", "Arctic Wolf",
                    "Symantec", "Akamai", "Cloudflare", "Verizon", "DBIR", "Siemens", "Schneider Electric"]
NOT_ADVISORY = ["CVE", "CVEs", "KEV", "Known Exploited Vulnerabilities", "Known Exploited Vulnerability",
                "Patch Tuesday", "webinar", "sponsored", "podcast", "earnings", "stock", "shares", "reportedly",
                "employees", "new feature", "feature", "rolls out", "launches"]

# ------------------------------------------------------------------ packs
# The broad threat collections search the title and the opening lines of an article ("title_opening"), not the whole
# text: a word mentioned in passing deep in an article ("...a suspected Chinese espionage case...", "sudo apt install",
# "unlike ransomware...") must not file it (2026-11-26).
APT_GROUPS = [
    "Lazarus", "Lazarus Group", "Kimsuky", "Andariel", "BlueNoroff", "ScarCruft", "APT37", "APT38", "APT43",
    "TraderTraitor", "Moonstone Sleet", "Jade Sleet", "Sapphire Sleet", "Diamond Sleet", "Emerald Sleet", "Onyx Sleet",
    "Volt Typhoon", "Salt Typhoon", "Silk Typhoon", "Flax Typhoon", "Linen Typhoon", "Violet Typhoon", "Brass Typhoon",
    "Mustang Panda", "APT1", "APT3", "APT10", "APT15", "APT27", "APT31", "APT40", "APT41", "Winnti", "Earth Lusca",
    "Earth Estries", "RedHotel", "BlackTech", "Naikon", "Ke3chang", "Lotus Blossom", "UNC3886", "UNC5221", "Storm-0558",
    "Fancy Bear", "Cozy Bear", "APT28", "APT29", "Sandworm", "Turla", "Gamaredon", "Nobelium", "Midnight Blizzard",
    "Forest Blizzard", "Seashell Blizzard", "Star Blizzard", "Secret Blizzard", "Cadet Blizzard", "Void Blizzard",
    "Laundry Bear", "Ember Bear", "Cold River", "ColdRiver", "Callisto",
    "Charming Kitten", "APT33", "APT34", "APT35", "APT42", "OilRig", "MuddyWater", "Mint Sandstorm", "Peach Sandstorm",
    "Cobalt Mirage", "Equation Group", "Sidewinder", "Transparent Tribe", "DarkHotel",
]
NATION_STATE_WORDS = [
    "APT", "APTs", "advanced persistent threat", "nation-state", "nation-states", "nation state", "state-sponsored",
    "state sponsored", "state-backed", "state-linked", "state-aligned", "government-backed", "state hackers",
    "cyberespionage", "cyber espionage", "cyber-espionage", "espionage", "China-linked", "China-nexus", "China-backed",
    "Russia-linked", "Russia-backed", "Russia-nexus", "Iran-linked", "Iran-backed", "Iran-nexus", "North Korea-linked",
    "North Korean hackers", "Chinese hackers", "Russian hackers", "Iranian hackers", "Kremlin-backed", "Beijing-backed",
    "military hackers", "GRU hackers", "intelligence hackers", "spy agency", "North Korea", "North Korean", "DPRK",
    "cyberwarfare", "cyber warfare", "cyber-warfare",
]
CYBER_CONTEXT = [  # a nation-state word alone ("espionage", "spy agency") is not enough: it must be about hacking
    "hacker", "hackers", "hacking", "hacked", "cyber", "cyberattack", "cyberattacks", "cyber attack", "cyber attacks",
    "cyberespionage", "cyber espionage", "cyber-espionage", "malware", "backdoor", "backdoors", "phishing",
    "spear-phishing", "intrusion", "intrusions", "breach", "breached", "exploit", "exploits", "exploited", "zero-day",
    "zero-days", "vulnerability", "vulnerabilities", "threat actor", "threat actors", "APT", "ransomware", "spyware",
    "implant", "wiper", "compromised", "infiltrated", "cybercrime", "botnet", "threat group", "hacking group",
    "cyber operations",
]
ZERO_DAY_WORDS = [
    "zero-day", "zero-days", "0-day", "0-days", "zeroday", "actively exploited", "exploited in the wild",
    "proof of concept", "poc exploit", "rce", "remote code execution"]

CORE: list[CollectionSpec] = [
    {"name": "Ransomware", "color": "#dc2626", "rules": [{"match_in": "title_opening", "keywords": [
        "ransomware", "lockbit", "blackcat", "alphv", "akira", "clop", "cl0p", "play ransomware", "black basta",
        "rhysida", "medusa", "qilin", "extortion", "double extortion", "data leak site"]}]},
    {"name": "Zero-days & Exploits", "color": "#be185d", "rules": [{"match_in": "title_opening", "keywords": ZERO_DAY_WORDS}]},
    {"name": "APT & Nation-State", "color": "#7c3aed", "rules": [
        {"match_in": "title_opening", "keywords": APT_GROUPS},
        {"match_in": "title_opening", "keywords": NATION_STATE_WORDS, "require": CYBER_CONTEXT}]},
    {"name": "Phishing & Social Eng.", "color": "#0ea5e9", "rules": [{"match_in": "title_opening", "keywords": [
        "phishing", "smishing", "vishing", "business email compromise", "bec", "credential harvesting",
        "social engineering", "qr code phishing"]}]},
    {"name": "Breaches & Leaks", "color": "#ea580c", "rules": [{"match_in": "title_opening", "keywords": [
        "data breach", "breach", "leaked", "exposed database", "stolen data", "compromised accounts"]}]},
    {"name": "Malware", "color": "#16a34a", "rules": [{"match_in": "title_opening", "keywords": [
        "malware", "trojan", "infostealer", "stealer", "botnet", "loader", "backdoor", "rootkit", "wiper", "rat"]}]},
    {"name": "Supply Chain", "color": "#0891b2", "rules": [{"match_in": "title_opening", "keywords": [
        "supply chain", "supply-chain", "malicious package", "npm", "pypi", "dependency confusion", "typosquat"]}]},
]

OT_PACK: list[CollectionSpec] = [
    {"name": "OT/ICS: Attacks & breaches", "color": "#b45309", "rules": [{"keywords": OT, "require": ATTACK_WORDS, "title_keywords": True,
                                                                    "exclude": ["ICSA", "CVSS", "SSA"]}]},
    {"name": "OT/ICS: Vulnerabilities & CVEs", "color": "#d97706", "rules": [
        {"keywords": OT, "require": VULN_WORDS, "title_keywords": True},
        {"keywords": ["ICSA", "ICS advisory", "ICS advisories", "ICS medical advisory"]}]},
    {"name": "OT/ICS: AI in OT", "color": "#a16207", "rules": [{"keywords": OT, "require": AI, "title_keywords": True}]},
    {"name": "OT/ICS: Defence, forensics & engineering", "color": "#65a30d", "rules": [
        {"keywords": OT, "require": DEFENCE_WORDS, "title_keywords": True}]},
]

PRACTICE: list[CollectionSpec] = [
    {"name": "Offensive security", "color": "#e11d48", "rules": [{"keywords": OFFENSIVE_WORDS, "match_in": "title_opening"}]},
    {"name": "Defensive security", "color": "#2563eb", "rules": [{"keywords": SOC_WORDS, "match_in": "title_opening"}]},
    {"name": "Threat intelligence", "color": "#7c3aed", "rules": [
        {"match_in": "title_opening", "keywords": ["threat intelligence", "threat intel", "CTI", "TTPs", "indicators of compromise", "IOCs",
                      "threat report", "threat landscape", "threat actor", "threat actors", "attribution",
                      "attributed", "APT", "intrusion set", "tradecraft", "MITRE ATT&CK", "campaign analysis",
                      "threat research", "threat analysis"]},
        {"keywords": [], "folder": "Threat Intelligence"}]},
    # Everything in the Advisories folder (government, CERT and vendor PSIRT feeds; keep CVE-listing feeds such as
    # cvefeed.io or MSRC's update guide in another folder), plus advisories and reports published elsewhere.
    {"name": "Threat advisories", "color": "#f97316", "rules": [
        {"keywords": [], "folder": "Advisories", "match_in": "title",
         "exclude": ["Known Exploited Vulnerabilities", "Known Exploited Vulnerability"]},
        {"keywords": ADVISORY_WORDS, "require": ADVISORY_ISSUERS, "match_in": "title", "exclude": NOT_ADVISORY}]},
]

AI_PACK: list[CollectionSpec] = [
    {"name": "AI: Offensive AI", "color": "#db2777", "rules": [
        {"keywords": AI, "require": OFFENSIVE_WORDS + [
            "AI-powered attack", "AI-powered attacks", "AI-generated malware", "AI-generated phishing",
            "malicious AI", "weaponized", "weaponize", "weaponizing", "WormGPT", "FraudGPT", "cybercriminals",
            "threat actors", "attackers", "malware", "phishing", "exploit", "exploits", "hacking"], "title_keywords": True}]},
    {"name": "AI: Defensive AI", "color": "#4f46e5", "rules": [
        {"keywords": AI, "require": SOC_WORDS + [
            "threat detection", "detection", "defenders", "defensive", "defense", "defence", "security analyst",
            "security analysts", "automated response", "anomaly detection", "Security Copilot", "AI SOC",
            "autonomous SOC", "stop attacks", "block attacks"], "title_keywords": True}]},
    {"name": "AI: AI security", "color": "#9333ea", "rules": [
        {"keywords": ["prompt injection", "indirect prompt injection", "jailbreak", "jailbreaks", "jailbreaking",
                      "model poisoning", "data poisoning", "training data poisoning", "adversarial machine learning",
                      "adversarial AI", "model theft", "model extraction", "model inversion", "AI red teaming",
                      "AI red team", "LLM security", "AI security", "securing AI", "agent hijacking",
                      "tool poisoning", "OWASP LLM", "OWASP Top 10 for LLM", "shadow AI",
                      "AI supply chain", "malicious model", "malicious models", "MITRE ATLAS"]},
        {"keywords": AI, "require": ["vulnerability", "vulnerabilities", "flaw", "flaws", "CVE", "exploit",
                                     "exploited", "hijack", "hijacked", "hijacking", "poisoned", "leak", "leaked",
                                     "exfiltrate", "exfiltration", "backdoor", "backdoored", "bypass"],
         "match_in": "title"}]},
    {"name": "AI: News & tools", "color": "#0d9488", "rules": [
        {"keywords": AI + ["AI tool", "AI tools", "model release", "open-weight", "open-source model",
                           "AI startup", "AI lab", "multimodal", "reasoning model", "AI assistant", "AI coding"],
         "match_in": "title"},
        {"keywords": [], "folder": "AI"}]},
]

# The ATT&CK Enterprise matrix (v20). No keyword rules: an article is filed under a tactic when it names one of the
# tactic's techniques or sub-techniques (app/ttp_filing.py); the list follows MITRE's matrix after each sync.
ATTACK_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Stealth", "Defense Impairment", "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
ATTACK: list[CollectionSpec] = [{"name": f"ATT&CK: {tactic}", "color": "#475569", "rules": []} for tactic in ATTACK_TACTICS]

# MITRE ATLAS (attacks on and with AI systems). Everyday terms per technique: (a note of the tactics it serves, the
# terms). The terms are aliases of the technique in the ATLAS watchlist; official names and IDs are added by
# app/atlas_sync.py from MITRE's data, and the tactics an article is filed under come from that data, not from here.
ATLAS_TERMS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "AML.T0051": (("Execution",), ("prompt injection", "prompt injections", "indirect prompt injection",
                                   "direct prompt injection", "injected prompt", "injected prompts", "malicious prompt",
                                   "malicious prompts", "prompt injection attack", "prompt injection attacks")),
    "AML.T0054": (("Defense evasion", "Privilege escalation"), (
        "LLM jailbreak", "LLM jailbreaks", "AI jailbreak", "AI jailbreaks", "jailbreak prompt", "jailbreak prompts",
        "chatbot jailbreak", "model jailbreak", "jailbreaking LLMs", "jailbreaking AI", "guardrail bypass",
        "bypass guardrails", "bypassing guardrails", "bypass AI guardrails", "bypass safety guardrails")),
    "AML.T0020": (("Persistence",), ("data poisoning", "training data poisoning", "poisoned training data",
                                     "poisoned dataset", "poisoned datasets", "dataset poisoning")),
    "AML.T0018": (("AI attack adaptation", "Persistence"), (
        "model poisoning", "poisoned model", "poisoned models", "backdoored model", "backdoored models",
        "model backdoor", "model backdoors", "backdoored AI model", "backdoored AI models")),
    "AML.T0070": (("Persistence",), ("RAG poisoning", "poisoned RAG", "knowledge base poisoning", "vector database poisoning")),
    "AML.T0080": (("Persistence",), ("memory poisoning", "context poisoning", "agent memory poisoning", "poisoned memory")),
    "AML.T0110": (("Persistence",), ("tool poisoning", "MCP tool poisoning", "poisoned MCP", "malicious MCP server",
                                     "malicious MCP servers", "poisoned tool descriptions", "tool shadowing")),
    "AML.T0109": (("Defense evasion",), ("MCP rug pull", "MCP rug pulls")),
    "AML.T0010": (("Initial access",), (
        "AI supply chain", "AI supply chain attack", "AI supply chain attacks", "ML supply chain", "model supply chain",
        "malicious AI model", "malicious AI models", "malicious ML model", "malicious ML models",
        "malicious Hugging Face", "malicious pickle", "malicious pickle file", "malicious pickle files")),
    "AML.T0060": (("Resource development",), ("slopsquatting", "hallucinated package", "hallucinated packages",
                                              "package hallucination", "package hallucinations")),
    "AML.T0017": (("Resource development",), (
        "AI-generated malware", "AI-written malware", "LLM-generated malware", "AI-developed malware",
        "AI-generated exploit", "AI-generated exploits", "WormGPT", "FraudGPT", "malicious LLM", "malicious LLMs")),
    "AML.T0015": (("Defense evasion", "Impact"), (
        "adversarial example", "adversarial examples", "adversarial evasion", "adversarial machine learning",
        "adversarial ML")),
    "AML.T0043": (("AI attack adaptation",), (
        "adversarial input", "adversarial inputs", "adversarial perturbation", "adversarial perturbations",
        "adversarial patch", "adversarial patches", "adversarial suffix", "adversarial prompt", "adversarial prompts")),
    "AML.T0088": (("AI attack adaptation",), ("deepfake", "deepfakes", "voice cloning", "voice clone", "cloned voice",
                                              "AI-generated video", "AI-generated videos", "synthetic media")),
    "AML.T0124": (("AI attack adaptation",), (
        "AI-orchestrated", "AI-orchestrated attack", "AI-orchestrated attacks", "AI-orchestrated espionage",
        "autonomous cyberattack", "autonomous cyberattacks", "agentic attack", "agentic attacks")),
    "AML.T0052": (("Initial access",), (
        "AI-generated phishing", "AI phishing", "AI-powered phishing", "LLM-generated phishing", "deepfake phishing",
        "deepfake vishing", "deepfake scam", "deepfake scams", "deepfake fraud")),
    "AML.T0132": (("Initial access",), ("exposed Ollama", "exposed LLM", "exposed LLMs", "exposed AI server",
                                        "exposed AI servers", "exposed MCP server", "exposed MCP servers",
                                        "exposed AI service", "exposed AI services")),
    "AML.T0011": (("Execution",), ("pickle deserialization", "unsafe pickle", "malicious GGUF", "malicious safetensors",
                                   "malicious model file", "malicious model files")),
    "AML.T0053": (("Execution", "Privilege escalation"), (
        "agent hijacking", "AI agent hijacking", "hijacked AI agent", "hijacked AI agents", "hijack AI agents",
        "excessive agency")),
    "AML.T0061": (("Persistence",), ("AI worm", "AI worms", "prompt worm", "self-replicating prompt",
                                     "self-replicating prompts", "Morris II")),
    "AML.T0069": (("Discovery",), ("system prompt leak", "system prompt leaks", "system prompt leakage",
                                   "system prompt extraction", "leaked system prompt", "leaked system prompts",
                                   "prompt leaking", "prompt leak", "prompt leakage")),
    "AML.T0137": (("Collection",), ("model inversion", "membership inference", "training data extraction",
                                    "extract training data", "memorized training data")),
    "AML.T0024": (("Exfiltration",), ("model extraction", "model extraction attack", "model extraction attacks",
                                      "model stealing", "distillation attack", "distillation attacks")),
    "AML.T0086": (("Exfiltration",), ("EchoLeak", "AI agent data exfiltration", "zero-click AI")),
    "AML.T0077": (("Exfiltration",), ("markdown image exfiltration", "markdown exfiltration")),
    "AML.T0048": (("Impact",), ("model theft", "stolen model weights", "AI intellectual property theft")),
    "AML.T0034": (("Impact",), ("LLMjacking", "denial of wallet", "denial-of-wallet", "cost harvesting")),
    "AML.T0029": (("Impact",), ("sponge attack", "sponge attacks", "sponge examples", "denial of AI service",
                                "model denial of service")),
}
ATLAS_TACTICS = [
    "Reconnaissance", "Resource Development", "AI Attack Adaptation", "Initial Access", "AI Model Access", "Execution",
    "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
    "Command and Control", "Exfiltration", "Impact",
]
# No keyword rules: the collections are filed from the techniques an article names (app/ttp_filing.py), and follow
# the tactics of MITRE's current matrix once a sync has stored it.
ATLAS: list[CollectionSpec] = [{"name": f"ATLAS: {tactic}", "color": "#7c3aed", "rules": []} for tactic in ATLAS_TACTICS]

OWASP: list[CollectionSpec] = [
    {"name": "OWASP: A01 Broken access control", "color": "#0f766e", "rules": [
        {"keywords": ["broken access control", "improper access control", "IDOR", "insecure direct object reference",
                      "authorization bypass", "authorisation bypass", "path traversal", "directory traversal",
                      "CSRF", "cross-site request forgery", "SSRF", "server-side request forgery",
                      "missing authorization"]},
        {"keywords": [], "cve_owasp": "2025:A01"}]},
    {"name": "OWASP: A02 Security misconfiguration", "color": "#0f766e", "rules": [
        {"keywords": ["misconfiguration", "misconfigurations", "misconfigured", "default credentials",
                      "default configuration", "exposed database", "unsecured database", "open S3 bucket",
                      "exposed bucket", "publicly exposed", "exposed admin panel", "XXE", "XML external entity",
                      "directory listing", "verbose errors"]},
        {"keywords": [], "cve_owasp": "2025:A02"}]},
    {"name": "OWASP: A03 Software supply chain failures", "color": "#0f766e", "rules": [
        {"keywords": ["supply chain attack", "supply-chain attack", "software supply chain", "malicious package",
                      "malicious packages", "dependency confusion", "typosquatting", "typosquat",
                      "compromised dependency", "vulnerable component", "outdated component", "SBOM",
                      "compromised build", "poisoned pipeline", "GitHub Action", "GitHub Actions", "npm package",
                      "PyPI package"]},
        {"keywords": [], "cve_owasp": "2025:A03"}]},
    {"name": "OWASP: A04 Cryptographic failures", "color": "#0f766e", "rules": [
        {"keywords": ["cryptographic failure", "cryptographic failures", "weak encryption", "broken encryption",
                      "weak cipher", "hardcoded key", "hard-coded key", "hardcoded encryption key", "plaintext password",
                      "plaintext passwords", "cleartext", "padding oracle", "TLS downgrade", "weak random",
                      "insecure randomness", "unencrypted", "certificate validation"]},
        {"keywords": [], "cve_owasp": "2025:A04"}]},
    {"name": "OWASP: A05 Injection", "color": "#0f766e", "rules": [
        {"keywords": ["SQL injection", "SQLi", "command injection", "OS command injection", "code injection",
                      "cross-site scripting", "XSS", "LDAP injection", "template injection", "SSTI",
                      "NoSQL injection", "XPath injection", "header injection", "argument injection", "eval injection"]},
        {"keywords": [], "cve_owasp": "2025:A05"}]},
    {"name": "OWASP: A06 Insecure design", "color": "#0f766e", "rules": [
        {"keywords": ["insecure design", "design flaw", "design flaws", "business logic flaw", "logic flaw",
                      "logic bug", "race condition", "TOCTOU", "threat modeling", "threat modelling",
                      "secure by design"]},
        {"keywords": [], "cve_owasp": "2025:A06"}]},
    {"name": "OWASP: A07 Authentication failures", "color": "#0f766e", "rules": [
        {"keywords": ["authentication bypass", "auth bypass", "broken authentication", "credential stuffing",
                      "brute force", "brute-force", "password spraying", "session hijacking", "session fixation",
                      "MFA bypass", "2FA bypass", "weak password", "weak passwords", "default password",
                      "default passwords", "account takeover", "hardcoded credentials", "hard-coded credentials"]},
        {"keywords": [], "cve_owasp": "2025:A07"}]},
    {"name": "OWASP: A08 Software or data integrity failures", "color": "#0f766e", "rules": [
        {"keywords": ["insecure deserialization", "deserialization", "unsafe deserialization", "unsigned update",
                      "unsigned updates", "update hijacking", "malicious update", "integrity check",
                      "code signing bypass", "signature bypass", "auto-update"]},
        {"keywords": [], "cve_owasp": "2025:A08"}]},
    {"name": "OWASP: A09 Logging & alerting failures", "color": "#0f766e", "rules": [
        {"keywords": ["insufficient logging", "logging failure", "logging failures", "log tampering",
                      "log injection", "undetected for months", "went undetected", "lack of monitoring",
                      "alerting failure", "missing logs"]},
        {"keywords": [], "cve_owasp": "2025:A09"}]},
    {"name": "OWASP: A10 Mishandling of exceptional conditions", "color": "#0f766e", "rules": [
        {"keywords": ["unhandled exception", "improper error handling", "error handling", "fail open",
                      "fails open", "fail-open", "null pointer dereference", "NULL pointer dereference",
                      "uncaught exception", "resource exhaustion", "unchecked return value"]},
        {"keywords": [], "cve_owasp": "2025:A10"}]},
]

def _cats(*slugs: str) -> list[RuleSpec]:
    return [{"keywords": [], "cve_category": s} for s in slugs]


# Articles that name a CVE (needs the CVE data from the CVE tab): by severity, by CISA KEV status, and by the kind of
# bug or target that the OWASP Top 10 (a web-application list) does not cover. Categories are the CVE-tracking ones
# (Settings -> CVE tracking), classified from each CVE's CWE, description and affected products.
CVES: list[CollectionSpec] = [
    {"name": "CVEs: Critical", "color": "#991b1b", "rules": [{"keywords": [], "cve_severity": "CRITICAL"}]},
    {"name": "CVEs: High", "color": "#dc2626", "rules": [{"keywords": [], "cve_severity": "HIGH"}]},
    {"name": "CVEs: Medium", "color": "#f59e0b", "rules": [{"keywords": [], "cve_severity": "MEDIUM"}]},
    {"name": "CVEs: Low", "color": "#65a30d", "rules": [{"keywords": [], "cve_severity": "LOW"}]},
    {"name": "CVEs: Actively exploited (KEV)", "color": "#7f1d1d", "rules": _cats("kev")},
    {"name": "CVEs: Used by ransomware", "color": "#b91c1c", "rules": _cats("kev-ransomware")},
    {"name": "CVEs: Remote code execution", "color": "#c2410c", "rules": _cats("rce")},
    {"name": "CVEs: Privilege escalation", "color": "#9333ea", "rules": _cats("privilege-escalation")},
    {"name": "CVEs: Memory corruption", "color": "#4f46e5", "rules": _cats("memory-corruption")},
    {"name": "CVEs: Denial of service", "color": "#64748b", "rules": _cats("dos")},
    {"name": "CVEs: Edge devices & remote access", "color": "#0e7490", "rules": _cats(
        "edge-firewall-vpn", "edge-routers-iot", "remote-access-file-transfer")},
    {"name": "CVEs: Operating systems & browsers", "color": "#2563eb", "rules": _cats("operating-systems", "browsers")},
    {"name": "CVEs: Virtualization & cloud", "color": "#0891b2", "rules": _cats("virtualization")},
    {"name": "CVEs: Email & collaboration servers", "color": "#0d9488", "rules": _cats("email-collab")},
    {"name": "CVEs: AI / ML & LLM", "color": "#db2777", "rules": _cats("ai-ml")},
]

CRYPTO_PACK: list[CollectionSpec] = [
    {"name": "Crypto: Hacks & breaches", "color": "#ca8a04", "rules": [
        {"keywords": CRYPTO, "require": CRYPTO_HACK_WORDS, "title_keywords": True},
        {"keywords": CRYPTO_HACK_WORDS, "folder": "Blockchain & Crypto", "match_in": "title"}]},
    {"name": "Crypto: News", "color": "#eab308", "rules": [{"keywords": CRYPTO, "match_in": "title",
                                                            "exclude": ["crypto agility", "cryptography"]},
                                                           {"keywords": [], "folder": "Blockchain & Crypto"}]},
]

PACKS: list[Pack] = [
    {"slug": "core", "title": "Core threats",
     "description": "Ransomware, zero-days, APTs, phishing, breaches, malware, supply chain.",
     "collections": CORE},
    {"slug": "ot", "title": "OT / ICS",
     "description": "Attacks on industrial systems, OT/ICS vulnerabilities, AI in OT, and OT defence, forensics & engineering.",
     "collections": OT_PACK},
    {"slug": "practice", "title": "Security practice",
     "description": "Offensive security, defensive security (SOC, IR, detection, hunting), threat intelligence, and threat advisories (government, CERT and vendor advisories and reports, without CVE listings).",
     "collections": PRACTICE},
    {"slug": "ai", "title": "AI",
     "description": "Offensive AI, defensive AI, AI security (attacks on AI systems), and AI news & tools.",
     "collections": AI_PACK},
    {"slug": "attack", "title": "MITRE ATT&CK tactics",
     "description": "One collection per tactic of the ATT&CK Enterprise matrix, from Reconnaissance to Impact. An article is "
                    "filed under a tactic when it names one of that tactic's techniques or sub-techniques.",
     "collections": ATTACK},
    {"slug": "atlas", "title": "MITRE ATLAS tactics (AI)",
     "description": "One collection per MITRE ATLAS tactic - attacks on and with AI systems (prompt injection, model "
                    "poisoning, jailbreaks, deepfakes...), matched on AI-specific technique names and everyday terms.",
     "collections": ATLAS},
    {"slug": "owasp", "title": "OWASP Top 10 (2025)",
     "description": "One collection per category: keywords, plus articles naming a CVE whose weakness maps to it.",
     "collections": OWASP},
    {"slug": "cve", "title": "CVEs",
     "description": "Articles that name a CVE: by CVSS severity, actively exploited (CISA KEV) and ransomware use, and kinds the "
                    "OWASP Top 10 leaves out: RCE, privilege escalation, memory corruption, DoS, edge devices, OS & browsers, "
                    "virtualization, email servers, AI/ML (needs the CVE data from the CVE tab).",
     "collections": CVES},
    {"slug": "crypto", "title": "Blockchain & crypto",
     "description": "Crypto hacks, thefts and scams, and general blockchain and crypto news (plus everything in the Blockchain & Crypto folder).",
     "collections": CRYPTO_PACK},
]

PACK_BY_SLUG = {p["slug"]: p for p in PACKS}


def rule_name(collection: str, index: int) -> str:
    return f"Auto: {collection}" if index == 0 else f"Auto: {collection} #{index + 1}"


# ------------------------------------------------------------------ upgrades of installed packs
# Rules installed from an older version of a pack, as they were installed. When an installed rule still looks exactly
# like this (you never edited it), it is brought up to the current spec once (app.api.automation.upgrade_pack_rules);
# edited rules are left alone. PACK_RULES_REV says which upgrade the database has had.
PACK_RULES_REV = "2"
_OLD_APT = ["apt", "nation-state", "state-sponsored", "lazarus", "kimsuky", "volt typhoon", "salt typhoon", "fancy bear",
            "cozy bear", "apt28", "apt29", "sandworm", "turla", "charming kitten", "mustang panda", "espionage",
            "threat actor"]
_OLD_ZERO_DAY = ["zero-day", "0-day", "zeroday", "actively exploited", "exploited in the wild", "proof of concept",
                 "poc exploit", "rce", "remote code execution"]


def _previous() -> dict[str, RuleSpec]:
    old: dict[str, RuleSpec] = {}
    for coll in CORE + PRACTICE:
        for index, spec in enumerate(coll["rules"]):
            if spec.get("match_in") != "title_opening" or (coll["name"] == "APT & Nation-State" and index):
                continue
            prev: RuleSpec = {k: v for k, v in spec.items() if k != "match_in"}  # type: ignore[assignment]
            if coll["name"] == "APT & Nation-State":
                prev["keywords"] = _OLD_APT
            elif coll["name"] == "Zero-days & Exploits":
                prev["keywords"] = _OLD_ZERO_DAY
            old[rule_name(coll["name"], index)] = prev
    return old


PREVIOUS: dict[str, RuleSpec] = _previous()
CURRENT: dict[str, tuple[str, int, RuleSpec]] = {  # rule name -> (collection, index, spec)
    rule_name(c["name"], i): (c["name"], i, spec) for p in PACKS for c in p["collections"] for i, spec in enumerate(c["rules"])}
