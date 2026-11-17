"""Build app/data/threat_actors.json - the threat-actor catalogue the app tracks.

Run by hand when you want to refresh the catalogue (it is NOT run by the app):

    python tools/build_threat_actors.py <misp-threat-actor.json> <atlas-entities.json>

Inputs (download them yourself; nothing is fetched here):
  * MISP galaxy "Threat Actor" cluster - https://github.com/MISP/misp-galaxy (clusters/threat-actor.json). An open,
    community-maintained catalogue that cross-references the names vendors give the same actor (CrowdStrike, Microsoft,
    Mandiant, Recorded Future, Secureworks, Symantec, Kaspersky, …).
  * MITRE ATLAS entities - the `entities` of the ATLAS release file, as {id: {name, type}}.
The adversary names shown on CrowdStrike's and Dragos' public pages are listed below (names only).

Only names, alternative names, a country code and the sources are stored - no descriptions.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "app" / "data" / "threat_actors.json"
TOKEN = re.compile(r"[^\W_]+", re.UNICODE)

# https://www.crowdstrike.com/en-us/adversaries/ (as listed 2026-11-16): name -> origin / category
CROWDSTRIKE = {
    "eCrime": """Apothecary Spider|Bitwise Spider|Blind Spider|Brash Spider|Chatty Spider|Cookie Spider|Cordial Spider|Curly Spider
|Graceful Spider|Hazard Spider|Herald Spider|Hijack Spider|Hook Spider|Imposter Spider|Lightning Spider|Luxury Spider|Masked Spider
|Mutant Spider|Nitro Spider|Pious Spider|Plastic Spider|Plump Spider|Pristine Spider|Prophet Spider|Punk Spider|Radiant Spider
|Recess Spider|Revenant Spider|Robot Spider|Royal Spider|Salty Spider|Scion Spider|Sinful Spider|Slim Spider|Sly Spider|Solar Spider
|Squab Spider|Tempus Spider|Traveling Spider|Tunnel Spider|Veto Spider|Vice Spider|Scattered Spider|Wizard Spider|Indrik Spider""",
    "hacktivist": "Bounty Jackal|Partisan Jackal",
    "BY": "Umbral Bison",
    "CN": "Ethereal Panda|Titan Panda|Vapor Panda|Vault Panda|Warp Panda|Operator Panda|Vanguard Panda|Wicked Panda",
    "KP": "Famous Chollima|Golden Chollima|Stardust Chollima|Velvet Chollima|Labyrinth Chollima",
    "IN": "Steel Tiger",
    "IR": "Banished Kitten|Charming Kitten|Helix Kitten|Hydro Kitten|Imperial Kitten",
    "RU": "Abyssal Bear|Crude Bear|Fancy Bear|Primitive Bear|Sentry Bear|Renaissance Spider|Cozy Bear|Voodoo Bear",
    "TR": "Cosmic Wolf",
}
# https://www.dragos.com/threat-groups (as listed 2026-11-16)
DRAGOS = """ALLANITE|AZURITE|BAUXITE|BENTONITE|CHERNOVITE|CHRYSENE|DYMALLOY|ELECTRUM|GANANITE|GRAPHITE|HEXANE|KAMACITE|KOSTOVITE
|LAURIONITE|MAGNALLIUM|PARISITE|PETROVITE|PYROXENE|RASPITE|STIBNITE|SYLVANITE|TALONITE|VANADINITE|VOLTZITE|WASSONITE|XENOTIME"""
# Single words that are also ordinary words / brands: never matched on their own.
STOP = set("""akira alibaba amoeba axiom bitter butterfly calcium cardinal cicada cleaver cobalt gorilla honeybee lexus machete mirage
monsoon moonlight nitro pioneer polaris popeye reaper scarab siesta silence snake strider superman trident watchdog wildcard
patchwork leviathan longhorn slingshot scimitar pickaxe vermin dragonfly dogfish buckeye kairos eldorado indra rancor antlion
blackjack labubu elfin lurid nazar topgear danti karba orova sarit sayad luder anonymous shadow unknown operation phantom royal hive
cuba medusa play karma money lotus hades conti lockbit rhysida hunters qilin clop cactus trigona bianlian everest snatch ragnar
graphite electrum actinium bohrium thallium zirconium phosphorus nobelium gallium hafnium nickel barium cerium europium iridium
curium strontium tellurium neptunium plutonium polonium radium rubidium chromium manganese holmium osmium krypton""".split())


# Names / alternative names that are ordinary wording in news ("copy-paste", "the mask"): never matched.
PHRASES = {"copypaste", "thebigbang", "themask", "uglyface", "thefamily", "newworldhackers", "teamspy", "whois"}


def clean(name: str) -> str:
    return " ".join(str(name).replace("​", "").split()).strip(" ,;")[:80]


def safe_alias(alias: str) -> bool:
    """Can this name be matched in text without hitting ordinary words?"""
    tokens = TOKEN.findall(alias)
    if not tokens or len(tokens) > 6 or len(alias) < 4 or key(alias) in PHRASES:
        return False
    if len(tokens) >= 2:
        return not all(len(t) <= 2 for t in tokens)
    word = tokens[0]
    if any(c.isdigit() for c in alias):
        return len(word) >= 4
    if alias.isupper():                     # ALL CAPS (ELECTRUM, GRAPHITE): the app matches these case-sensitively
        return len(word) >= 5
    return len(word) >= 5 and word.lower() not in STOP


def key(name: str) -> str:
    return "".join(TOKEN.findall(name.lower()))


def main() -> None:
    misp = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    atlas = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    actors: list[dict] = []
    by_key: dict[str, dict] = {}

    def add(name: str, aliases: list[str], country: str, kind: str, source: str, own_entry: bool = False) -> None:
        name = clean(name)
        if not name:
            return
        names = [clean(a) for a in [name, *aliases] if clean(a)]
        hit = None if own_entry else next((by_key[key(n)] for n in names if key(n) in by_key), None)
        if hit is None:
            hit = {"name": name, "aliases": [], "country": "", "kind": "", "sources": []}
            actors.append(hit)
        for n in names:
            if key(n) != key(hit["name"]) and key(n) not in {key(a) for a in hit["aliases"]}:
                hit["aliases"].append(n)
        hit["country"] = hit["country"] or country
        hit["kind"] = hit["kind"] or kind
        if source not in hit["sources"]:
            hit["sources"].append(source)

    # MISP: every actor keeps its own entry (they share alternative names; merging on those would chain distinct
    # actors together). A vendor name is then attached to the entry whose MAIN name it is, else to the first entry
    # that lists it as an alternative name.
    for v in misp["values"]:
        meta = v.get("meta") or {}
        country = str(meta.get("country") or "")[:2].upper()
        kind = "state" if meta.get("cfr-suspected-state-sponsor") else ""
        add(v.get("value", ""), [s for s in meta.get("synonyms") or [] if isinstance(s, str)], country if country.isalpha() else "", kind,
            "MISP galaxy", own_entry=True)
    for a in actors:
        by_key.setdefault(key(a["name"]), a)
    for a in actors:
        for alias in a["aliases"]:
            by_key.setdefault(key(alias), a)
    for origin, names in CROWDSTRIKE.items():
        for n in names.replace("\n", "").split("|"):
            add(n, [], origin if len(origin) == 2 else "", {"eCrime": "crime", "hacktivist": "hacktivist"}.get(origin, "state"), "CrowdStrike")
    for n in DRAGOS.replace("\n", "").split("|"):
        add(n, [], "", "", "Dragos")
    for eid, e in atlas.items():
        if str(e.get("type") or "").lower() == "activity cluster":   # ATLAS entities also list researchers and vendors
            add(e["name"], [], "", "", "MITRE ATLAS")

    out = []
    for a in actors:
        aliases = [x for x in a["aliases"] if safe_alias(x)][:30]
        name_ok = safe_alias(a["name"])
        if not name_ok and not aliases:
            continue                        # nothing it could be recognised by
        out.append({"name": a["name"], "match_name": name_ok, "aliases": aliases, "country": a["country"], "kind": a["kind"],
                    "sources": a["sources"]})
    out.sort(key=lambda a: a["name"].lower())
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps({"version": 1, "built": sys.argv[3] if len(sys.argv) > 3 else "", "misp_version": misp.get("version"),
                               "actors": out}, ensure_ascii=False, indent=0), encoding="utf-8")
    print(f"{len(out)} actors written to {OUT} ({OUT.stat().st_size // 1024} KB); dropped {len(actors) - len(out)} with no usable name")
    print("by source:", {s: sum(1 for a in out if s in a["sources"]) for s in ("MISP galaxy", "CrowdStrike", "Dragos", "MITRE ATLAS")})
    print("atlas types:", sorted({str(e.get("type")) for e in atlas.values()}))


if __name__ == "__main__":
    main()
