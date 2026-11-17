"""Secret scan for the project's own files (detect-secrets engine + extra patterns).

Usage:  python -I tools/secret_scan.py            # fail (exit 1) on findings not in the baseline
        python -I tools/secret_scan.py --update   # after REVIEWING findings, accept them into the baseline

Scans app/, static/, tests/, tools/, deploy/, docs/, examples/ and top-level config files. Never scans
.venv/, data/ (runtime secrets live there and are git/docker-ignored) or caches. Findings are printed
as file:line:type only - the secret value itself is never printed.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASELINE = ROOT / ".secrets.baseline.json"
SCAN_DIRS = ["app", "static", "tests", "tools", "deploy", "docs", "examples"]
SCAN_FILES = ["Dockerfile", "docker-compose.yml", ".env.example", "README.md", "SECURITY.md", "CHANGELOG.md",
              "requirements.txt", "requirements-dev.txt"]
SKIP_PARTS = {"__pycache__", ".venv", "data", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".js", ".css", ".html", ".md", ".yml", ".yaml", ".json", ".txt", ".service", ".svg",
                 ".opml", ".xml", ".toml", ".cfg", ".ini", ".sh", ".ps1", ""}
# Extra high-signal patterns (cloud keys, PATs, private keys, Fernet keys, our own API tokens).
EXTRA = {
    "Private key block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "GitHub token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|github_pat_[A-Za-z0-9_]{40,}"),
    "GitLab token": re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    "Slack token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "OpenAI/Anthropic key": re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "Fernet key": re.compile(r"(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{43}=(?![A-Za-z0-9_=-])"),
    "Feedwarden API token": re.compile(r"\bfw_[A-Za-z0-9_-]{40,}\b"),
}


def files() -> list[Path]:
    out = [ROOT / f for f in SCAN_FILES if (ROOT / f).is_file()]
    for d in SCAN_DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.is_file() and not (SKIP_PARTS & set(p.relative_to(ROOT).parts)) and p.suffix.lower() in TEXT_SUFFIXES:
                out.append(p)
    return sorted(set(out))


def fingerprint(rel: str, kind: str, line: str) -> str:
    # Hash of the matched line: stable across line-number changes, never stores the secret itself.
    return hashlib.sha256(f"{rel}|{kind}|{line.strip()}".encode()).hexdigest()[:24]


def scan() -> list[dict]:
    findings: list[dict] = []
    try:
        from detect_secrets.core.scan import scan_file
        from detect_secrets.settings import default_settings
    except ImportError:  # pragma: no cover - dev dependency missing
        print("detect-secrets not installed (pip install -r requirements-dev.txt); running extra patterns only")
        scan_file = None
    targets = files()
    if scan_file is not None:
        with default_settings():
            for path in targets:
                rel = path.relative_to(ROOT).as_posix()
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                for secret in scan_file(str(path)):
                    line = lines[secret.line_number - 1] if 0 < secret.line_number <= len(lines) else ""
                    findings.append({"file": rel, "line": secret.line_number, "type": secret.type,
                                     "id": fingerprint(rel, secret.type, line)})
    for path in targets:
        rel = path.relative_to(ROOT).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for kind, rx in EXTRA.items():
                if rx.search(line):
                    findings.append({"file": rel, "line": n, "type": kind, "id": fingerprint(rel, kind, line)})
    return findings


def main(argv: list[str]) -> int:
    findings = scan()
    accepted = set(json.loads(BASELINE.read_text())["accepted"]) if BASELINE.exists() else set()
    if "--update" in argv:
        BASELINE.write_text(json.dumps({"note": "Reviewed false positives / test fixtures. Fingerprints only - no secret values.",
                                        "accepted": sorted({f["id"] for f in findings})}, indent=1) + "\n")
        print(f"Baseline updated: {len({f['id'] for f in findings})} accepted fingerprint(s). Review them first!")
        return 0
    new = [f for f in findings if f["id"] not in accepted]
    print(f"Scanned {len(files())} files: {len(findings)} finding(s), {len(findings) - len(new)} accepted in baseline.")
    for f in new:
        print(f"  NEW  {f['file']}:{f['line']}  {f['type']}")
    return 1 if new else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
