"""One-command security gate (DevSecOps "security automation" layer). Run before every release/deploy.

Usage (project root, dev venv active):
    python -I tools/security_check.py            # secrets, SAST, SCA, permissions, tests
    python -I tools/security_check.py --dast     # ... plus the dynamic pentest harness (~2 min)

Exit code is non-zero if any gate fails, so it can run in CI or as a pre-push hook.
"""

from __future__ import annotations

import shutil
import subprocess  # nosec B404 - fixed argument lists only, no shell
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run(name: str, args: list[str], ok_codes: tuple[int, ...] = (0,)) -> bool:
    print(f"\n=== {name} ===", flush=True)
    result = subprocess.run(args, cwd=ROOT)  # nosec B603 - trusted, fixed command lines
    passed = result.returncode in ok_codes
    print(f"--> {'PASS' if passed else 'FAIL'} ({name})")
    return passed


def main(argv: list[str]) -> int:
    gates = [
        ("Secret scan (detect-secrets + patterns, vs reviewed baseline)", [PY, "-I", "tools/secret_scan.py"]),
        ("Route permission audit (BFLA / missing auth)", [PY, "-I", "tools/route_audit.py"]),
        # SAST: medium+ severity, medium+ confidence. B608 (SQL built from fixed fragments) is reviewed and
        # documented in SECURITY.md; everything else fails the gate.
        ("SAST: bandit", [PY, "-m", "bandit", "-q", "-r", "app", "-ll", "-ii", "-s", "B608"]),
        ("SCA: pip-audit on the hash-locked dependency set", [PY, "-m", "pip_audit", "--disable-pip", "--no-deps",
                                                              "-r", "requirements.lock"]),
        ("Unit, integration and security regression tests", [PY, "-m", "pytest", "-q"]),
    ]
    results = [run(name, args) for name, args in gates]
    if "--dast" in argv:
        for mode in ("0", "1"):
            data = tempfile.mkdtemp(prefix="pentest-")
            # The harness reports known benign FAILs (see docs/PENTEST-REPORT.md); review its output.
            results.append(run(f"DAST: pentest harness (private targets={'on' if mode == '1' else 'off'})",
                               [PY, "-I", "tools/pentest_harness.py", ".", data, mode]))
            shutil.rmtree(data, ignore_errors=True)
    if shutil.which("trivy"):
        results.append(run("Container image scan (trivy)", ["trivy", "image", "--severity", "HIGH,CRITICAL",
                                                            "--exit-code", "1", "eye-of-sauron:latest"]))
    else:
        print("\n(trivy not installed - container image scan skipped; see docs/GUIDE.md)")
    failed = results.count(False)
    print(f"\n{'ALL GATES PASSED' if not failed else f'{failed} GATE(S) FAILED'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
