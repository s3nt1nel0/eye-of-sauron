"""List every HTTP route with the permission it requires (BFLA / missing-auth audit).

Usage (project root, venv active):  python -I tools/route_audit.py
Exit code 1 if a mutating route needs less than ``write`` or any /api route is public
(except the login endpoint). Used by tests/test_route_permissions.py as well.
"""

from __future__ import annotations

import os
import sys
import tempfile

PUBLIC_ALLOWED = {("POST", "/api/v1/auth/login"), ("GET", "/"), ("GET", "/login"), ("GET", "/healthz"),
                  # Google Reader API login for native apps (app passwords, throttled like /auth/login)
                  ("POST", "/api/greader.php/accounts/ClientLogin"), ("POST", "/api/greader/accounts/ClientLogin")}
SAFE = {"GET", "HEAD", "OPTIONS"}
# POST endpoints that only read (query bodies) or only end the caller's own session.
READ_ONLY_POST = {("POST", "/api/v1/analytics/query"), ("POST", "/api/v1/social/compose"), ("POST", "/api/v1/auth/logout")}
# "reader" = mobile-app token (Google Reader API surface only); it may change read/star state and subscriptions.
RANK = {"PUBLIC": 0, "auth": 1, "read": 2, "reader": 3, "write": 3, "publish": 4, "admin": 5}


def _deps(dependant, out: set) -> None:
    for sub in getattr(dependant, "dependencies", []):
        call = sub.call
        name = getattr(call, "__qualname__", str(call))
        if "require.<locals>" in name and call.__closure__:
            out.add(call.__closure__[0].cell_contents)
        if name == "get_principal":
            out.add("auth")
        if name == "reader_principal":
            out.add("reader")
        _deps(sub, out)


def _walk(routes, prefix: str = ""):
    for route in routes:
        if hasattr(route, "dependant") and hasattr(route, "methods"):
            found: set = set()
            _deps(route.dependant, found)
            level = max(found, key=lambda s: RANK.get(s, 0)) if found else "PUBLIC"
            for method in route.methods:
                yield level, method, prefix + route.path
        elif hasattr(route, "original_router"):
            ctx = getattr(route, "include_context", None)
            sub_prefix = getattr(ctx, "prefix", "") if ctx is not None else ""
            yield from _walk(route.original_router.routes, prefix + (sub_prefix or ""))
        elif hasattr(route, "routes") and not hasattr(route, "app_directory"):
            yield from _walk(route.routes, prefix + getattr(route, "path", ""))


def audit(app) -> tuple[list[tuple[str, str, str]], list[str]]:
    rows = sorted(set(_walk(app.routes)), key=lambda r: (r[2], r[1]))
    problems = []
    for level, method, path in rows:
        if (method, path) in PUBLIC_ALLOWED:
            continue
        if level == "PUBLIC":
            problems.append(f"PUBLIC route: {method} {path}")
        elif method not in SAFE and RANK[level] < RANK["write"] and (method, path) not in READ_ONLY_POST:
            problems.append(f"mutating route needs only '{level}': {method} {path}")
    return rows, problems


def main() -> int:
    os.environ.setdefault("EOS_DATA_DIR", tempfile.mkdtemp(prefix="route-audit-"))
    os.environ.setdefault("EOS_ADMIN_PASSWORD", "route-audit-only-password")
    os.environ.setdefault("EOS_DISABLE_SCHEDULER", "true")
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app.main import create_app

    rows, problems = audit(create_app())
    for level, method, path in rows:
        print(f"{level:8} {method:7} {path}")
    print(f"\n{len(rows)} routes; {len(problems)} problem(s)")
    for p in problems:
        print("  !!", p)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
