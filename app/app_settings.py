"""User-adjustable application settings (stored in the DB, validated on write)."""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Callable

_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def _int_range(lo: int, hi: int, allow_zero: bool = False) -> Callable[[Any], int]:
    def check(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("must be an integer")
        if allow_zero and value == 0:
            return 0
        if not lo <= value <= hi:
            raise ValueError(f"must be between {lo} and {hi}" + (" (or 0)" if allow_zero else ""))
        return value

    return check


def _boolean(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ValueError("must be true or false")
    return value


def _choice(*options: str) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if value not in options:
            raise ValueError(f"must be one of: {', '.join(options)}")
        return value

    return check


def _int_choice(*options: int) -> Callable[[Any], int]:
    def check(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value not in options:
            raise ValueError(f"must be one of: {', '.join(str(o) for o in options)}")
        return value

    return check


def _id_list(limit: int) -> Callable[[Any], list[int]]:
    def check(value: Any) -> list[int]:
        if not isinstance(value, list) or len(value) > limit or any(isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 2**31 - 1 for v in value):
            raise ValueError(f"must be a list of at most {limit} ids")
        return sorted(set(value))

    return check


_TERM = re.compile(r"^[^\x00-\x1f<>]{2,60}$")


def _terms(limit: int) -> Callable[[Any], list[str]]:
    def check(value: Any) -> list[str]:
        if not isinstance(value, list) or len(value) > limit or any(not isinstance(v, str) or not _TERM.match(v.strip()) for v in value):
            raise ValueError(f"must be a list of at most {limit} words or phrases (2-60 characters each)")
        out: list[str] = []
        for v in value:  # keep the order, drop duplicates (case-insensitive)
            if v.strip().lower() not in {o.lower() for o in out}:
                out.append(v.strip())
        return out

    return check


def _color(value: Any) -> str:
    if not isinstance(value, str) or not _HEX_COLOR.match(value):
        raise ValueError("must be a #rrggbb colour")
    return value.lower()


# key -> (default, validator)
SCHEMA: dict[str, tuple[Any, Callable[[Any], Any]]] = {
    "default_refresh_minutes": (60, _int_range(5, 10080)),
    "retention_days": (90, _int_range(1, 3650, allow_zero=True)),
    "max_articles_per_feed": (1000, _int_range(50, 100_000, allow_zero=True)),
    "load_images": (True, _boolean),
    "theme": ("system", _choice("system", "dark", "light")),
    "accent_color": ("#3b82f6", _color),
    "density": ("comfortable", _choice("comfortable", "compact")),
    "layout": ("three-pane", _choice("three-pane", "list")),
    "page_size": (50, _int_range(10, 200)),
    "default_view": ("unread", _choice("all", "unread", "read", "starred", "today")),
    "sort": ("newest", _choice("newest", "oldest")),
    "mark_read_on_open": (True, _boolean),
    "hide_read": (True, _boolean),
    "hide_watched": (True, _boolean),  # watched videos leave the Videos views and wait in the Watched tab  # read articles leave feeds/folders/collections and stay in the Read view
    "show_snippets": (True, _boolean),
    "font_size": ("medium", _choice("small", "medium", "large")),
    "ui_mode": ("reader", _choice("reader", "dashboard", "library", "accounts", "podcasts", "threatmap")),
    "sidebar_drag_drop": (True, _boolean),
    "default_dashboard_id": (0, _int_range(1, 2**31 - 1, allow_zero=True)),
    # CVE tracking (NVD API 2.0 + CISA KEV + MITRE CWE)
    "cve_enabled": (True, _boolean),
    "cve_backfill_days": (30, _int_range(1, 365)),
    "cve_sync_minutes": (120, _int_range(30, 1440)),
    # MITRE ATT&CK: how often to check for a new release (groups -> watchlist, techniques -> watchlist + rules)
    "attack_sync": ("weekly", _choice("off", "daily", "weekly")),
    # Smart features (Settings → Appearance & reading)
    "story_grouping": (True, _boolean),                          # fold articles about the same story into one item
    "story_match": ("normal", _choice("strict", "normal", "loose")),
    "entity_chips": (True, _boolean),                            # "Mentions" chips in the reader (open entity pages)
    "ttp_everyday_terms": (True, _boolean),                      # recognise techniques by everyday terms (DDoS, ClickFix)
    "report_alert_channels": ([], _id_list(10)),                 # 📑 new reports & guidance -> these delivery channels
    "report_alert_kinds": ("all", _choice("all", "government", "vendor")),
    "related_media": (True, _boolean),                           # ▶ / 🎙 related videos and podcasts in the reader
    "matrix_days": (30, _int_choice(0, 7, 30, 90, 365)),             # period of the technique matrix (0 = all time)
    # ideas from FreshRSS extensions
    "highlight_terms": ([], _terms(50)),                         # words highlighted in the article list and reader
    "adaptive_refresh": (True, _boolean),                        # quiet feeds are checked less often (default interval only)
    "image_proxy": (True, _boolean),                             # reader images load through this server
    "show_reading_time": (True, _boolean),
    "show_site_icons": (True, _boolean),
}


def get_all(db: sqlite3.Connection) -> dict[str, Any]:
    values = {key: default for key, (default, _) in SCHEMA.items()}
    for row in db.execute("SELECT key, value FROM settings"):
        if row["key"] in SCHEMA:
            try:
                values[row["key"]] = SCHEMA[row["key"]][1](json.loads(row["value"]))
            except (ValueError, TypeError):
                pass  # corrupt/legacy value -> fall back to default
    return values


def get(db: sqlite3.Connection, key: str) -> Any:
    return get_all(db)[key]


def update(db: sqlite3.Connection, changes: dict[str, Any]) -> dict[str, Any]:
    errors: dict[str, str] = {}
    clean: dict[str, Any] = {}
    for key, value in changes.items():
        if key not in SCHEMA:
            errors[key] = "unknown setting"
            continue
        try:
            clean[key] = SCHEMA[key][1](value)
        except ValueError as exc:
            errors[key] = str(exc)
    if errors:
        raise ValueError(errors)
    for key, value in clean.items():
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, json.dumps(value)),
        )
    return get_all(db)
