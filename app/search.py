"""Safe full-text query construction (shared by the article list and analytics)."""

from __future__ import annotations

import re

_FTS_TOKEN = re.compile(r"[\w][\w.\-]*", re.UNICODE)


def fts_query(q: str) -> str | None:
    """Turn free text into a safe FTS5 query: every token is a quoted literal (AND-ed)."""
    tokens = _FTS_TOKEN.findall(q)[:20]
    if not tokens:
        return None
    quoted = ['"' + t.replace('"', '""') + '"' for t in tokens]
    quoted[-1] += "*"  # prefix match on the last token (search-as-you-type)
    return " ".join(quoted)
