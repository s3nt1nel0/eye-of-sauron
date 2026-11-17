"""Shared request-model helpers."""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import HTTPException
from pydantic import AfterValidator, BaseModel, ConfigDict, StringConstraints

from app import netguard

HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


class StrictModel(BaseModel):
    # Reject unknown fields: prevents mass-assignment surprises and typos.
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


def _url(value: str) -> str:
    try:
        return netguard.normalize_url(value)
    except netguard.UnsafeURLError as exc:
        raise ValueError(str(exc)) from exc


def _color(value: str) -> str:
    if not HEX_COLOR.match(value):
        raise ValueError("must be a #rrggbb colour")
    return value.lower()


HttpUrlStr = Annotated[str, StringConstraints(min_length=1, max_length=netguard.MAX_URL_LENGTH), AfterValidator(_url)]
Name = Annotated[str, StringConstraints(min_length=1, max_length=100)]
Color = Annotated[str, AfterValidator(_color)]
Keyword = Annotated[str, StringConstraints(min_length=1, max_length=100)]


def not_found(what: str = "Resource") -> HTTPException:
    return HTTPException(status_code=404, detail=f"{what} not found")


def conflict(detail: str) -> HTTPException:
    return HTTPException(status_code=409, detail=detail)


TopicIds = Annotated[str, StringConstraints(max_length=200, pattern=r"^\d{1,9}(,\d{1,9}){0,19}$")]


def topic_clause(ids_csv: str | None, match: str) -> tuple[str, list[int]]:
    """SQL for "article has any / all of these topics" (up to 20 ids, bound as parameters). Topic 0 = no topic at all."""
    if not ids_csv:
        return "", []
    ids = list(dict.fromkeys(int(x) for x in ids_csv.split(",")))
    real = [i for i in ids if i > 0]
    none = "NOT EXISTS (SELECT 1 FROM article_topics t0 WHERE t0.article_id = a.id)"
    parts: list[str] = []
    if match == "all":
        parts = ["EXISTS (SELECT 1 FROM article_topics t WHERE t.article_id = a.id AND t.topic_id = ?)" for _ in real]
        if 0 in ids:
            parts.append(none)  # "Other" plus a topic can never both hold: honest empty result
        return " AND (" + " AND ".join(parts) + ")", real
    if real:
        parts.append(f"EXISTS (SELECT 1 FROM article_topics t WHERE t.article_id = a.id AND t.topic_id IN ({','.join('?' * len(real))}))")
    if 0 in ids:
        parts.append(none)
    return " AND (" + " OR ".join(parts) + ")", real
