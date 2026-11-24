"""Transport-neutral helpers used by preserved AYNUO audit controls."""

from __future__ import annotations


def get(source, path: str) -> list[dict]:
    try:
        return list(source.path(*path.split("/")))
    except (KeyError, TypeError, ValueError):
        return []


def get_settings(source, path: str) -> dict:
    entries = get(source, path)
    return entries[0] if entries else {}

