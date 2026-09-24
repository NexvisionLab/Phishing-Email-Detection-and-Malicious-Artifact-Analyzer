from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


def _feed_entries(path: Path) -> set[str]:
    if not path.is_file() or path.stat().st_size > 50_000_000:
        return set()
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.casefold() == ".json":
        try:
            data = json.loads(text)
            values = data if isinstance(data, list) else data.get("indicators", [])
            return {str(value).strip().casefold() for value in values}
        except (ValueError, AttributeError):
            return set()
    return {line.strip().casefold() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")}


def enrich_url(url: str, enabled: bool = False, feed_paths: list[str] | None = None) -> dict[str, Any]:
    """Match local/downloaded indicator feeds; never performs a network call."""
    configured = feed_paths or [p for p in os.getenv("PHISHCHECK_FEEDS", "").split(os.pathsep) if p]
    if not configured:
        return {"status": "not_evaluated", "reason": "no_local_feeds_configured"}
    host = (urlsplit(url).hostname or "").casefold()
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()
    needles = {url.casefold(), host, digest}
    matches: list[dict[str, str]] = []
    errors: list[str] = []
    for raw_path in configured:
        path = Path(raw_path)
        try:
            entries = _feed_entries(path)
            matched = needles.intersection(entries)
            if matched:
                matches.append({"feed": path.name, "indicator": min(matched)})
        except OSError as exc:
            errors.append(f"{path.name}:{type(exc).__name__}")
    return {
        "status": "matched" if matches else ("partial" if errors else "checked"),
        "matches": matches,
        "errors": errors,
        "feeds_checked": len(configured),
    }


def reputation_points(data: dict[str, Any]) -> int:
    return 70 if data.get("matches") else 0
