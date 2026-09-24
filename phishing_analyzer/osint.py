from __future__ import annotations

from typing import Any


def enrich_domain(
    host: str,
    enabled: bool = False,
    cache_dir: str | None = None,
) -> dict[str, Any]:
    """Return an explicit offline-policy result without touching the network.

    ``enabled`` and ``cache_dir`` remain accepted for API compatibility. The
    production build never performs DNS, TLS, RDAP, URL visits, cache reads, or
    cache writes. Local indicator feeds are handled separately by reputation.py.
    """
    del host, cache_dir
    return {
        "status": "not_evaluated",
        "reason": "network_disabled_by_policy" if enabled else "network_disabled",
        "requested": enabled,
        "cache": "not_used",
    }
