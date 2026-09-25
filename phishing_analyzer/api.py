from __future__ import annotations

import hmac
import ipaddress
import os
import threading
import time
from collections import deque
from urllib.parse import urlsplit

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field

from .analyzer import analyze_email

app = FastAPI(title="NexVision Offline Phishing Analyzer", version="2.4.1")
_requests: dict[str, deque[float]] = {}
_requests_lock = threading.Lock()
_RATE_LIMIT = 60
_MAX_RATE_CLIENTS = 10_000


class AnalyzeRequest(BaseModel):
    content: str = Field(min_length=1, max_length=2_000_000)
    network_enabled: bool = False


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": "2.4.1", "mode": "offline"}


def _admit_client(client: str, now: float) -> bool:
    with _requests_lock:
        bucket = _requests.setdefault(client, deque())
        cutoff = now - 60
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= _RATE_LIMIT:
            return False
        bucket.append(now)
        if len(_requests) > _MAX_RATE_CLIENTS:
            stale = [key for key, values in _requests.items() if key != client and (not values or values[-1] < cutoff)]
            for key in stale:
                _requests.pop(key, None)
            if len(_requests) > _MAX_RATE_CLIENTS:
                oldest = min((key for key in _requests if key != client), key=lambda key: _requests[key][-1], default=None)
                if oldest is not None:
                    _requests.pop(oldest, None)
        return True


_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _host_allowed(host_header: str | None) -> bool:
    """Reject a Host header that is not local when no token protects the service.

    Without this, a web page on an attacker's domain that resolves to 127.0.0.1 (DNS rebinding) is
    treated as a same-origin client of the unauthenticated local API. Extra hostnames for a reviewed
    gateway can be listed, comma-separated, in PHISHCHECK_ALLOWED_HOSTS.
    """
    extra = {item.strip().lower() for item in os.getenv("PHISHCHECK_ALLOWED_HOSTS", "").split(",") if item.strip()}
    try:
        host = urlsplit("//" + (host_header or "")).hostname
    except ValueError:
        return False
    return host is not None and (host in _LOCAL_HOSTS or host in extra)


def _is_loopback(client: str) -> bool:
    try:
        return ipaddress.ip_address(client).is_loopback
    except ValueError:
        return False


@app.post("/v1/analyze")
def analyze(request: AnalyzeRequest, http_request: Request, authorization: str | None = Header(default=None)) -> dict:
    client = http_request.client.host if http_request.client else "unknown"
    expected = os.getenv("PHISHCHECK_API_TOKEN", "")
    if expected:
        supplied = (authorization or "").removeprefix("Bearer ")
        # Compare bytes: hmac.compare_digest raises TypeError for a non-ASCII str, which turned a
        # malformed Authorization header into a 500 instead of a 401.
        if not hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8")):
            raise HTTPException(status_code=401, detail="Unauthorized")
    elif not _is_loopback(client):
        raise HTTPException(status_code=401, detail="Bearer token required for non-loopback clients")
    elif not _host_allowed(http_request.headers.get("host")):
        raise HTTPException(status_code=421, detail="Untrusted Host header")
    now = time.monotonic()
    if not _admit_client(client, now):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    try:
        return analyze_email(request.content, network_enabled=request.network_enabled).to_dict()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
