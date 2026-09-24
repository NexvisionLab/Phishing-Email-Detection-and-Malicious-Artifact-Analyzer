from __future__ import annotations

import re
from email.utils import getaddresses, parseaddr
from typing import Any

from .domains import registrable_domain
from .models import Finding


def _domain(address: str) -> str:
    email = parseaddr(address)[1].lower()
    return email.rsplit("@", 1)[-1].strip(".>") if "@" in email else ""


def _aligned(left: str, right: str) -> bool:
    return bool(left and right and registrable_domain(left) == registrable_domain(right))


def _authserv_id(block: str) -> str:
    return block.split(";", 1)[0].strip().lower().split()[0] if block.strip() else ""


def analyze_headers_detailed(headers: dict[str, str], trusted_authserv_ids: set[str] | None = None) -> tuple[list[Finding], dict[str, Any]]:
    if not headers:
        return [], {"status": "not_evaluated", "reason": "headers_unavailable"}
    findings: list[Finding] = []
    trusted = {item.casefold().rstrip(".") for item in (trusted_authserv_ids or set())}
    auth_blocks = [line.strip() for line in headers.get("authentication-results", "").splitlines() if line.strip()]
    trusted_blocks = [block for block in auth_blocks if _authserv_id(block).rstrip(".") in trusted]
    auth_meta: dict[str, Any] = {
        "status": "evaluated" if trusted_blocks else "not_evaluated",
        "trusted_authserv_ids": sorted(trusted),
        "observed_authserv_ids": [_authserv_id(block) for block in auth_blocks],
        "trusted_blocks": len(trusted_blocks),
        "standard": "RFC 9989",
    }
    if auth_blocks and not trusted_blocks:
        findings.append(
            Finding(
                "AUTH_RESULTS_UNTRUSTED",
                "Authentication-Results was not issued by a trusted receiver",
                "info",
                0,
                ", ".join(auth_meta["observed_authserv_ids"]) or "missing authserv-id",
                "headers",
                "not_evaluated",
            )
        )
    auth = "\n".join(trusted_blocks).lower()
    for mechanism, points in (("dmarc", 22), ("dkim", 16), ("spf", 12)):
        match = re.search(rf"\b{mechanism}\s*=\s*(fail|softfail|temperror|permerror)", auth)
        if match:
            findings.append(
                Finding(
                    f"{mechanism.upper()}_FAIL",
                    f"{mechanism.upper()} authentication did not pass",
                    "high" if mechanism == "dmarc" else "medium",
                    points,
                    match.group(0),
                    "headers",
                )
            )

    from_domain = _domain(headers.get("from", ""))
    reply_domain = _domain(headers.get("reply-to", ""))
    return_domain = _domain(headers.get("return-path", ""))
    sender_domain = _domain(headers.get("sender", ""))
    from_addresses = [address for _, address in getaddresses(headers.get("from", "").splitlines()) if address]
    if len(from_addresses) > 1:
        findings.append(
            Finding(
                "MULTIPLE_FROM_ADDRESSES",
                "Message presents multiple author addresses",
                "medium",
                16,
                ", ".join(from_addresses[:5]),
                "headers",
            )
        )
    for header_name in ("from", "reply-to", "subject"):
        values = [value for value in headers.get(header_name, "").splitlines() if value.strip()]
        if len(values) > 1:
            findings.append(
                Finding(
                    "DUPLICATE_SECURITY_HEADER",
                    f"Message contains multiple {header_name.title()} header fields",
                    "medium",
                    14,
                    f"{len(values)} instances",
                    "headers",
                )
            )
    if from_domain and sender_domain and not _aligned(from_domain, sender_domain):
        findings.append(
            Finding(
                "SENDER_FROM_MISMATCH",
                "Sender organizational domain differs from From",
                "low",
                6,
                f"From: {from_domain}; Sender: {sender_domain}",
                "headers",
            )
        )
    if from_domain and reply_domain and not _aligned(from_domain, reply_domain):
        findings.append(
            Finding(
                "REPLY_TO_MISMATCH",
                "Reply-To organizational domain differs from From",
                "medium",
                14,
                f"From: {from_domain}; Reply-To: {reply_domain}",
                "headers",
            )
        )
    if from_domain and return_domain and not _aligned(from_domain, return_domain):
        findings.append(
            Finding(
                "RETURN_PATH_MISMATCH",
                "Return-Path organizational domain differs from From",
                "low",
                7,
                f"From: {from_domain}; Return-Path: {return_domain}",
                "headers",
            )
        )

    if trusted_blocks and from_domain:
        spf_domains = re.findall(r"smtp\.mailfrom=([^\s;]+)", auth)
        dkim_domains = re.findall(r"header\.d=([^\s;]+)", auth)
        spf_pass = bool(re.search(r"\bspf\s*=\s*pass", auth))
        dkim_pass = bool(re.search(r"\bdkim\s*=\s*pass", auth))
        dmarc_pass = bool(re.search(r"\bdmarc\s*=\s*pass", auth))
        spf_aligned = spf_pass and any(_aligned(from_domain, value.strip("<>")) for value in spf_domains)
        dkim_aligned = dkim_pass and any(_aligned(from_domain, value) for value in dkim_domains)
        dmarc_aligned = dmarc_pass or spf_aligned or dkim_aligned
        auth_meta.update(
            {
                "from_domain": from_domain,
                "spf_mailfrom_domains": spf_domains,
                "dkim_signing_domains": dkim_domains,
                "spf_aligned": spf_aligned,
                "dkim_aligned": dkim_aligned,
                "dmarc_aligned": dmarc_aligned,
            }
        )
        if (spf_pass or dkim_pass) and not dmarc_aligned:
            findings.append(
                Finding(
                    "DMARC_ALIGNMENT_FAILURE",
                    "Passing authentication is not aligned with RFC5322.From",
                    "high",
                    22,
                    f"From: {from_domain}; SPF: {spf_domains}; DKIM: {dkim_domains}",
                    "headers",
                )
            )

    arc = headers.get("arc-authentication-results", "") or headers.get("arc-seal", "")
    if arc:
        auth_meta["arc"] = "present_not_trust_proof"
        findings.append(
            Finding(
                "ARC_PRESENT",
                "ARC chain is present but does not prove message safety",
                "info",
                0,
                "ARC evidence requires a trusted validator and chain evaluation",
                "headers",
            )
        )
    if not headers.get("message-id"):
        findings.append(Finding("MESSAGE_ID_MISSING", "Message-ID header is missing", "low", 4, "No Message-ID was parsed", "headers"))
    if headers.get("in-reply-to") and not headers.get("references"):
        findings.append(
            Finding(
                "THREAD_CONTEXT_INCOMPLETE",
                "Reply claims a thread but References is missing",
                "low",
                5,
                headers.get("in-reply-to", "")[:160],
                "thread",
            )
        )
    if headers.get("in-reply-to") and reply_domain and from_domain and not _aligned(reply_domain, from_domain):
        findings.append(
            Finding(
                "THREAD_REPLY_ROUTE_CHANGED",
                "Reply routing changed inside an apparent thread",
                "high",
                18,
                f"From: {from_domain}; Reply-To: {reply_domain}",
                "thread",
            )
        )
    return findings, auth_meta


def analyze_headers(headers: dict[str, str], trusted_authserv_ids: set[str] | None = None) -> list[Finding]:
    return analyze_headers_detailed(headers, trusted_authserv_ids)[0]
