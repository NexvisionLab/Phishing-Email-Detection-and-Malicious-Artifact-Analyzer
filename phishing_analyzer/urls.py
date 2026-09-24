from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from urllib.parse import parse_qsl, unquote, urlsplit, urlunsplit

from .domains import registrable_domain, unicode_risks
from .models import Finding, LinkResult

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "tiny.cc",
    "rb.gy",
    "shorturl.at",
}
SUSPICIOUS_TERMS = re.compile(r"(?i)(login|signin|verify|secure|account|update|password|wallet|invoice|payment|auth)")
REDIRECT_KEYS = {
    "continue",
    "dest",
    "destination",
    "next",
    "redirect",
    "redirect_to",
    "redirect_uri",
    "return",
    "return_to",
    "target",
    "url",
}


def _risk(score: int) -> str:
    if score >= 75:
        return "high"
    if score >= 50:
        return "likely_phishing"
    if score >= 25:
        return "suspicious"
    return "low"


def _finding(code: str, title: str, severity: str, points: int, evidence: str) -> Finding:
    return Finding(code, title, severity, points, evidence, "url")


def normalize_url(url: str) -> str:
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    host = unquote((parsed.hostname or "").lower()).rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    parsed_port = parsed.port
    port = f":{parsed_port}" if parsed_port else ""
    host_for_netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    userinfo = parsed.netloc.rsplit("@", 1)[0] + "@" if "@" in parsed.netloc else ""
    path = parsed.path or "/"
    return urlunsplit((scheme, userinfo + host_for_netloc + port, path, parsed.query, ""))


def _obfuscated_ipv4(host: str) -> str | None:
    if not re.fullmatch(r"(?i)(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+)){0,3}", host):
        return None
    values: list[int] = []
    for part in host.split("."):
        try:
            base = (
                16
                if part.casefold().startswith("0x")
                else 8
                if len(part) > 1 and part.startswith("0") and set(part) <= set("01234567")
                else 10
            )
            values.append(int(part, base))
        except ValueError:
            return None
    if len(values) == 1:
        packed = values[0]
    elif len(values) == 2 and values[0] <= 0xFF and values[1] <= 0xFFFFFF:
        packed = (values[0] << 24) | values[1]
    elif len(values) == 3 and values[0] <= 0xFF and values[1] <= 0xFF and values[2] <= 0xFFFF:
        packed = (values[0] << 24) | (values[1] << 16) | values[2]
    elif len(values) == 4 and all(value <= 0xFF for value in values):
        packed = sum(value << shift for value, shift in zip(values, (24, 16, 8, 0)))
    else:
        return None
    if not 0 <= packed <= 0xFFFFFFFF:
        return None
    canonical = str(ipaddress.IPv4Address(packed))
    return canonical if canonical != host else None


def analyze_url(url: str) -> LinkResult:
    findings: list[Finding] = []
    try:
        original = urlsplit(url.strip())
        original_port = original.port
        normalized = normalize_url(url)
        parsed = urlsplit(normalized)
        host = parsed.hostname or ""
        parsed_port = parsed.port
    except (ValueError, UnicodeError):
        return LinkResult(
            url, url, "", 80, "high", [_finding("MALFORMED_URL", "Malformed URL", "high", 80, url)], registrable_domain="", rank_score=80
        )

    if parsed.scheme not in {"http", "https"} or not host:
        findings.append(_finding("INVALID_URL", "URL is not a valid HTTP(S) link", "high", 60, url))
    if parsed.scheme == "http":
        findings.append(_finding("HTTP_ONLY", "Link does not use HTTPS", "low", 8, parsed.scheme))
    if original.username or original.password:
        findings.append(_finding("USERINFO", "URL contains misleading user information", "high", 25, original.netloc[:120]))
    raw_host = (original.hostname or "").lower().rstrip(".")
    if "%" in raw_host and unquote(raw_host) != raw_host:
        findings.append(_finding("PERCENT_ENCODED_HOST", "URL encodes characters inside the hostname", "high", 20, raw_host[:160]))
    canonical_ip = _obfuscated_ipv4(host.strip("[]"))
    if canonical_ip:
        findings.append(_finding("OBFUSCATED_IP", "Link uses alternate IPv4 notation", "high", 30, f"{host} -> {canonical_ip}"))
    try:
        ip = ipaddress.ip_address(canonical_ip or host.strip("[]"))
        findings.append(_finding("IP_HOST", "Link uses an IP address instead of a domain", "high", 22, str(ip)))
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            findings.append(_finding("NON_PUBLIC_IP", "Link points to a non-public address", "high", 35, str(ip)))
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(_finding("PUNYCODE", "Domain uses internationalized Punycode", "medium", 15, host))
    unicode_evidence = unicode_risks(host)
    if unicode_evidence["mixed_script"]:
        findings.append(_finding("MIXED_SCRIPT", "Domain mixes writing systems", "high", 24, str(unicode_evidence["scripts"])))
    if unicode_evidence["invisible_or_bidi_controls"]:
        findings.append(
            _finding(
                "UNICODE_CONTROLS",
                "Domain contains invisible or bidirectional controls",
                "high",
                30,
                str(unicode_evidence["invisible_or_bidi_controls"]),
            )
        )
    raw_brand_matches = unicode_evidence["brand_matches"]
    brand_matches = raw_brand_matches if isinstance(raw_brand_matches, list) else []
    for match in brand_matches[:2]:
        if not isinstance(match, dict):
            continue
        findings.append(
            _finding(
                "BRAND_IMPERSONATION",
                f"Possible {match['brand'].title()} impersonation",
                "high",
                28,
                f"Observed {match['observed']}; official {match['official']}",
            )
        )
    if host in SHORTENERS or any(host.endswith("." + d) for d in SHORTENERS):
        findings.append(_finding("SHORTENER", "Link uses a URL-shortening service", "medium", 15, host))
    labels = host.split(".")
    if len(labels) >= 5:
        findings.append(_finding("DEEP_SUBDOMAIN", "Domain has many subdomain levels", "low", 8, host))
    if len(normalized) > 180:
        findings.append(_finding("LONG_URL", "URL is unusually long", "low", 8, f"{len(normalized)} characters"))
    decoded = unquote(parsed.path + "?" + parsed.query)
    terms = sorted({m.group(0).lower() for m in SUSPICIOUS_TERMS.finditer(decoded)})
    if terms:
        findings.append(
            _finding("PHISHING_TERMS", "Link contains account or payment terms", "medium", min(15, 5 + len(terms) * 2), ", ".join(terms))
        )
    if parsed_port and parsed_port not in {80, 443}:
        findings.append(_finding("UNUSUAL_PORT", "Link uses a non-standard port", "medium", 12, str(original_port)))
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    if len(query_items) > 12:
        findings.append(_finding("MANY_PARAMETERS", "Link contains many query parameters", "low", 5, "More than 12 parameters"))
    for key, value in query_items:
        if key.casefold() not in REDIRECT_KEYS:
            continue
        candidate = value.strip()
        for _ in range(2):
            decoded_candidate = unquote(candidate)
            if decoded_candidate == candidate:
                break
            candidate = decoded_candidate
        nested = urlsplit(candidate)
        encoded_redirect = False
        if (
            not (nested.scheme in {"http", "https"} and nested.hostname)
            and 20 <= len(candidate) <= 4096
            and re.fullmatch(r"[A-Za-z0-9_+/=-]+", candidate)
        ):
            try:
                decoded_redirect = base64.urlsafe_b64decode(candidate + "=" * (-len(candidate) % 4)).decode("utf-8")
                nested = urlsplit(decoded_redirect)
                encoded_redirect = True
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass
        nested_host = (nested.hostname or "").lower().rstrip(".")
        if nested.scheme in {"http", "https"} and nested_host:
            if encoded_redirect:
                findings.append(_finding("ENCODED_REDIRECT", "Redirect destination is encoded", "medium", 10, key))
            findings.append(
                _finding("NESTED_REDIRECT", "Link contains a nested redirect destination", "medium", 12, f"{key} -> {nested_host}")
            )
            outer_domain = registrable_domain(host)
            nested_domain = registrable_domain(nested_host)
            if outer_domain and nested_domain and outer_domain != nested_domain:
                findings.append(
                    _finding(
                        "CROSS_DOMAIN_REDIRECT",
                        "Nested redirect crosses organizational domains",
                        "high",
                        20,
                        f"{outer_domain} -> {nested_domain}",
                    )
                )
            break
    if len(re.findall(r"%[0-9a-fA-F]{2}", parsed.path + parsed.query)) >= 10:
        findings.append(
            _finding("EXCESSIVE_PERCENT_ENCODING", "Link contains extensive percent encoding", "low", 6, "Ten or more encoded bytes")
        )
    if host.count("-") >= 4:
        findings.append(_finding("MANY_HYPHENS", "Domain contains many hyphens", "low", 6, host))

    score = min(100, sum(item.points for item in findings))
    codes = {item.code for item in findings}
    if "PHISHING_TERMS" in codes and codes.intersection({"SHORTENER", "PUNYCODE"}):
        score = max(score, 25)
    return LinkResult(
        url,
        normalized,
        host,
        score,
        _risk(score),
        findings,
        {"status": "not_evaluated", "reason": "offline_feed_not_configured"},
        registrable_domain=registrable_domain(host),
        rank_score=score,
    )


def risk_label(score: int) -> str:
    return _risk(score)
