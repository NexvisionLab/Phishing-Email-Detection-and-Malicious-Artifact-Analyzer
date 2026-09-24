from __future__ import annotations

import hashlib
import html
import re
import unicodedata
from dataclasses import dataclass
from email.utils import parseaddr

from .domains import BRANDS, registrable_domain
from .models import Finding

ADVANCED_RULE_PACK_VERSION = "2026.09.23.1"


@dataclass(frozen=True, slots=True)
class AdvancedRule:
    rule_id: str
    category: str
    pattern: str
    title: str
    points: int
    attack_mapping: str


ADVANCED_RULES: tuple[AdvancedRule, ...] = (
    AdvancedRule(
        "oauth.consent",
        "OAuth consent phishing",
        r"\b(grant|approve|authorize|consent to)\b.{0,55}\b(permission|access)\b.{0,45}\b(app|application|mailbox|files?|tenant)\b",
        "Requests OAuth application consent",
        28,
        "MITRE ATT&CK T1566.002/T1528",
    ),
    AdvancedRule(
        "identity.device-code",
        "Device-code phishing",
        r"\b(device code|verification code)\b.{0,70}\b(enter|use|visit|sign[ -]?in|microsoft|google)\b|\b(microsoft\.com/devicelogin|google\.com/device)\b",
        "Directs the recipient through a device-code sign-in flow",
        28,
        "MITRE ATT&CK T1566.002",
    ),
    AdvancedRule(
        "identity.mfa-push",
        "MFA fatigue or approval phishing",
        r"\b(mfa|multi[ -]?factor|authenticator|push notification|login request)\b.{0,70}\b(approve|accept|allow|verify|number matching)\b",
        "Requests approval of an MFA or login prompt",
        25,
        "MITRE ATT&CK T1621",
    ),
    AdvancedRule(
        "identity.session-token",
        "Session-token phishing",
        r"\b(session (?:expired|token|cookie)|reauthenticate|re-authenticate|keep me signed in|single sign[ -]?on)\b.{0,70}\b(sign[ -]?in|login|verify|continue|restore)\b",
        "Uses a session or SSO reauthentication lure",
        22,
        "MITRE ATT&CK T1539/T1550.004",
    ),
    AdvancedRule(
        "execution.clickfix",
        "ClickFix or command-execution lure",
        r"\b(windows\s*\+\s*r|run dialog|powershell|terminal|command prompt)\b.{0,120}\b(paste|execute|run|ctrl\s*\+\s*v)\b|\bcopy.{0,40}(command|script).{0,40}(run|terminal|powershell)\b",
        "Instructs the recipient to paste or execute a command",
        42,
        "MITRE ATT&CK T1204.002/T1059",
    ),
    AdvancedRule(
        "remote.rmm",
        "Remote-access tool lure",
        r"\b(anydesk|teamviewer|screenconnect|connectwise|logmein|rustdesk|quick assist|remote desktop)\b.{0,80}\b(install|download|open|allow|code|session)\b",
        "Requests installation or use of remote-access software",
        34,
        "MITRE ATT&CK T1219",
    ),
    AdvancedRule(
        "cloud.share",
        "Cloud-document phishing",
        r"\b(sharepoint|onedrive|google drive|dropbox|docusign|adobe sign)\b.{0,80}\b(shared|document|file|signature)\b.{0,80}\b(sign[ -]?in|verify|view|open)\b",
        "Cloud document or signature lure requires account action",
        20,
        "MITRE ATT&CK T1566.002/T1566.003",
    ),
    AdvancedRule(
        "otp.request",
        "One-time-code theft",
        r"\b(otp|one[ -]?time (?:password|code)|verification code|security code)\b.{0,70}\b(reply|send|share|provide|tell)\b|\b(reply|send|share|provide).{0,50}\b(otp|verification code)\b",
        "Asks the recipient to disclose a one-time code",
        32,
        "MITRE ATT&CK T1111",
    ),
    AdvancedRule(
        "qr.login",
        "QR login phishing",
        r"\b(scan|open)\b.{0,30}\b(qr|quick response)\b.{0,70}\b(sign[ -]?in|login|verify|mfa|authenticate|payment)\b",
        "Uses a QR code for authentication or payment action",
        24,
        "MITRE ATT&CK T1566.002",
    ),
)


PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d ().-]{6,}\d)(?!\w)")
CRYPTO_PATTERNS = {
    "bitcoin": re.compile(r"(?<![A-Za-z0-9])(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})(?![A-Za-z0-9])"),
    "ethereum": re.compile(r"(?<![A-Fa-f0-9])0x[A-Fa-f0-9]{40}(?![A-Fa-f0-9])"),
    "tron": re.compile(r"(?<![A-Za-z0-9])T[A-HJ-NP-Za-km-z1-9]{33}(?![A-Za-z0-9])"),
}
IBAN_RE = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])", re.IGNORECASE)
UPI_RE = re.compile(r"(?<![\w.-])[\w.-]{2,}@(upi|paytm|ybl|okaxis|oksbi|okhdfcbank|ibl)(?!\w)", re.IGNORECASE)
CALLBACK_CONTEXT = re.compile(r"(?i)\b(invoice|subscription|renewal|refund|charge|purchase|security alert|virus|fraud)\b")
CALL_ACTION = re.compile(r"(?i)\b(call|phone|dial|contact support|hotline)\b")
PAYMENT_CONTEXT = re.compile(
    r"(?i)\b(pay|payment|transfer|send|deposit|refund|fee|wallet|beneficiary|bank details|gift card|crypto|bitcoin|usdt)\b"
)


def _redacted(kind: str, value: str) -> dict[str, str]:
    compact = re.sub(r"\s+", "", value)
    visible = compact[-4:] if len(compact) >= 4 else "****"
    return {
        "type": kind,
        "masked": f"***{visible}",
        "sha256_prefix": hashlib.sha256(compact.encode("utf-8", errors="replace")).hexdigest()[:16],
    }


def extract_sensitive_indicators(text: str) -> list[dict[str, str]]:
    indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        item = _redacted(kind, value)
        identity = (kind, item["sha256_prefix"])
        if identity not in seen:
            seen.add(identity)
            indicators.append(item)

    for match in PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 7 <= len(digits) <= 16:
            add("phone", match.group(0))
    for kind, pattern in CRYPTO_PATTERNS.items():
        for match in pattern.finditer(text):
            add(f"{kind}_wallet", match.group(0))
    for match in IBAN_RE.finditer(text):
        add("iban", match.group(0))
    for match in UPI_RE.finditer(text):
        add("upi_id", match.group(0))
    return indicators[:50]


def _advanced_rule_findings(text: str) -> tuple[list[Finding], dict[str, int], list[dict[str, str]]]:
    findings: list[Finding] = []
    category_scores: dict[str, int] = {}
    mappings: list[dict[str, str]] = []
    for rule in ADVANCED_RULES:
        match = re.search(rule.pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            continue
        findings.append(
            Finding(
                "ADVANCED_TACTIC",
                rule.title,
                "high" if rule.points >= 30 else "medium",
                rule.points,
                match.group(0)[:180],
                f"advanced:{rule.rule_id}",
            )
        )
        category_scores[rule.category] = category_scores.get(rule.category, 0) + rule.points
        mappings.append({"rule_id": rule.rule_id, "mapping": rule.attack_mapping})
    return findings, category_scores, mappings


def _callback_findings(text: str, indicators: list[dict[str, str]]) -> tuple[list[Finding], dict[str, int]]:
    phone_present = any(item["type"] == "phone" for item in indicators)
    if phone_present and CALLBACK_CONTEXT.search(text) and CALL_ACTION.search(text):
        return [
            Finding(
                "CALLBACK_PHISHING",
                "Invoice, refund, or security lure directs the recipient to call",
                "high",
                30,
                "Phone number redacted; callback context observed",
                "advanced:callback",
            )
        ], {"Callback phishing": 30}
    return [], {}


def _payment_findings(text: str, indicators: list[dict[str, str]]) -> tuple[list[Finding], dict[str, int]]:
    financial = [item for item in indicators if item["type"] != "phone"]
    if financial and PAYMENT_CONTEXT.search(text):
        types = sorted({item["type"] for item in financial})
        return [
            Finding(
                "PAYMENT_DESTINATION", "Message contains a payment destination or wallet", "high", 24, ", ".join(types), "advanced:payment"
            )
        ], {"Payment diversion or crypto transfer": 24}
    return [], {}


def _html_findings(body_html: str) -> tuple[list[Finding], dict[str, int]]:
    if not body_html:
        return [], {}
    body_html = html.unescape(body_html)
    body_html = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", "", body_html)
    findings: list[Finding] = []
    score = 0
    checks = (
        (
            "HTML_SMUGGLING",
            "HTML contains client-side payload construction or download behavior",
            38,
            r"(?is)data:(?:text/html|application/octet-stream)[^,]{0,120};base64|\b(?:atob|createObjectURL|Uint8Array|new\s+Blob)\s*\(|<a\b[^>]*\bdownload\s*=",
        ),
        (
            "HTML_CREDENTIAL_FORM",
            "Email HTML contains a password or credential input",
            32,
            r"(?is)<input\b[^>]*\btype\s*=\s*['\"]?(?:password|email)['\"]?",
        ),
        (
            "HTML_SCRIPT_OBFUSCATION",
            "Email HTML contains script-obfuscation markers",
            28,
            r"(?is)\b(?:eval|unescape|fromCharCode)\s*\(|\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}|\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){3,}",
        ),
        (
            "HTML_HIDDEN_CONTENT",
            "Email HTML hides content from normal display",
            12,
            r"(?is)(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:[;\s]|$)|font-size\s*:\s*0)",
        ),
        (
            "UNSAFE_URI_SCHEME",
            "Email HTML uses an unsafe or opaque URI scheme",
            30,
            r"(?is)(?:href|src|action)\s*=\s*['\"]\s*(?:javascript:|data:text/html|blob:|file:)",
        ),
        (
            "HTML_FORCED_NAVIGATION",
            "Email HTML contains client-side forced navigation",
            28,
            r"(?is)\b(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=|\()|window\.open\s*\(",
        ),
    )
    for code, title, points, pattern in checks:
        match = re.search(pattern, body_html)
        if match:
            findings.append(Finding(code, title, "high" if points >= 28 else "medium", points, match.group(0)[:180], "advanced:html"))
            score += points
    return findings, ({"HTML smuggling or credential capture": min(100, score)} if score else {})


def _header_impersonation(headers: dict[str, str]) -> tuple[list[Finding], dict[str, object]]:
    if not headers:
        return [], {"status": "not_evaluated"}
    findings: list[Finding] = []
    display_name, address = parseaddr(headers.get("from", ""))
    from_domain = address.rsplit("@", 1)[-1].casefold().strip(".>") if "@" in address else ""
    display_folded = unicodedata.normalize("NFKC", display_name.casefold())
    brand_hits: list[str] = []
    for brand, official_domains in BRANDS.items():
        if re.search(rf"(?<!\w){re.escape(brand)}(?!\w)", display_folded) and registrable_domain(from_domain) not in official_domains:
            brand_hits.append(brand)
    if brand_hits:
        findings.append(
            Finding(
                "DISPLAY_NAME_BRAND_IMPERSONATION",
                "Display name claims a brand not aligned with the sender domain",
                "high",
                24,
                f"Claimed: {', '.join(brand_hits)}; sender domain: {from_domain or 'unavailable'}",
                "headers",
            )
        )
    controls = [f"U+{ord(char):04X}" for char in f"{display_name}{address}" if unicodedata.category(char) in {"Cf", "Cc"}]
    if controls:
        findings.append(
            Finding(
                "HEADER_UNICODE_CONTROL",
                "Sender identity contains invisible or bidirectional controls",
                "high",
                28,
                ", ".join(controls[:10]),
                "headers",
            )
        )
    message_id = headers.get("message-id", "")
    message_domain_match = re.search(r"@([^>\s]+)", message_id)
    message_domain = message_domain_match.group(1).casefold().strip(".") if message_domain_match else ""
    if from_domain and message_domain and registrable_domain(from_domain) != registrable_domain(message_domain):
        findings.append(
            Finding(
                "MESSAGE_ID_DOMAIN_MISMATCH",
                "Message-ID domain differs from the visible sender domain",
                "low",
                5,
                f"From: {from_domain}; Message-ID: {message_domain}",
                "headers",
            )
        )
    return findings, {
        "status": "evaluated",
        "display_name": display_name[:160],
        "from_domain": from_domain,
        "claimed_brands": brand_hits,
        "message_id_domain": message_domain,
    }


def analyze_advanced(
    subject: str, body_text: str, body_html: str, headers: dict[str, str]
) -> tuple[list[Finding], dict[str, int], dict[str, object]]:
    text = f"{subject}\n{body_text}"[:250_000]
    indicators = extract_sensitive_indicators(text)
    rule_findings, category_scores, mappings = _advanced_rule_findings(text)
    callback_findings, callback_scores = _callback_findings(text, indicators)
    payment_findings, payment_scores = _payment_findings(text, indicators)
    html_findings, html_scores = _html_findings(body_html[:1_000_000])
    header_findings, impersonation = _header_impersonation(headers)
    findings = rule_findings + callback_findings + payment_findings + html_findings + header_findings

    for scores in (callback_scores, payment_scores, html_scores):
        for category, points in scores.items():
            category_scores[category] = category_scores.get(category, 0) + points

    sources = {finding.source.split(":", 1)[-1] for finding in findings if finding.points >= 20}
    if len(sources) >= 3:
        findings.append(
            Finding(
                "MULTI_TACTIC_CORROBORATION",
                "Multiple advanced phishing tactics corroborate one another",
                "high",
                14,
                ", ".join(sorted(sources)),
                "advanced:correlation",
            )
        )

    metadata: dict[str, object] = {
        "version": ADVANCED_RULE_PACK_VERSION,
        "sensitive_indicators": indicators,
        "sensitive_values_redacted": True,
        "attack_mappings": mappings,
        "impersonation": impersonation,
        "tactic_count": len([finding for finding in findings if finding.points > 0]),
    }
    return findings, category_scores, metadata


def validate_advanced_rules() -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for rule in ADVANCED_RULES:
        if rule.rule_id in seen:
            errors.append(f"duplicate advanced rule id: {rule.rule_id}")
        seen.add(rule.rule_id)
        if not 1 <= rule.points <= 50:
            errors.append(f"invalid points for {rule.rule_id}: {rule.points}")
        try:
            re.compile(rule.pattern, re.IGNORECASE | re.DOTALL)
        except re.error as exc:
            errors.append(f"invalid regex for {rule.rule_id}: {exc}")
    return errors
