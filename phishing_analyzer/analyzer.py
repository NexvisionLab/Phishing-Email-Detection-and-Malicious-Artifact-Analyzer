from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime

from .advanced import analyze_advanced
from .attachments import analyze_attachment
from .content import analyze_content, detect_languages, matched_scam_rules, normalize_text
from .extractor import extract_urls, parse_input
from .headers import analyze_headers_detailed
from .locale_rules import RULE_PACK_VERSION, SUPPORTED_LANGUAGES, language_scores, region_signals
from .models import AnalysisResult, Finding, ScoreDimensions
from .osint import enrich_domain
from .reputation import enrich_url, reputation_points
from .rulepack import build_rule_manifest
from .urls import analyze_url, risk_label

MAX_INPUT_BYTES = 2_000_000
MAX_LINKS = 3
MAX_ATTACHMENTS = 100


def _confidence(findings: list[Finding], evidence_status: dict[str, str]) -> str:
    observed = [f for f in findings if f.status == "observed" and f.points > 0]
    independent_sources = len({f.source.split(":", 1)[0] for f in observed})
    evaluated = sum(value in {"evaluated", "checked", "complete", "partial"} for value in evidence_status.values())
    if independent_sources >= 3 and evaluated >= 3:
        return "high"
    if independent_sources >= 2 or evaluated >= 2:
        return "moderate"
    return "limited"


def _trusted_ids(explicit: set[str] | None) -> set[str]:
    if explicit is not None:
        return explicit
    return {item.strip().casefold() for item in os.getenv("PHISHCHECK_TRUSTED_AUTHSERV_IDS", "").split(",") if item.strip()}


def _score(dimensions: ScoreDimensions, corroborated: bool) -> int:
    # This is a triage index, not a probability. A strong single dimension can
    # drive escalation while corroboration rewards independent evidence.
    peak = max(dimensions.sender_authenticity, dimensions.message_intent, dimensions.destination_risk, dimensions.payload_risk)
    blended = round(
        dimensions.sender_authenticity * 0.25
        + dimensions.message_intent * 0.25
        + dimensions.destination_risk * 0.35
        + dimensions.payload_risk * 0.25
    )
    return min(100, max(peak, blended + (10 if corroborated else 0)))


def analyze_email(
    raw: str | bytes,
    network_enabled: bool = False,
    trusted_authserv_ids: set[str] | None = None,
    feed_paths: list[str] | None = None,
    cache_dir: str | None = None,
) -> AnalysisResult:
    raw_bytes = raw if isinstance(raw, bytes) else raw.encode("utf-8", errors="replace")
    if not raw_bytes.strip():
        raise ValueError("Email content is empty")
    if len(raw_bytes) > MAX_INPUT_BYTES:
        raise ValueError("Input exceeds the 2 MB analysis limit")

    parsed = parse_input(raw)
    classification, content_findings, category_scores = analyze_content(parsed.subject, parsed.body_text)
    advanced_findings, advanced_scores, advanced_meta = analyze_advanced(
        parsed.subject,
        parsed.body_text,
        parsed.body_html,
        parsed.headers,
    )
    for category, points in advanced_scores.items():
        category_scores[category] = category_scores.get(category, 0) + points
    if category_scores:
        classification = max(category_scores, key=lambda name: category_scores[name])
    normalized_message = normalize_text(f"{parsed.subject}\n{parsed.body_text}")
    languages = detect_languages(normalized_message)
    # Preserve the v2.0 generic Chinese code while exposing script-specific
    # BCP-47-style variants for new integrations.
    if any(code.startswith("zh-") for code in languages):
        languages.append("zh")
    language_profile = language_scores(normalized_message)
    matched_rules = matched_scam_rules(parsed.subject, parsed.body_text)
    regional_patterns = region_signals(normalized_message, matched_rules)
    header_findings, auth_meta = analyze_headers_detailed(parsed.headers, _trusted_ids(trusted_authserv_ids))
    attachment_results = [analyze_attachment(item) for item in parsed.attachments[:MAX_ATTACHMENTS]]
    attachments_skipped = max(0, len(parsed.attachments) - len(attachment_results))
    all_urls, mismatches = extract_urls(parsed)
    for attachment in attachment_results:
        all_urls.extend(url for url in attachment.extracted_urls if url.casefold() not in {item.casefold() for item in all_urls})

    # Static analysis is safe for all destinations. The three highest-risk
    # destinations receive local-feed checks. Network enrichment is permanently
    # disabled by production policy; the compatibility flag records intent only.
    link_results = [analyze_url(url) for url in all_urls]
    mismatch_destinations = {actual.casefold() for _, actual in mismatches}
    for result in link_results:
        result.rank_score = min(100, result.score + (25 if result.display_url.casefold() in mismatch_destinations else 0))
        result.selected_for_deep_inspection = False
    selected = sorted(link_results, key=lambda item: (-item.rank_score, all_urls.index(item.display_url)))[:MAX_LINKS]
    for result in selected:
        result.selected_for_deep_inspection = True
        result.reputation = enrich_url(result.normalized_url, feed_paths=feed_paths)
        result.osint = enrich_domain(result.registrable_domain or result.host, network_enabled, cache_dir)
        rep_points = reputation_points(result.reputation)
        if rep_points:
            result.findings.append(
                Finding(
                    "LOCAL_FEED_HIT",
                    "Local threat-intelligence feed contains this destination",
                    "high",
                    rep_points,
                    str(result.reputation.get("matches", []))[:500],
                    "reputation",
                )
            )
            result.score = min(100, result.score + rep_points)
            result.risk = risk_label(result.score)

    mismatch_findings = [
        Finding(
            "DISPLAY_LINK_MISMATCH",
            "Visible link text differs from its destination",
            "high",
            25,
            f"Shown: {shown}; Destination: {actual}",
            "url",
        )
        for shown, actual in mismatches[:20]
    ]
    html_findings = [
        Finding("ACTIVE_HTML_DESTINATION", f"HTML contains {item['type'].replace('_', ' ')}", "medium", 10, item["value"], "html")
        for item in parsed.html_indicators[:20]
        if item["type"] != "url_extraction_limit"
    ]
    resource_findings: list[Finding] = []
    url_extraction_limited = any(item["type"] == "url_extraction_limit" for item in parsed.html_indicators)
    if url_extraction_limited:
        resource_findings.append(
            Finding(
                "URL_EXTRACTION_LIMIT",
                "Message exceeded the static URL-analysis ceiling",
                "medium",
                8,
                "First 2,000 unique destinations retained",
                "resource",
                "partial",
            )
        )
    if attachments_skipped:
        resource_findings.append(
            Finding(
                "ATTACHMENT_COUNT_LIMIT",
                "Message exceeded the attachment-analysis ceiling",
                "high",
                15,
                f"{attachments_skipped} attachment(s) not analyzed after the first {MAX_ATTACHMENTS}",
                "resource",
                "partial",
            )
        )
    advanced_header_findings = [finding for finding in advanced_findings if finding.source == "headers"]
    advanced_intent_findings = [finding for finding in advanced_findings if finding.source != "headers"]
    findings = content_findings + advanced_findings + header_findings + mismatch_findings + html_findings + resource_findings
    attachment_findings = [finding for item in attachment_results for finding in item.findings]
    link_findings = [finding for item in selected for finding in item.findings]

    dimensions = ScoreDimensions(
        sender_authenticity=min(
            100, sum(f.points for f in header_findings + advanced_header_findings if f.source in {"headers", "thread"})
        ),
        message_intent=min(100, sum(f.points for f in content_findings + advanced_intent_findings)),
        destination_risk=max((item.score for item in selected), default=0),
        payload_risk=max((item.score for item in attachment_results), default=0),
    )
    active_dimensions = sum(
        value >= 12
        for value in (dimensions.sender_authenticity, dimensions.message_intent, dimensions.destination_risk, dimensions.payload_risk)
    )
    score = _score(dimensions, active_dimensions >= 2)
    strongest_category = max(category_scores.values(), default=0)
    if selected and strongest_category >= 15:
        score = max(score, 35)
    risk = risk_label(score)

    attachment_partial = attachments_skipped > 0 or any(
        finding.status in {"partial", "not_evaluated"} for item in attachment_results for finding in item.findings
    )
    image_attachments = [item for item in attachment_results if item.detected_type == "image"]
    if not image_attachments:
        qr_status = "not_applicable"
    elif all(item.qr.get("status") == "evaluated" for item in image_attachments):
        qr_status = "evaluated"
    elif any(item.qr.get("status") == "evaluated" for item in image_attachments):
        qr_status = "partial"
    else:
        qr_status = "not_evaluated"
    evidence_status = {
        "content": "evaluated",
        "headers": "evaluated" if parsed.headers else "not_evaluated",
        "authentication": auth_meta.get("status", "not_evaluated"),
        "links_static": "partial" if url_extraction_limited else "evaluated" if all_urls else "not_applicable",
        "local_reputation": "checked"
        if selected and any(item.reputation.get("status") in {"checked", "matched", "partial"} for item in selected)
        else "not_evaluated",
        "network_osint": "disabled_by_policy" if network_enabled else "not_evaluated",
        "attachments": "partial" if attachment_partial else "evaluated" if parsed.attachments else "not_applicable",
        "qr": qr_status,
        "thread_context": "evaluated" if parsed.headers.get("in-reply-to") or parsed.headers.get("references") else "not_applicable",
        "language_support": "limited" if languages == ["undetermined"] else "evaluated",
        "regional_patterns": "observed" if regional_patterns else "not_observed",
        "advanced_tactics": "observed" if advanced_findings else "not_observed",
        "sensitive_indicator_extraction": "evaluated",
    }
    all_findings = findings + attachment_findings + link_findings
    confidence = _confidence(all_findings, evidence_status)
    summary = {
        "high": "Strong phishing indicators were identified. Do not reply, open links, or provide credentials.",
        "likely_phishing": "Multiple indicators are consistent with phishing. Treat the message as malicious until verified independently.",
        "suspicious": "Suspicious indicators were identified. Verify the sender through a trusted channel before acting.",
        "low": "No strong indicator was identified, but this result does not prove the email is safe.",
    }[risk]
    skipped = max(0, len(all_urls) - len(selected))
    limitations = [
        "The score is a triage index, not a probability or proof of malicious intent.",
        "All unique HTTP(S) destinations are statically ranked; only the three highest-risk destinations receive deep enrichment.",
        "Static analysis applies resource ceilings of 2,000 unique destinations and 100 attachments per message; any truncation is explicitly reported as partial coverage.",
        "Authentication-Results is scored only when its authserv-id is explicitly trusted.",
        "ARC presence is contextual evidence and does not prove that a message is safe.",
        "No live infrastructure or reputation lookup is performed; local feeds can miss new, targeted, compromised, or short-lived infrastructure.",
        "Attachments are statically inspected with strict limits; they are never executed or detonated.",
        "Language and brand rules are screening aids and require analyst review for consequential decisions.",
        "Regional-pattern matches indicate wording or named entities only; they do not establish sender location, identity, or nationality.",
        "Unsupported, short, code-switched, transliterated, or dialect-heavy text may be marked as limited language support.",
        "Advanced tactic rules identify message artifacts, not post-click behavior; endpoint, identity-provider, and mail telemetry are required to confirm execution or account compromise.",
        "Phone numbers, payment identifiers, and wallet addresses are masked and hashed in metadata; extraction can still miss obfuscated or image-only values.",
    ]
    message_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    analyzed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    rule_manifest = build_rule_manifest()
    return AnalysisResult(
        version="2.4.1",
        input_type=parsed.input_type,
        score=score,
        risk=risk,
        classification=classification,
        confidence=confidence,
        summary=summary,
        findings=findings,
        links=link_results,
        links_found=len(all_urls),
        links_checked=len(selected),
        limitations=limitations,
        attachments=attachment_results,
        dimensions=dimensions,
        evidence_status=evidence_status,
        metadata={
            "case_id": f"NV-{message_sha256[:16].upper()}",
            "message_sha256": message_sha256,
            "analyzed_at": analyzed_at,
            "subject": parsed.subject,
            "languages": languages,
            "language_scores": language_profile,
            "language_names": [SUPPORTED_LANGUAGES.get(code, code) for code in languages],
            "supported_languages": SUPPORTED_LANGUAGES,
            "rule_pack_version": RULE_PACK_VERSION,
            "rule_manifest_schema": rule_manifest["schema_version"],
            "rule_manifest_sha256": rule_manifest["manifest_sha256"],
            "matched_rule_ids": [rule.rule_id for rule in matched_rules],
            "regional_pattern_matches": regional_patterns,
            "advanced_detection": advanced_meta,
            "category_scores": category_scores,
            "links_skipped": skipped,
            "links_skipped_deep_inspection": skipped,
            "url_extraction_truncated": url_extraction_limited,
            "attachments_skipped": attachments_skipped,
            "link_selection": [
                {"url": item.display_url, "rank_score": item.rank_score, "selected": item.selected_for_deep_inspection}
                for item in sorted(link_results, key=lambda item: -item.rank_score)
            ],
            "authentication": auth_meta,
            "thread": {
                "message_id": parsed.headers.get("message-id", ""),
                "in_reply_to": parsed.headers.get("in-reply-to", ""),
                "references": parsed.headers.get("references", ""),
            },
            "governance": {
                "model": "deterministic_offline_rules_plus_supporting_character_model",
                "score_is_probability": False,
                "regional_match_is_origin_attribution": False,
                "analyst_review_required": risk != "low" or confidence == "limited",
            },
        },
    )
