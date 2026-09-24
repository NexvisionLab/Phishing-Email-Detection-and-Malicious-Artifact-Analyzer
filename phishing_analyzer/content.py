from __future__ import annotations

import re
import unicodedata
from collections import defaultdict

from .local_model import classify_local
from .locale_rules import GENERIC_RULES, NEGATION_PATTERNS, SCAM_RULES, detect_languages
from .models import Finding

NEGATION = re.compile("|".join(f"(?:{pattern})" for pattern in NEGATION_PATTERNS), re.IGNORECASE)


def normalize_text(value: str) -> str:
    value = unicodedata.normalize("NFKC", value)
    value = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]", "", value)
    return re.sub(r"(?<=\w)[._\u200b](?=\w)", "", value)


def _negated(text: str, start: int) -> bool:
    return bool(NEGATION.search(text[max(0, start - 55) : start]))


def matched_scam_rules(subject: str, body: str):
    text = normalize_text(f"{subject}\n{body}"[:250_000])
    return tuple(
        rule
        for rule in SCAM_RULES
        if (match := re.search(rule.pattern, text, re.IGNORECASE | re.DOTALL)) and not _negated(text, match.start())
    )


def analyze_content(subject: str, body: str) -> tuple[str, list[Finding], dict[str, int]]:
    text = normalize_text(f"{subject}\n{body}"[:250_000])
    category_scores: dict[str, int] = defaultdict(int)
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    for rule in SCAM_RULES:
        match = re.search(rule.pattern, text, re.IGNORECASE | re.DOTALL)
        identity = (rule.category, rule.title)
        if match and identity not in seen and not _negated(text, match.start()):
            seen.add(identity)
            category_scores[rule.category] += rule.points
            findings.append(
                Finding(
                    "CONTENT_PATTERN",
                    rule.title,
                    "medium" if rule.points < 25 else "high",
                    rule.points,
                    match.group(0)[:160],
                    f"content:{rule.language}:{rule.rule_id}",
                )
            )

    generic_seen: set[str] = set()
    for pattern, title, points in GENERIC_RULES:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match and title not in generic_seen and not _negated(text, match.start()):
            generic_seen.add(title)
            findings.append(Finding("SOCIAL_ENGINEERING", title, "low", points, match.group(0)[:160], "content"))

    model_category, model_similarity = classify_local(text)
    # The local n-gram model is supporting evidence only. It can never create a
    # high score by itself, and a negated warning is not treated as malicious.
    if model_similarity >= 0.24 and not (NEGATION.search(text) and not category_scores):
        model_points = min(10, max(4, round(model_similarity * 18)))
        category_scores[model_category] += model_points
        findings.append(
            Finding(
                "LOCAL_MODEL_SIGNAL",
                f"Offline character model resembles {model_category.lower()}",
                "low",
                model_points,
                f"cosine similarity {model_similarity:.3f}",
                "local_model",
            )
        )

    classification = max(category_scores, key=lambda name: category_scores[name]) if category_scores else "Pattern undetermined"
    return classification, findings, dict(category_scores)


__all__ = ["analyze_content", "detect_languages", "matched_scam_rules", "normalize_text"]
