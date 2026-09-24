from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import Any

from .advanced import ADVANCED_RULE_PACK_VERSION, ADVANCED_RULES, validate_advanced_rules
from .locale_rules import (
    GENERIC_RULES,
    RULE_PACK_VERSION,
    SCAM_RULES,
    SUPPORTED_LANGUAGES,
    validate_rule_pack,
)

SCHEMA_VERSION = "1.0"


def _digest(value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def build_rule_manifest() -> dict[str, Any]:
    """Describe the exact built-in rules without asserting package authenticity."""
    locale_rules = [asdict(rule) for rule in SCAM_RULES]
    advanced_rules = [asdict(rule) for rule in ADVANCED_RULES]
    generic_rules = [list(rule) for rule in GENERIC_RULES]
    body: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "locale_rule_pack_version": RULE_PACK_VERSION,
        "advanced_rule_pack_version": ADVANCED_RULE_PACK_VERSION,
        "counts": {
            "locale_rules": len(locale_rules),
            "advanced_rules": len(advanced_rules),
            "generic_rules": len(generic_rules),
            "languages": len(SUPPORTED_LANGUAGES),
        },
        "languages": sorted(SUPPORTED_LANGUAGES),
        "locale_rule_ids": [rule["rule_id"] for rule in locale_rules],
        "advanced_rule_ids": [rule["rule_id"] for rule in advanced_rules],
        "categories": sorted({rule["category"] for rule in locale_rules + advanced_rules}),
        "digests": {
            "locale_rules_sha256": _digest(locale_rules),
            "advanced_rules_sha256": _digest(advanced_rules),
            "generic_rules_sha256": _digest(generic_rules),
        },
        "integrity": {
            "algorithm": "SHA-256",
            "authenticity": "not_asserted",
            "note": "A matching digest detects accidental change; it does not prove publisher identity.",
        },
    }
    body["manifest_sha256"] = _digest(body)
    return body


def validate_rule_manifest(manifest: object) -> list[str]:
    """Compare a manifest with the installed built-in rule set."""
    errors = validate_rule_pack() + validate_advanced_rules()
    if not isinstance(manifest, dict):
        return errors + ["manifest must be a JSON object"]
    expected = build_rule_manifest()
    if manifest.get("schema_version") != SCHEMA_VERSION:
        errors.append("unsupported manifest schema_version")
    supplied_digest = manifest.get("manifest_sha256")
    body = {key: value for key, value in manifest.items() if key != "manifest_sha256"}
    if supplied_digest != _digest(body):
        errors.append("manifest digest does not match its content")
    if manifest != expected:
        errors.append("manifest does not match the installed built-in rules")
    return errors
