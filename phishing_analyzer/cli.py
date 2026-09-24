from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from .analyzer import analyze_email
from .models import AnalysisResult
from .report import docx_report, html_report, json_report, pdf_report, stix_report
from .rulepack import build_rule_manifest, validate_rule_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze pasted email content or an .eml file for phishing indicators")
    parser.add_argument("input", nargs="?", help="Path to an .eml/text file; omit to read stdin")
    parser.add_argument(
        "--network", action="store_true", help="Deprecated compatibility flag; network enrichment is disabled by production policy"
    )
    parser.add_argument(
        "--trusted-authserv-id", action="append", default=[], help="Trusted Authentication-Results authserv-id (repeatable)"
    )
    parser.add_argument("--feed", action="append", default=[], help="Local newline/JSON indicator feed (repeatable)")
    parser.add_argument("--cache-dir", help="Deprecated compatibility option; no network cache is read or written")
    parser.add_argument("--rule-manifest", action="store_true", help="Print the built-in rule manifest and exit")
    parser.add_argument("--verify-rule-manifest", help="Verify a rule-manifest JSON file against the built-in rules and exit")
    parser.add_argument("--format", choices=("json", "html", "pdf", "docx", "stix"), default="json")
    parser.add_argument("--output", help="Write report to this path instead of stdout")
    args = parser.parse_args()
    if args.rule_manifest:
        import json

        manifest_text = json.dumps(build_rule_manifest(), ensure_ascii=False, indent=2)
        if args.output:
            Path(args.output).write_text(manifest_text, encoding="utf-8")
        else:
            print(manifest_text)
        return 0
    if args.verify_rule_manifest:
        import json

        manifest = json.loads(Path(args.verify_rule_manifest).read_text(encoding="utf-8"))
        errors = validate_rule_manifest(manifest)
        if errors:
            parser.error("; ".join(errors))
        print("Rule manifest verified")
        return 0
    raw = Path(args.input).read_bytes() if args.input else sys.stdin.buffer.read()
    try:
        trusted = set(args.trusted_authserv_id) if args.trusted_authserv_id else None
        result = analyze_email(
            raw, network_enabled=args.network, trusted_authserv_ids=trusted, feed_paths=args.feed or None, cache_dir=args.cache_dir
        )
    except ValueError as exc:
        parser.error(str(exc))
    renderers: dict[str, Callable[[AnalysisResult], str | bytes]] = {
        "json": json_report,
        "html": html_report,
        "pdf": pdf_report,
        "docx": docx_report,
        "stix": stix_report,
    }
    output = renderers[args.format](result)
    if args.output:
        if isinstance(output, bytes):
            Path(args.output).write_bytes(output)
        else:
            Path(args.output).write_text(output, encoding="utf-8")
    else:
        if isinstance(output, bytes):
            parser.error("binary PDF/DOCX output requires --output")
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
