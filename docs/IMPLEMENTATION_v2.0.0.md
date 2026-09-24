# NexVision Phishing Analyzer v2.0.0 — Implementation Record

## Release objective

Complete roadmap items 1–11 in a single additive, offline-first release while preserving the original Python entry point, CLI, local web service, input limit, and three-link deep-inspection ceiling.

## Control map

| # | Control | Implementation | Fail-closed behavior |
|---|---|---|---|
| 1 | Authentication trust | Explicit `authserv-id` allowlist; SPF/DKIM identity extraction; relaxed RFC5322.From alignment; ARC contextual note | Untrusted or absent results are `not_evaluated` and add zero points |
| 2 | Link selection | Static analysis of every URL; stable descending risk rank; top three enriched | Unselected links remain visible as `static only` |
| 3 | Organizational domains | Public Suffix List through `publicsuffix2` | Conservative label fallback if the PSL library is unavailable |
| 4 | Unicode/brands | IDNA, mixed scripts, control characters, confusable skeletons, edit distance, local brand registry | Evidence is advisory and reviewable |
| 5 | Domain OSINT | Direct DNS, TLS, and public RDAP; JSON cache | Disabled by default; errors are recorded without changing message content |
| 6 | Reporting | JSON, HTML, PDF, DOCX, STIX 2.1; case and SHA-256 identity; evidence coverage | Missing checks are explicit |
| 7 | HTML | Standard-library parser for URL-bearing tags/attributes, meta-refresh, SVG, CSS, percent/base64 tokens | No rendering, JavaScript, or remote resource load |
| 8 | Attachments/QR | Static magic, hashes, archive/OOXML/PDF/HTML checks; bounded expansion; optional local OpenCV QR | Never executes; oversized/unsupported work is `not_evaluated` |
| 9 | Content | English/Chinese/Malay/Tamil rules plus local character n-gram similarity | Negation suppression; pattern-undetermined abstention |
| 10 | Thread context | Message-ID, References, In-Reply-To and Reply-To organizational-domain changes | No identity claim is inferred |
| 11 | Scoring | Sender, intent, destination, payload dimensions; corroboration-aware fusion | Score is labelled as triage, never probability |

## Data handling

- Maximum message size: 2 MB.
- Maximum single attachment static-analysis size: 10 MB.
- Maximum archive members: 200.
- Maximum declared archive expansion: 50 MB.
- No cloud or commercial threat-intelligence API, API keys, or message submission.
- Optional network mode sends only selected domain names to normal DNS/TLS and public RDAP infrastructure.
- Local feed files are read-only and may contain URLs, hosts, or SHA-256 URL hashes.

## Backward compatibility

- `analyze_email(raw, network_enabled=False)` remains valid.
- Existing `Finding`, `LinkResult`, and `AnalysisResult` fields remain; new fields have defaults.
- CLI default remains JSON to stdout.
- Local FastAPI routes remain `/health` and `/v1/analyze`.
- `links_checked` remains capped at three; `links` now lists all statically analyzed destinations and marks deep selection.

## Governance

Every output includes the deterministic model type, whether analyst review is required, the message SHA-256, a deterministic case ID, evidence coverage, confidence, limitations, and analyst disposition. Thresholds are operational defaults and must be calibrated against an independently labelled, campaign-separated corpus before claims about sensitivity, specificity, or probability are made.
