# Architecture

## Purpose

The analyzer converts untrusted email material into bounded, explainable triage evidence without following links or executing content.

## Components

| Module | Responsibility |
|---|---|
| `extractor.py` | Bounded RFC 5322, text, HTML, encoding and URL extraction |
| `headers.py` | Sender, authentication, alignment and thread-context evidence |
| `content.py` | Text normalization, scam-rule evaluation and classification |
| `locale_rules.py` | Versioned multilingual and regional wording rules |
| `advanced.py` | Advanced lure, impersonation, callback, payment and HTML tactics |
| `urls.py` | URL normalization, Unicode/domain checks, redirect parameters and static risk |
| `attachments.py` | Static attachment, archive, PDF, Office, HTML, calendar and QR inspection |
| `reputation.py` | Optional local indicator-feed matching |
| `osint.py` | Compatibility boundary that explicitly denies network enrichment |
| `analyzer.py` | Workflow orchestration, evidence coverage and four-dimensional scoring |
| `report.py` | JSON, HTML, PDF, DOCX and STIX rendering |
| `rulepack.py` | Deterministic rule inventory, digests and verification |
| `cli.py` / `api.py` | Local CLI and optional localhost API interfaces |

## Processing sequence

1. Reject empty input and input larger than 2 MB.
2. Parse plain text or RFC 5322 content with bounded fallbacks.
3. Evaluate message content, advanced tactics, headers and attachments.
4. Extract and deduplicate at most 2,000 HTTP(S) destinations.
5. Apply static URL analysis to every retained destination.
6. Select up to three highest-risk destinations for local-feed enrichment.
7. Calculate separate sender, intent, destination and payload dimensions.
8. Produce evidence coverage, limitations, governance metadata and reports.

## Trust boundaries

- Input email and attachments are untrusted.
- `Authentication-Results` is scored only for explicitly trusted `authserv-id` values.
- Local indicator feeds are administrator-supplied data and should be provenance-controlled.
- Generated HTML uses a restrictive CSP and no-referrer policy.
- STIX objects contain suspicious static indicators, not confirmed maliciousness.

## Resource ceilings

| Resource | Limit |
|---|---:|
| Raw message | 2 MB |
| Unique destinations | 2,000 |
| Deep-inspected destinations | 3 |
| Attachments | 100 |
| Individual attachment | 10 MB |
| Archive members | 200 |
| Archive expanded size | 50 MB |
| PDF decompressed inspection | 5 MB |
| PDF streams | 20 |

Coverage states become `partial` or `not_evaluated` when a ceiling prevents complete inspection.
