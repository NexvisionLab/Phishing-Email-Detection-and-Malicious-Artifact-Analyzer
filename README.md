# NexVision Offline Phishing Analyzer

[![CI](https://github.com/NexvisionLab/NexVision-PhishIntel/actions/workflows/ci.yml/badge.svg)](https://github.com/NexvisionLab/NexVision-PhishIntel/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB)](https://www.python.org/)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/license-PolyForm%20Noncommercial%201.0.0-blue)](LICENSE.md)

NexVision Offline Phishing Analyzer is a defensive, source-available Python toolkit for inspecting pasted email text and RFC 5322 `.eml` messages without contacting external services. It classifies social-engineering intent, analyzes headers and attachments, statically ranks discovered HTTP(S) destinations, and deeply inspects up to three high-risk links.

> The result is an analyst triage aid—not proof that a message is malicious or safe. Consequential decisions require examiner review.

## Why this project

- **Fully offline:** no DNS, TLS, RDAP, URL visits, cloud APIs, third-party submissions, or telemetry.
- **Evidence-led:** reports explain findings, scoring dimensions, evidence coverage, limitations, and analyst-review requirements.
- **Multilingual:** deterministic coverage across 19 language variants and multiple regional scam patterns.
- **Broad scam taxonomy:** credential theft, BEC, delivery, job/task, investment, romance, recovery, authority impersonation, callback fraud, QR lures, OAuth/device-code abuse, ClickFix, and more.
- **Static attachment triage:** PDFs, images, HTML/SVG, calendar invitations, archives, Office containers, attached emails, and optional local QR decoding.
- **Multiple outputs:** JSON, HTML, PDF, DOCX, and STIX 2.1.

## Safety model

```mermaid
flowchart TD
    A[Email text or EML] --> B[Bounded parser]
    B --> C[Header and content rules]
    B --> D[Static URL analysis]
    B --> E[Static attachment analysis]
    C --> F[Evidence and score]
    D --> F
    E --> F
    F --> G[JSON HTML PDF DOCX STIX]
```

Inputs are processed locally. Extracted destinations are treated as strings and are never opened. Attachments are not executed or detonated.

## Installation

```bash
git clone https://github.com/NexvisionLab/NexVision-PhishIntel.git
cd NexVision-PhishIntel
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Optional components:

```bash
python -m pip install '.[api]'  # Local FastAPI service
python -m pip install '.[qr]'   # Local QR decoding
python -m pip install '.[dev]'  # Tests, linting, typing and builds
```

## Command line

```bash
phishcheck suspicious.eml
phishcheck suspicious.eml --format html --output report.html
phishcheck suspicious.eml --format pdf --output report.pdf
phishcheck suspicious.eml --format docx --output report.docx
phishcheck suspicious.eml --format stix --output indicators.json
```

Use trusted receiver-generated authentication results and an approved local indicator feed:

```bash
phishcheck suspicious.eml \
  --trusted-authserv-id mx.company.example \
  --feed ./feeds/approved-indicators.txt
```

Generate and verify the deterministic rule manifest:

```bash
phishcheck --rule-manifest --output rule-manifest.json
phishcheck --verify-rule-manifest rule-manifest.json
```

The legacy `--network`, `network_enabled`, and `cache_dir` inputs remain for compatibility but cannot activate networking. A request is recorded as `disabled_by_policy`.

## Python API

```python
from phishing_analyzer import analyze_email

result = analyze_email(
    raw_email,
    trusted_authserv_ids={"mx.company.example"},
    feed_paths=["./feeds/approved-indicators.txt"],
)

print(result.risk)
print(result.score)
print(result.to_dict())
```

## Local HTTP API

```bash
export PHISHCHECK_API_TOKEN='replace-with-a-random-secret'
uvicorn phishing_analyzer.api:app --host 127.0.0.1 --port 8080
```

```bash
curl -s http://127.0.0.1:8080/v1/analyze \
  -H 'Authorization: Bearer replace-with-a-random-secret' \
  -H 'Content-Type: application/json' \
  --data '{"content":"Urgent: verify your account at https://example.test/login"}'
```

Keep the built-in service on localhost. External or multi-worker deployment requires a reviewed gateway providing TLS, centralized authentication, centralized rate limiting, audit retention, and access control.

## Detection and reporting

Every result includes:

- classification, risk, triage score, and evidence confidence;
- sender-authenticity, message-intent, destination-risk, and payload-risk dimensions;
- selected and non-selected links with static evidence;
- attachment hashes, detected types, findings, and coverage limits;
- language and regional-pattern indicators without nationality attribution;
- rule-pack versions and deterministic manifest digest;
- explicit limitations and analyst disposition.

See [Detection coverage](docs/DETECTION_COVERAGE.md), [Architecture](docs/ARCHITECTURE.md), [API reference](docs/API.md), and [Security and privacy](docs/SECURITY_AND_PRIVACY.md).

## Validation

Release 2.4.1 passed 155 automated tests, Ruff, Mypy, Bandit, package integrity checks, dependency vulnerability scanning, and representative JSON/HTML/PDF/DOCX/STIX workflows. PDF and DOCX examples were also render-checked.

The public security review is in [PUBLIC_SECURITY_AUDIT.md](PUBLIC_SECURITY_AUDIT.md). It does not claim real-world accuracy, calibration, or freedom from all defects. Independent multilingual and campaign-separated validation remains required before broad operational use.

Run the quality gates locally:

```bash
python -m pip install '.[api,dev]'
pytest -q
ruff check phishing_analyzer tests
mypy phishing_analyzer
python -m build
```

## Repository map

| Path | Purpose |
|---|---|
| `phishing_analyzer/` | Analyzer, parsers, rules, scoring, reports, CLI and API |
| `tests/` | Unit, adversarial, resource-limit and regression tests |
| `docs/` | Architecture, security, API, coverage, research and validation |
| `examples/` | Synthetic input and generated report examples |
| `requirements-production.txt` | Tested Linux production dependency resolution |
| `docs/sbom-v2.4.1.cdx.json` | CycloneDX software bill of materials |

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes. Report security vulnerabilities privately through GitHub Security Advisories as described in [SECURITY.md](SECURITY.md). Do not place real malicious payloads, personal information, secrets, or production emails in public issues or pull requests.

## Licence

Copyright © 2026 NexVision Lab.

This project is source-available under the PolyForm Noncommercial License 1.0.0. It may be used, studied and modified for permitted non-commercial purposes.

Commercial use, paid services, commercial redistribution, production deployment and hosted services require a separate written licence from NexVision Lab.

SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
