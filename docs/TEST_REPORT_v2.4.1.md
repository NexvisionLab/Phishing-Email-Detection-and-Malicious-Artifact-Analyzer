# Release validation report v2.4.1

Date: 2026-09-24

## Summary

All automated source, test, type, package, dependency, and representative output checks completed successfully after remediation. PDF and DOCX examples were rendered to page images and visually inspected; no clipping, overlap, missing sections, or unreadable output was observed.

## Commands and results

| Command | Result |
|---|---|
| `python -m pytest -q` | 155 passed (one upstream AnyIO deprecation warning) |
| `ruff check phishing_analyzer tests` | Passed |
| `mypy phishing_analyzer` | Passed, 18 source files checked |
| `bandit -q -r phishing_analyzer` | Passed; no findings |
| `detect-secrets scan` with generated-hash exclusions | No verified secrets found |
| `pip check` | Passed |
| `pip-audit -r requirements-production.txt` | No known vulnerabilities found on 2026-09-24 |
| `python -m build` | Source distribution and wheel built successfully |
| CLI JSON/HTML/PDF/DOCX/STIX generation | Passed for `examples/sample_advanced_phishing.eml` |
| `phishcheck --rule-manifest` and `--verify-rule-manifest` | Passed |
| FastAPI health, bearer-authentication, analysis, and requested-network-policy tests | Passed |
| Wheel metadata and content inspection | Version, licence expression, `LICENSE.md`, package modules, and console entry point verified |
| PDF render with Poppler | 2 pages; visual QA passed |
| DOCX render with the document renderer and LibreOffice | 3 pages; visual QA passed |

## Security regression coverage added

- Network functions remain unused even when the legacy network flag is true.
- Compressed PDF active markers and URLs are detected within bounded resources.
- Relative HTML destinations resolve through an absolute base URL; contact URIs are not disclosed.
- Rule manifests are reproducible and fail verification after tampering.
- STIX exports omit zero-signal URLs and use valid UUID/timestamp fields.
- HTML reports carry CSP and referrer restrictions.
- API rate-limit state is synchronized, bounded, and rejects excess requests.
- API bearer authentication and offline-policy reporting are exercised end to end.

## Not verified by automated tests

- Real-world precision, recall, calibration, and drift on an independent corpus.
- Multi-process or distributed gateway enforcement.
- Artifact signatures, protected Git tags, and build-system provenance because the supplied package contained no Git history or signing material.
- Organization-specific legal, retention, access-control, and incident-response approval.
