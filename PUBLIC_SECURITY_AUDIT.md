# Public release security audit

Release: 2.4.1
Audit date: 2026-09-24
Decision: approved for source publication; conditional for controlled offline pilot use.

## Scope

The review covered Python source, tests, configuration examples, dependency metadata, documentation, synthetic examples, generated reports, package contents and release artefacts. It traced CLI, Python and HTTP workflows and reviewed privacy, secret exposure, hostile-input limits, network behavior, dependency vulnerabilities and licence preservation.

## Results

| Area | Result | Evidence |
|---|---|---|
| Automated tests | Pass | 155 tests |
| Lint | Pass | Ruff |
| Static typing | Pass | Mypy across 18 source files |
| Dependency consistency | Pass | `pip check` |
| Known dependency vulnerabilities | Pass at audit time | Production requirements scanned with `pip-audit` |
| Static security analysis | Pass after review | Bandit and manual source inspection |
| Secrets | No verified secrets found | Pattern scan and `detect-secrets` review |
| Personal contact data | No personal name, personal email, phone number or address published | Repository-wide text and archive scan |
| Runtime network behavior | Disabled by policy | Regression test blocks DNS, sockets and HTTPS even when requested |
| Package integrity | Pass | Wheel/sdist contents and licence metadata inspected |
| Reports | Pass | JSON/HTML/PDF/DOCX/STIX workflows; PDF/DOCX render review |

## Detailed findings

| Severity | Classification | File and line | Evidence | Impact | Action |
|---|---|---|---|---|---|
| High | Confirmed defect | `phishing_analyzer/api.py:62-68` | The API previously allowed any client when `PHISHCHECK_API_TOKEN` was unset. | An unintentionally exposed service could permit unauthenticated analysis requests and resource use. | Fixed: tokenless operation is now limited to loopback addresses; non-loopback clients fail closed with HTTP 401. Regression tests cover both paths. |
| Low | Confirmed defect | `phishing_analyzer/urls.py:153-155` | Bandit identified assertion-dependent type assumptions in a runtime parsing path. Python assertions can be disabled. | Optimized interpreter mode could bypass defensive assumptions and produce an unexpected exception on malformed intermediate data. | Fixed: explicit type checks replace assertions. Bandit now reports no findings. |
| Low | Confirmed defect | `tests/test_production_v24.py:23-38` | A synthetic contact-redaction fixture used a non-reserved-looking telephone number. | Although not linked to a person, publishing arbitrary contact-like data creates avoidable privacy ambiguity. | Fixed: the fixture now uses the fictional North American 202-555-01xx range and remains covered by redaction assertions. |
| Low | Confirmed defect | `README.md:3,39-40`; `pyproject.toml:19-22`; `CITATION.cff:10` | Publication metadata referenced the earlier planned repository slug instead of the final `Phishing-Email-Detection-and-Malicious-Artifact-Analyzer` repository. | Clone commands, CI badges, project links and citation metadata would direct users to the wrong location. | Fixed before final publication verification; all repository references now use `NexvisionLab/Phishing-Email-Detection-and-Malicious-Artifact-Analyzer`. (An earlier revision of this row named a slug that was never the published repository.). |
| Informational | Needs verification | `docs/DETECTION_COVERAGE.md:1-54` | No independent, campaign-separated multilingual evaluation corpus was available. | Precision, recall, calibration and cross-region generalization cannot be claimed from the current test suite. | Documented limitation; require an independently governed benchmark before production accuracy claims. |
| Informational | Needs verification | `pyproject.toml:24-35` | One upstream Starlette test-client dependency emits an AnyIO deprecation warning while all tests pass. | A future dependency update may require compatibility work; no current runtime failure was observed. | Track through Dependabot and CI; do not suppress the warning in project code. |
| Informational | Visible artifact | Repository-wide scan | No accidental assistant/model references, chat transcripts, prompt fragments, placeholder citations or generated metadata were found. The audit statement itself intentionally discusses these categories. | None in the audited public tree. | No removal required; retain the evidence-based statement below. |

## Security changes included

- Removed live DNS, TLS and RDAP behavior while preserving compatibility parameters.
- Added bounded PDF decompression and partial-coverage evidence.
- Added HTML contact redaction and base-URL resolution.
- Corrected STIX identifier, timestamp and confidence semantics.
- Added HTML CSP and referrer restrictions.
- Bounded and synchronized API rate-limit state.
- Added fail-closed authentication for non-loopback API clients.
- Added deterministic rule manifests, production dependency pins and a CycloneDX SBOM.

## Publication privacy review

Synthetic examples use reserved `.test`, `.example`, `.invalid`, documentation domains and fictional 202-555-01xx phone numbers. Tests that validate official-domain impersonation behavior contain public brand domains only; they contain no personal contact details. Configuration contains placeholders only. No API keys, authentication tokens, private keys, passwords, personal contact information or production case material are intentionally included.

## Remaining operational risks

- No independent, campaign-separated multilingual corpus was supplied, so accuracy and calibration claims are not made.
- The built-in HTTP service is not approved as a standalone internet-facing boundary.
- Dependency versions are pinned but release artefacts are not cryptographically signed or hash-locked.
- OCR, detonation, live reputation, password-assisted archives and organization-specific baselines are outside scope.
- Production deployment and hosted services require a separate written licence from NexVision Lab.

## Artifact statement

No accidental assistant/model references, chat transcripts, prompt fragments, placeholder citations, unfinished feature stubs or hard-coded production results were found in the public release scope. This does not prove that code was or was not AI-generated; authorship cannot be established from coding style.
