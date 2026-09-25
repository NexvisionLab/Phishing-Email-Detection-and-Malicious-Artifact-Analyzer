# Changelog

## Unreleased

- API: a non-ASCII `Authorization` header now returns 401 instead of a 500.
- API: with no token configured, loopback requests must carry a local `Host` header (421 otherwise), closing a DNS-rebinding path; `PHISHCHECK_ALLOWED_HOSTS` extends the list.
- PDF report: each line is capped at 1,500 characters. One 200 KB URL took 48 s and a 1 MB URL over four minutes because ReportLab lays out unbreakable text quadratically; it now takes about 0.3 s. JSON, HTML and DOCX keep the full value.
- Parser: at most 2,000 MIME parts are examined (a 2 MB message with 50,000 parts took about 40 s); truncation is reported as a `mime_part_limit` indicator.
- Corrected the repository name in the README, package metadata and citation file.
## 2.4.1 — 2026-09-23

- Added fail-closed API authentication for non-loopback clients when no bearer token is configured.
- Replaced assertion-only URL normalization checks with explicit defensive validation.
- Completed publication privacy, secret, static-security, dependency and package-content reviews.
- Added public security, contribution, architecture, API and disclosure documentation.

## 2.4.0 — 2026-09-23

- Enforced a fully offline runtime policy while preserving legacy network parameters as explicit no-ops.
- Added deterministic rule manifests with integrity verification and clear authenticity limitations.
- Corrected STIX 2.1 identifiers, timestamps, labels, confidence, and suspicious-only export behavior.
- Added bounded FlateDecode inspection for PDF streams and explicit partial-coverage reporting.
- Resolved relative HTML destinations through declared base URLs and hashed `mailto:`/`tel:` values.
- Added CSP/referrer controls to HTML reports and bounded, thread-safe API rate-limit state.
- Modernized licence metadata, added lint/type/build tooling, regression tests, and production audit evidence.

## 2.3.0 — 2026-09-23

- Added attached-email (`message/rfc822` and `.eml`) extraction and static lure/URL analysis.
- Added base64url, repeated percent-encoding, JavaScript escape, and HTML-entity evasion handling.
- Added alternate IPv4, percent-encoded hostname, encoded redirect, and excessive-encoding URL findings.
- Added duplicate/multiple From-header and Sender/From domain anomaly evidence.
- Added archive path-traversal, symlink, embedded-object, DDE, and MHTML active-content checks.
- Redacted non-URL QR payloads in metadata using masked values and SHA-256 fingerprints.
- Added explicit URL/attachment resource ceilings and propagated partial-analysis states into evidence coverage.
- Expanded the suite from 129 to 146 tests with adversarial and negative-control cases.

## 2.2.0 — 2026-09-22

- Added advanced offline rules for OAuth consent, device-code phishing, MFA fatigue, session-token theft, ClickFix, remote-access tools, cloud-document lures, OTP theft, QR login, and callback phishing.
- Added privacy-preserving phone, cryptocurrency-wallet, IBAN, and UPI extraction using masked values and SHA-256 fingerprints.
- Added HTML-smuggling, credential-form, script-obfuscation, hidden-content, unsafe-scheme, display-name impersonation, Message-ID mismatch, and multi-source corroboration evidence.
- Added nested and cross-domain redirect decoding without opening links.
- Expanded payload checks for double extensions, Bidi filenames, calendar invitations, encrypted archives, nested archives, disk images, add-ins, and installer formats.
- Added MITRE ATT&CK mappings, versioned advanced-rule metadata, adversarial tests, and an advanced sample report.

## 2.1.0 — 2026-09-22

- Expanded deterministic language coverage from 4 to 19 language variants, including Traditional Chinese, Indonesian, Spanish, French, German, Portuguese, Arabic, Hindi, Bengali, Urdu, Thai, Vietnamese, Japanese, Korean, and Filipino/Tagalog.
- Added versioned multilingual rules for 19 scam families, including government impersonation, digital-arrest, bank, tech-support, investment/crypto, romance, recovery, money-mule, family impersonation, toll, tax, utility, subscription, loan, charity, and visa fraud.
- Added non-attributive regional-pattern metadata for Singapore, Malaysia, Indonesia, Hong Kong, Australia, New Zealand, the US, Canada, the UK, India, Japan, South Korea, Brazil, Latin America, MENA, Sub-Saharan Africa, and the Philippines.
- Added explicit limited-language-support evidence, rule IDs, rule-pack versioning, and validation tests.
- Added multilingual negation handling and kept the offline character model as low-weight supporting evidence only.
- Adopted the PolyForm Noncommercial License 1.0.0 notice specified by NexVision Lab.

## 2.0.0 — 2026-09-22

- Added explicit trusted `Authentication-Results` boundary and RFC 9989-aligned identity comparison.
- Changed link handling from first-three selection to all-link static ranking plus top-three deep inspection.
- Added Public Suffix List organizational domains, Unicode/confusable checks, and brand impersonation evidence.
- Replaced cloud reputation APIs with local feeds and optional direct DNS/TLS/RDAP plus caching.
- Added structured HTML destination extraction, attachment analysis, local QR support, multilingual rules, and offline character-model fusion.
- Added thread/account-compromise context and four-dimensional scoring.
- Added JSON, HTML, PDF, DOCX, and STIX reports with hashes, case IDs, coverage, abstention, and analyst-review metadata.
- Added optional local API bearer authentication, per-client rate limiting, and fail-closed network enablement.
- Expanded automated coverage from 15 to 34 tests and added randomized robustness checks.

## 0.1.1

- Fixed IPv6 handling, URL user-info preservation, low-risk consistency, shortener/Punycode thresholds, and unquoted HTML anchor extraction.
