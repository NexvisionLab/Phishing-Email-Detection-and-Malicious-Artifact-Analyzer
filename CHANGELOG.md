# Changelog

## Unreleased

- CI is green again: the `ruff check` step had failed on every run since 2026-09-27 (15 errors, all in the case-review helper
  scripts under `tests/`: `fuzz_probe.py`, `make_cases.py`, `run_cases.py`, `test_case_review.py`). Because `ruff` runs before
  `mypy`, `bandit`, `pip-audit` and the build in `ci.yml`, none of those had run in CI since then; all pass locally on the
  fixed code (`pytest` 263 passed, `ruff`, `mypy`, `bandit`, `pip-audit`, `python -m build`). Changes are lint-only: files opened
  with context managers, unused `noqa` comments and an unused import removed, imports sorted, `datetime.UTC`, and the
  zero-width space and right-to-left override characters in the test emails written as `​` / `‮` escapes (same
  characters, now visible in the source). Regenerating the 20 case emails gives the same content as before apart from the
  random `Message-ID`, MIME boundaries and zip timestamps, which change on every run.

- Credential-phishing coverage for Malay, Indonesian, Arabic and Russian bank-style lures, and a QR-code-in-email lure.
  Found by running 25 phishing emails in many languages plus 8 genuine emails through the checker: a Malay ("Akaun anda
  telah digantung"), Indonesian, Arabic and Russian bank-account-suspension email each scored Low, because the existing
  rules for those languages only matched "verify" next to "account" and none matched "verify your identity" or a
  lock/suspension threat. Also Low before this: an MFA email asking the recipient to scan a QR code to "re-enrol". New
  rules: `lock.ms`/`lock.id`/`lock.ar`/`lock.ru` (account-suspension threats), `cred.ms.identity`/`cred.id.identity`/
  `cred.ar.identity`/`cred.ru` (verify-identity wording), `qr.en.verify`, `lock.en`. Russian is now a supported language
  (`SUPPORTED_LANGUAGES`, script hint, marker words). `crypto.en.seedphrase` (added just above, in the case review
  below) is widened to also catch "private key"/"keystore" wording, which it did not. Two existing English rules
  (`cred.en.verify`, `bec.en.bankchange`) matched "update your account" and "update your payment details" inside an
  ordinary billing notice pointing to the account's own settings page, which scored a real Netflix-style notice
  `likely_phishing` 51; both now exempt a match followed by "settings". `tests/test_multilingual_lures.py` covers the
  five new scam wordings and 7 genuine emails that share their vocabulary (an "always verify your identity" bank alert,
  seed-phrase safety advice, a real MFA reminder, a real QR check-in, an Indonesian bank product email, a Russian
  newsletter). Not added: Hindi, Bengali, Urdu, Thai, Japanese, Korean and Tagalog still have one credential rule each
  with no lock/suspension wording.

- Case review (2026-09-27): twenty realistic emails (fifteen attacks, five tricky legitimate messages; `tests/make_cases.py`,
  `tests/run_cases.py`) plus a malformed-input probe (`tests/fuzz_probe.py`) turned up these bugs, all fixed with regression
  tests in `tests/test_case_review.py`:
  - **Crash:** a message declaring a made-up charset (`charset=nonsense-9`) raised `LookupError`, because the fallback that
    recovers from an undecodable part decoded with the same unknown name. It now falls back to UTF-8.
  - **Non-ASCII text destroyed:** for any message that had headers, `part.get_content()` decoded a part with no charset as
    ASCII, so `café` became a replacement character and Chinese became the literal text `\u4f60\u597d` before any rule saw it.
    An uploaded `.eml` with a UTF-8 body and no charset lost every non-ASCII character too. Text is now kept as pasted, or
    decoded from its bytes with the declared charset, or UTF-8.
  - **Link mismatch never scored:** `DISPLAY_LINK_MISMATCH` (25 points) and the active-HTML findings were reported but never
    reached any score dimension, so a message built on "the text says one site, the link goes to another" could still read
    low. They now count toward the destination score.
  - **Link mismatch compared whole strings:** tracking parameters on a legitimate link raised it, and link text that was just
    a domain (`paypal.com`) did not. It now compares the site the text names with the site the link opens (file names such as
    `invoice.pdf` are not domains). `sites.google.com` shown as `drive.google.com` is a mismatch even though both are
    `google.com`.
  - **Sender domain never checked for brand look-alikes:** `micr0soft-online.com` was flagged only as a link. The From
    domain now gets the same check (`SENDER_DOMAIN_BRAND_IMPERSONATION`).
  - **Missing rules** (rule pack 2026.09.2): payroll or direct-deposit diversion, a request for a wallet recovery phrase
    (and a "wallet suspended" notice), and French tax-refund lures with a bank-details deadline (with or without accents).
  - **Disguised wording:** zero-width characters were already removed but lookalike Cyrillic or Greek letters mixed into a
    Latin word, letters separated by spaces (`s e e d   p h r a s e`) and runs of spaces hid keywords from the rules. Words
    that mix Latin with lookalike letters are folded, spaced letters are joined and repeated spaces collapsed; words
    written entirely in another script (real Russian or Greek text) are left alone.
  - Known and not fixed: a 1.9 MB message takes about 6 seconds and a message with 10,000 header lines about 5 seconds.

- QR codes: new `phishing_analyzer.qr` module. `decode_qr_image` reads every code in an image (OpenCV, with `pyzbar` as an
  optional fallback, since each misses codes the other reads, and an inverted retry for light-on-dark codes) and never
  raises. `classify_payload` says what scanning a code would do (link, Wi-Fi, payment, SMS, call, authenticator setup,
  script, app install...) without returning secrets: a Wi-Fi password, an authenticator secret and most of a wallet address
  are not shown.
- Fixed in the process: an image is now measured from its header before decoding. A 303 KB, 100-megapixel PNG made the
  decoder allocate 1.3 GB (about 13 bytes per pixel, and OpenCV's own cap is a billion pixels), so a small attachment could
  exhaust memory; images over 36 megapixels are now reported as `image_too_large`. A raw `cv2.error` is no longer possible.
  A QR code holding a web address without `http://` (`bit.ly/...`, `example.com/pay`) was ignored; it is now treated as a
  link. File names such as `report.pdf` are not mistaken for web addresses.
- The optional `qr` extra now allows OpenCV 5 and CI installs it, so decoding is tested on every platform; `qr-fallback`
  adds `pyzbar`.

- Brand look-alike detection (`domains.brand_impersonation`) was matching by substring, which flagged real and innocent
  hosts as "suspicious" (`google.co.uk`, `googleapis.com`, `amazonaws.com`, and `mashable.com`, `masterclass.com`,
  `mohawk.com`, `pineapple.com` for containing `mas`, `moh` or `apple`), while missing look-alikes spelled with digits or
  letter pairs (`micros0ft-support.top`, `amaz0n-security.com`, `g00gle-accounts.com`, `rnicrosoft.com`, `googel.com`).
  It now splits each label to the left of the public suffix on hyphens and matches a token that is the brand, the brand
  joined only to lure words (`paypalsecure`, `verify-apple`), or one edit or one swap away from a brand of five or more
  letters, after folding digit and `rn`/`vv` look-alikes. The brands' own domain families (Google, Amazon, Microsoft, Apple,
  PayPal, DHL) are recognised so they are never flagged.
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
