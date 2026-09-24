# Security and privacy

## Offline guarantee

The production code does not perform DNS, TLS, RDAP, WHOIS, URL fetching, browser navigation, cloud threat-intelligence calls, third-party submissions, or telemetry. Legacy network-related parameters are retained only for compatibility and return `network_disabled_by_policy`.

Optional local files may be used for approved indicator feeds. The analyzer does not download or update those feeds.

## Sensitive data handling

- Email bodies and attachments remain in the calling process.
- Phone numbers, payment identifiers, wallet addresses, `mailto:` values and `tel:` values are masked or represented by short SHA-256 fingerprints in relevant metadata.
- Reports include message and attachment hashes for case correlation.
- Reports may still contain sender addresses, subjects, observed URLs and message evidence supplied by the operator. Treat report files as sensitive case material.
- No application telemetry or remote logging is implemented.

## Hostile-input defenses

- Input, URL, attachment, archive, decoded-token and PDF-decompression ceilings.
- No archive extraction to disk.
- No subprocess execution of email content.
- No script, macro, document or attachment execution.
- No URL resolution through the operating system or browser.
- HTML is parsed without rendering or remote loads.

## API deployment

The optional FastAPI service rejects unauthenticated non-loopback clients, offers bearer authentication, and uses a bounded, thread-safe in-process rate limiter. These controls are not a complete internet-facing security boundary.

For any external deployment, add a reviewed gateway with TLS, centralized identity, authorization, distributed rate limiting, request-size enforcement, network egress denial, security logging, retention policy and penetration testing.

## Known limitations

- Static rules can miss new, image-only, heavily obfuscated or context-specific lures.
- Authentication success does not prove that a message is safe.
- Local feeds can be incomplete or stale.
- QR decoding is optional and depends on local packages.
- No OCR, detonation, password-assisted archive inspection or endpoint/identity telemetry correlation is performed.
- Scores are triage indices, not calibrated probabilities.
