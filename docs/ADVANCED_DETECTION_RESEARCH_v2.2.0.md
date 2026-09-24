# Advanced detection research — v2.2.0

## Conclusion

The strongest improvement is not a larger keyword list. It is corroboration across sender identity, social-engineering intent, HTML behavior, destinations, callbacks, payment identifiers, and payload structure. Version 2.2 implements that approach offline, preserves evidence, and avoids treating any single supporting artifact as proof.

## Research basis

- MITRE ATT&CK T1566 defines phishing through attachment, link, service, and voice routes. Related ATT&CK techniques cover MFA request generation, one-time-code interception, command execution, remote services, and token abuse. Source: <https://attack.mitre.org/techniques/T1566/>
- The FBI IC3 2024 report records 193,407 phishing/spoofing complaints and separately tracks business email compromise, government impersonation, investment, romance, tech-support, and related fraud. Source: <https://www.ic3.gov/AnnualReport/Reports/2024_IC3Report.pdf>
- The U.S. FTC consumer taxonomy emphasizes impersonation, prizes, jobs, investment, romance, business, and payment scams, supporting family-level classification instead of a phishing-only binary. Source: <https://consumer.ftc.gov/scams>
- Australian Scamwatch describes impersonation, investment, product/service, romance, threat/extortion, job/employment, and unexpected-money scams. Source: <https://www.scamwatch.gov.au/types-of-scams>
- Hong Kong's official information-security guidance includes QR-code phishing as a delivery technique. Source: <https://www.infosec.gov.hk/en/knowledge-centre/phishing>
- FATF describes cyber-enabled fraud as transnational and highlights phishing, AI-enabled deception, messaging platforms, payments, rapid information sharing, and cross-border cooperation. Source: <https://www.fatf-gafi.org/en/publications/Methodsandtrends/cyber-enabled-fraud-digitalisation-ml-tf-pf-risks.html>

## Implemented controls

| Area | v2.2 control | Safety boundary |
|---|---|---|
| Identity abuse | OAuth-consent, device-code, MFA-fatigue, SSO/session, and OTP-disclosure rules | Message artifacts only; no claim that an account was compromised |
| User execution | ClickFix/command-paste and remote-access-tool lures | Commands are never executed |
| Callback and payment | Requires contextual wording plus a phone/payment destination | Values are masked and fingerprinted in reports |
| HTML | Credential forms, HTML smuggling, obfuscation, hidden content, and unsafe URI schemes | HTML is parsed, not rendered remotely |
| Sender identity | Brand display-name/domain alignment, Unicode controls, Message-ID mismatch | Message-ID mismatch is low-weight supporting evidence |
| Redirects | Decodes common nested redirect parameters and detects organizational-domain changes | No URL is opened or followed |
| Attachments | Double extensions, Bidi names, encrypted/nested archives, disk images, installer/add-in formats, and calendar lures | Strict static limits; no detonation |
| Correlation | Adds corroboration only when strong findings span three advanced sources | A triage signal, not a probability |
| Explainability | Stable rule IDs, rule-pack version, ATT&CK mappings, evidence codes, and coverage states | Analyst review remains required |

## False-positive controls

- Callback phishing requires all three elements: a phone number, invoice/refund/subscription/security context, and an instruction to call.
- Brand impersonation is suppressed when the sender's registrable domain is in the brand's official-domain set.
- Message-ID mismatch contributes only five points because legitimate mail platforms often use a different domain.
- Same-organizational-domain redirects receive a smaller finding than cross-domain redirects.
- Payment destinations are elevated only when payment context is present.
- Sensitive indicators are not repeated verbatim in result metadata or human-readable reports.

## Recommended next improvements

1. Move rule content into signed, schema-validated data packs with provenance, review dates, expiry, rollback, and reproducible signatures.
2. Add optional local ONNX classifiers for multilingual semantic intent and image OCR, with deterministic rules retained as explanations and guardrails.
3. Add deployment-supplied brand/domain inventories, executive/vendor relationship data, and historical correspondent baselines for organization-specific BEC detection.
4. Correlate analyzer output with identity-provider, endpoint, proxy, DNS, and mail telemetry to confirm post-click execution, token theft, or suspicious sign-in activity.
5. Add sandbox integration only as a separately isolated, opt-in service; never execute attachments in the analyzer process.
6. Add analyst feedback capture, drift dashboards, per-language precision/recall sets, and threshold calibration against locally labeled mail.
7. Add OCR and visual brand/logo comparison for image-only QR and credential lures while keeping image processing local.
8. Distribute curated local reputation feeds with signatures, expiry, source confidence, and collision-resistant indicator normalization.

## Governance

The score is a triage index. It is not a probability, safety certificate, sender attribution, or automated enforcement decision. Regional wording indicates only a matched pattern. Consequential actions require independent verification and human review.
