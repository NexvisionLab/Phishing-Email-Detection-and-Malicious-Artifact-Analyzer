# Detection coverage

## Languages

English, Simplified Chinese, Traditional Chinese, Malay, Indonesian, Tamil, Spanish, French, German, Portuguese, Arabic, Hindi, Bengali, Urdu, Thai, Vietnamese, Japanese, Korean, and Filipino/Tagalog.

Language detection and rule matching are screening aids. Short, code-switched, transliterated and dialect-heavy messages may be marked as limited or undetermined.

## Scam and phishing patterns

- Credential and account-verification phishing
- Business email compromise and payment diversion
- Delivery, invoice, toll, tax, utility and subscription lures
- Job, task, investment, crypto, romance and recovery fraud
- Government, police, bank, friend/family and brand impersonation
- Tech-support, callback, money-mule, prize, charity, loan and immigration fraud
- OAuth consent, device-code, MFA-push and session-token lures
- ClickFix command-execution and remote-access-tool instructions
- Cloud-document, one-time-code and QR-login phishing
- HTML credential forms, smuggling, obfuscation and forced navigation

## Header evidence

- Trusted `Authentication-Results` boundary
- SPF, DKIM and DMARC alignment context
- ARC caveats
- From, Sender, Reply-To and Message-ID mismatches
- Duplicate author headers and thread-route changes
- Display-name brand impersonation and Unicode controls

## URL evidence

- IP and non-public hosts
- Punycode, mixed scripts, controls and confusable brands
- Shorteners, deep subdomains and suspicious terms
- User-information confusion and alternate IPv4 notation
- Redirect parameters, encoding layers and destination mismatch
- HTML anchors, forms, frames, scripts, objects, meta refresh, SVG and CSS URLs

## Attachment evidence

- Hashes, type mismatch, executable/script types and deceptive extensions
- Attached email lures and URLs
- QR URLs with redacted non-URL payloads
- Raw and bounded Flate-compressed PDF active markers and URLs
- HTML/SVG active elements and HTML smuggling
- Calendar invitation lures
- Archive expansion limits, encryption, traversal, symlinks and nested containers
- Office macros, embedded objects, DDE fields and external relationships

## Not covered

The analyzer does not prove authorship or intent, determine sender nationality, follow destinations, evaluate live infrastructure, render webpages, execute attachments, detonate files, perform OCR, decrypt archives, or confirm post-click activity.
