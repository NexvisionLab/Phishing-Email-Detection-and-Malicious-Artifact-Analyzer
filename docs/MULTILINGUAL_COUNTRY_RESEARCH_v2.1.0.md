# Multilingual and country-pattern research — v2.1.0

Date: 2026-09-22

## Research outcome

Cyber-enabled fraud is transnational, changes quickly, and crosses email, text, messaging, social platforms, websites, and payments. FATF describes it as one of the most widespread profit-motivated crimes and emphasizes phishing, AI-enabled deception, messaging applications, payment transparency, rapid information sharing, and cross-border cooperation. That supports a modular, versioned rule-pack design rather than one fixed English phishing list.

Official consumer-protection taxonomies also overlap but are not identical. The US FTC includes phishing, business and government impersonation, charity, debt, family emergency, gift card, job, prize, romance, tech support, wire transfer, immigration, and education scams. Australia's Scamwatch separately describes relationship, investment, identity takeover, buying/selling, threat, job, unexpected-money, BEC, recovery, and donation scams. Singapore's ScamShield highlights investment, job, impersonation, e-commerce, fake-friend, phishing, tech-support, malware, and money-mule scams.

Sources consulted:

- FATF, [Cyber-Enabled Fraud — Digitalisation and ML/TF/PF Risks](https://www.fatf-gafi.org/en/publications/Methodsandtrends/cyber-enabled-fraud-digitalisation-ml-tf-pf-risks.html)
- OECD, [Protecting Consumers from Financial Scams and Frauds](https://www.oecd.org/en/publications/protecting-consumers-from-financial-scams-and-frauds_d41817bb-en.html)
- US FTC, [Scams taxonomy and consumer guidance](https://consumer.ftc.gov/scams)
- Australian Competition and Consumer Commission, [Scamwatch types of scams](https://www.scamwatch.gov.au/types-of-scams)
- Singapore Government, [ScamShield scam-type resources](https://www.scamshield.gov.sg/resources/videos/)
- Hong Kong Government, [Phishing guidance](https://www.infosec.gov.hk/en/knowledge-centre/phishing)
- UK Government, [Online Fraud Charter](https://www.gov.uk/government/publications/online-fraud-charter-2023)
- INTERPOL, [Financial crime](https://www.interpol.int/en/Crimes/Financial-crime)

## Implemented design

### Language coverage

The deterministic rule pack now covers 19 language variants: English, Simplified Chinese, Traditional Chinese, Malay, Indonesian, Tamil, Spanish, French, German, Portuguese, Arabic, Hindi, Bengali, Urdu, Thai, Vietnamese, Japanese, Korean, and Filipino/Tagalog.

Language detection combines conservative lexical markers with script hints. Closely related languages are not separated from script alone. Chinese output preserves the v2.0 `zh` compatibility code while adding `zh-Hans` or `zh-Hant`.

### Scam coverage

Twenty families are represented: credential phishing; BEC/payment diversion; delivery/invoice; job/task; prize/advance-fee; extortion; investment/crypto; romance; recovery; government/law-enforcement impersonation; bank/payment-service impersonation; tech-support/malware; money-mule recruitment; friend/family impersonation; toll/traffic-payment; tax/refund; utility/telecom; subscription/renewal; charity/disaster; loan/debt; and immigration/visa. Some closely related labels share one family in reporting.

### Regional patterns

Region profiles cover Singapore, Malaysia, Indonesia, Hong Kong, Australia, New Zealand, the United States, Canada, the United Kingdom, India, Japan, South Korea, Brazil, Latin America, the Middle East/North Africa, Sub-Saharan Africa, and the Philippines.

These are content-pattern hints based on wording or named entities. They are not geolocation and must not be used to infer the sender's identity, nationality, residence, or infrastructure origin. The JSON governance field `regional_match_is_origin_attribution` is always `false`.

### False-positive and governance controls

- Multilingual negation windows suppress common warning/education phrasing.
- A rule must match before its scam family contributes deterministic content points.
- The local character n-gram model contributes at most 10 low-severity points and cannot independently create a high verdict.
- Unsupported or ambiguous language produces `language_support: limited` and may result in `Pattern undetermined`.
- Every match includes a stable rule ID and rule-pack version for reproducibility.
- Rule-pack validation rejects duplicate IDs, unsupported language codes, invalid score weights, broken regular expressions, and inadequate category breadth.

## Recommended next improvements

1. **Curated native-speaker corpus:** commission reviewed malicious and benign examples for every supported language, dialect, transliteration style, and code-switch pair. Track precision/recall separately by language and scam family.
2. **Signed rule-pack updates:** distribute rule packs as signed, versioned data files with provenance, expiry/review dates, and rollback support. Keep analyzer execution offline.
3. **Organization profiles:** allow administrators to supply local trusted brands, domains, payment vocabulary, business roles, and known invoice templates without modifying source.
4. **Campaign clustering:** privacy-preserving local clustering over normalized subjects, sender infrastructure, URLs, attachment hashes, and rule IDs to connect related messages.
5. **Entity and payment-instruction extraction:** extract account numbers, wallet addresses, gift-card requests, phone numbers, payment apps, and requested amounts as evidence, with masking in reports.
6. **Attachment depth:** add sandbox-independent parsers for more document formats, password-protected archive workflow, YARA-compatible local rules, and optional local OCR for image-only lures.
7. **Homograph expansion:** use UTS #39 confusable data and brand dictionaries supplied by the deployment, with clear version/provenance fields.
8. **Evaluation gates:** require per-language false-positive ceilings and regression results before accepting a rule-pack release. Include adversarial spacing, Unicode normalization, transliteration, and negation tests.
9. **Analyst feedback loop:** store explicit analyst dispositions locally and generate suggested rule changes for review; never auto-promote feedback into production rules.
10. **Privacy-preserving federation:** exchange only approved hashes, domains, and rule/campaign identifiers between deployments; never upload full message content by default.

## Known limitations

Rules can miss novel wording, slang, dialects, transliteration, mixed languages, obfuscated text, and image-only content. Official-looking entity names can appear in both scams and legitimate messages. A region hint is not attribution. The score is a triage index, not a probability, and consequential decisions require human review.
