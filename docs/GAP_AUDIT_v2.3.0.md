# Advanced detection gap audit — v2.3.0

## Outcome

The v2.2 engine already covered the main phishing routes, multilingual scam intent, top-three link enrichment, identity lures, HTML smuggling, callback fraud, QR links, attachment risk, and evidence-led reporting. The audit found several evasion and operational-resilience gaps. Version 2.3 closes the high-value gaps that can be addressed safely with offline static analysis.

## Research basis

- MITRE ATT&CK T1566 separates phishing into attachment, link, service, and voice techniques and recommends correlation with identity, endpoint, file, process, and network telemetry. <https://attack.mitre.org/techniques/T1566/>
- Microsoft identifies device-code flow as a high-risk authentication method that can be used in phishing attacks. <https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows>
- Microsoft documents consent phishing and investigation of risky OAuth applications, supporting continued OAuth-permission and identity-flow detection. <https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/protect-against-consent-phishing>
- Microsoft attack-simulation guidance treats QR codes as a phishing payload, supporting QR extraction and link analysis. <https://learn.microsoft.com/en-us/defender-office-365/attack-simulation-training-simulations>
- RFC 9989 defines current DMARC behavior and alignment. RFC 8617 cautions that ARC authenticates handling identities but does not establish their trustworthiness or message safety. <https://datatracker.ietf.org/doc/rfc9989/> and <https://datatracker.ietf.org/doc/rfc8617/>

## Gaps closed

| Gap | Risk | v2.3 control |
|---|---|---|
| Attached email blind spot | A malicious forwarded `.eml` could hide a lure and destination | Serializes and parses attached RFC 5322 messages; extracts URLs and adds lure evidence |
| Encoding evasion | Base64url, repeated percent encoding, entities, and JavaScript escapes could hide URLs or unsafe schemes | Bounded multi-layer decoding with strict size and token limits |
| Alternate IP notation | Integer, hexadecimal, octal, or shortened IPv4 could evade ordinary IP checks | Converts supported alternate notation to canonical IPv4 and applies public/private-address checks |
| Encoded redirects | A redirect target could be base64url-encoded | Decodes common redirect parameters and compares organizational domains |
| Header ambiguity | Duplicate authors or unrelated Sender domains can confuse identity assessment | Adds duplicate/multiple From and Sender/From findings; Sender mismatch remains low weight |
| Container abuse | Archive traversal, symlinks, embedded objects, or DDE fields were not explicit | Adds dedicated static findings without extracting or executing members |
| MHTML activity | Active MHTML could be missed when magic bytes were inconclusive | Uses extension and content type in addition to signature checks |
| QR privacy | Non-URL QR text could be copied into metadata | Stores masked values and short SHA-256 fingerprints instead |
| Work amplification | Extremely large URL or attachment counts could cause excessive analysis | Caps work at 2,000 unique destinations and 100 attachments, with explicit partial coverage |
| Coverage accuracy | Oversized or encrypted payloads could still appear fully evaluated | Propagates partial/not-evaluated findings into the overall evidence status |

## Remaining gaps and recommended roadmap

1. Add optional local OCR and image-layout analysis for screenshot-only credential lures and QR codes embedded in PDF pages.
2. Add password-assisted archive inspection only through an isolated analyst workflow; never guess or execute content in the analyzer process.
3. Add local organization profiles for known vendors, executives, correspondent history, approved SaaS tenants, and payment-change baselines.
4. Correlate results with mail gateway, identity-provider, endpoint, DNS, proxy, and cloud-audit telemetry to confirm clicks, token issuance, consent grants, and execution.
5. Create per-language and per-scam-family labeled evaluation sets with precision, recall, calibration, and drift measurements.
6. Move rules into signed data packs with provenance, expiry, rollback, and review ownership.
7. Add isolated detonation as a separate service only when an approved sandbox and legal/operational controls exist.

## Safety position

Version 2.3 remains an offline-first triage tool. It does not follow destinations, execute commands, open active content, detonate files, assert sender nationality, or treat authentication success as proof of safety. The score remains a triage index, not a probability.
