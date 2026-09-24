# Security policy

## Supported version

Security fixes are applied to the latest published release. Version 2.4.x is the supported line at initial publication.

## Reporting a vulnerability

Use the repository's private **Security** → **Report a vulnerability** workflow. Do not disclose exploitable details, personal data, production emails, credentials, or active malicious payloads in a public issue.

Include:

- affected version and component;
- reproduction steps using synthetic data;
- expected and observed behavior;
- security impact and realistic attack preconditions;
- proposed mitigation, if known.

NexVision Lab will assess the report, coordinate remediation, and publish an advisory when appropriate. Submission does not guarantee a bounty or commercial relationship.

## Security boundaries

- The analyzer is designed to operate fully offline.
- URLs are parsed as data and are not visited.
- Attachments are inspected statically and are not executed.
- The built-in API is intended for controlled localhost use.
- Analysis results are decision support and require analyst review.
