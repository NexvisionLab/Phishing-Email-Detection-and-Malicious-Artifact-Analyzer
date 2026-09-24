# Contributing

Contributions that improve defensive analysis, correctness, tests, documentation, accessibility, and privacy are welcome under the repository licence.

## Development setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install '.[api,dev]'
```

## Required checks

```bash
pytest -q
ruff check phishing_analyzer tests
mypy phishing_analyzer
python -m build
```

## Change requirements

- Preserve the fully offline runtime boundary.
- Preserve public interfaces unless a breaking change is explicitly reviewed and versioned.
- Add tests for meaningful behavior and demonstrated defects.
- Keep work bounded against hostile input sizes and decompression amplification.
- Do not add cloud submissions, URL fetching, telemetry, embedded credentials, or unsafe execution paths.
- Do not submit real victim emails, personal information, credentials, live malicious samples, or third-party proprietary material.
- Keep scores described as triage indices, not probabilities.
- Keep regional wording as a content signal, not an attribution of origin or nationality.
- Update the changelog and relevant documentation.

## Pull requests

Explain the problem, the security/privacy effect, compatibility impact, tests performed, and any unresolved limitation. A clean style alone is not evidence about authorship; review focuses on behavior, provenance, and validation.
