# API reference

## Python

```python
analyze_email(
    raw: str | bytes,
    network_enabled: bool = False,
    trusted_authserv_ids: set[str] | None = None,
    feed_paths: list[str] | None = None,
    cache_dir: str | None = None,
) -> AnalysisResult
```

`network_enabled` and `cache_dir` are compatibility parameters. They never enable networking or cache access.

`AnalysisResult.to_dict()` returns a JSON-serializable structure containing version, classification, triage score, risk, confidence, findings, links, attachments, score dimensions, evidence states, limitations and metadata.

## HTTP

### `GET /health`

Returns service status, version and offline mode.

### `POST /v1/analyze`

Request:

```json
{
  "content": "Raw email or pasted message text",
  "network_enabled": false
}
```

Constraints:

- `content` is required and limited to 2,000,000 characters by the HTTP schema.
- Configure `PHISHCHECK_API_TOKEN` to require `Authorization: Bearer <token>`.
- Requests from non-loopback clients are rejected unless `PHISHCHECK_API_TOKEN` is configured and supplied.
- Requests are limited to 60 analyses per client per minute in a single process.
- `network_enabled: true` records a denied request and never performs networking.

Responses:

- `200`: analysis result.
- `400`: invalid or empty content.
- `401`: missing or incorrect configured bearer token.
- `429`: per-process rate limit exceeded.

## Environment variables

| Variable | Purpose |
|---|---|
| `PHISHCHECK_API_TOKEN` | Optional local API bearer secret |
| `PHISHCHECK_TRUSTED_AUTHSERV_IDS` | Comma-separated trusted authentication service identifiers |
| `PHISHCHECK_FEEDS` | Platform-separated approved local feed paths |

Do not commit environment files or production secrets.
