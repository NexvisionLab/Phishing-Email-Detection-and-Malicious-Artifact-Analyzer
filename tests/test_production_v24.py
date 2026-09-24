import json
import zlib
from email.message import EmailMessage

from fastapi.testclient import TestClient

from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.api import _MAX_RATE_CLIENTS, _RATE_LIMIT, _admit_client, _requests, app
from phishing_analyzer.report import html_report, stix_report
from phishing_analyzer.rulepack import build_rule_manifest, validate_rule_manifest


def _message_with_attachment(filename: str, content_type: str, payload: bytes) -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["Subject"] = "Attachment"
    message.set_content("See attachment")
    maintype, subtype = content_type.split("/", 1)
    message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return message.as_bytes()


def test_relative_html_urls_use_declared_base_and_contact_values_are_redacted():
    raw = """From: x@example.com
Content-Type: text/html

<base href="https://portal.example/account/">
<a href="verify">Verify</a>
<a href="mailto:private.person@example.com">Mail</a>
<a href="tel:+12025550198">Call</a>
"""
    result = analyze_email(raw)
    assert "https://portal.example/account/verify" in {link.normalized_url for link in result.links}
    contacts = [item["value"] for item in result.metadata.get("html_indicators", [])]
    serialized = json.dumps(result.to_dict())
    assert "private.person@example.com" not in serialized
    assert "+12025550198" not in serialized
    assert not contacts or all(value.startswith("redacted:sha256:") for value in contacts)


def test_compressed_pdf_active_content_and_url_are_inspected():
    compressed = zlib.compress(b"/JavaScript /OpenAction https://compressed.evil/login")
    pdf = b"%PDF-1.4\n1 0 obj<</Filter /FlateDecode>>stream\n" + compressed + b"\nendstream\nendobj"
    result = analyze_email(_message_with_attachment("invoice.pdf", "application/pdf", pdf))
    assert "ACTIVE_PDF" in {finding.code for finding in result.attachments[0].findings}
    assert "compressed.evil" in {link.host for link in result.links}


def test_rule_manifest_is_reproducible_and_tamper_evident():
    manifest = build_rule_manifest()
    assert validate_rule_manifest(manifest) == []
    manifest["counts"]["locale_rules"] += 1
    errors = validate_rule_manifest(manifest)
    assert "manifest digest does not match its content" in errors
    assert "manifest does not match the installed built-in rules" in errors


def test_stix_exports_only_suspicious_urls_with_valid_uuid_ids():
    result = analyze_email("Use https://example.com/about or verify at https://evil.test/login")
    bundle = json.loads(stix_report(result))
    assert bundle["id"].startswith("bundle--")
    assert len(bundle["objects"]) == 1
    indicator = bundle["objects"][0]
    assert indicator["labels"] == ["suspicious-activity"]
    assert indicator["valid_from"] == result.metadata["analyzed_at"]
    assert indicator["confidence"] > 0


def test_html_report_sets_offline_safe_document_policies():
    report = html_report(analyze_email("https://evil.test/login"))
    assert 'content="no-referrer"' in report
    assert "default-src 'none'" in report


def test_rate_limiter_is_bounded_and_rejects_excess_requests():
    _requests.clear()
    now = 1000.0
    assert all(_admit_client("same", now + index / 1000) for index in range(_RATE_LIMIT))
    assert not _admit_client("same", now + 1)
    for index in range(_MAX_RATE_CLIENTS + 10):
        _admit_client(f"client-{index}", now + 120 + index / 1000)
    assert len(_requests) <= _MAX_RATE_CLIENTS


def test_api_authentication_and_offline_policy(monkeypatch):
    _requests.clear()
    monkeypatch.setenv("PHISHCHECK_API_TOKEN", "secret-token")
    client = TestClient(app)
    assert client.post("/v1/analyze", json={"content": "hello"}).status_code == 401
    response = client.post(
        "/v1/analyze",
        json={"content": "https://evil.test/login", "network_enabled": True},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert response.status_code == 200
    assert response.json()["evidence_status"]["network_osint"] == "disabled_by_policy"


def test_api_requires_token_for_non_loopback_client(monkeypatch):
    _requests.clear()
    monkeypatch.delenv("PHISHCHECK_API_TOKEN", raising=False)
    external = TestClient(app, client=("203.0.113.10", 50000))
    assert external.post("/v1/analyze", json={"content": "hello"}).status_code == 401


def test_api_allows_unauthenticated_loopback_for_compatibility(monkeypatch):
    _requests.clear()
    monkeypatch.delenv("PHISHCHECK_API_TOKEN", raising=False)
    local = TestClient(app, client=("127.0.0.1", 50000))
    assert local.post("/v1/analyze", json={"content": "hello"}).status_code == 200
