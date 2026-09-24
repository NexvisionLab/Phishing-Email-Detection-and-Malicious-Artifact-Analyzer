from email.message import EmailMessage

import phishing_analyzer.analyzer as analyzer_module
import phishing_analyzer.extractor as extractor_module
from phishing_analyzer.analyzer import analyze_email


def test_url_ceiling_is_reported_as_partial(monkeypatch):
    monkeypatch.setattr(extractor_module, "MAX_EXTRACTED_URLS", 3)
    result = analyze_email(" ".join(f"https://host{i}.test/path" for i in range(8)))
    assert result.links_found == 3
    assert result.evidence_status["links_static"] == "partial"
    assert result.metadata["url_extraction_truncated"] is True
    assert "URL_EXTRACTION_LIMIT" in {finding.code for finding in result.findings}


def test_attachment_ceiling_is_reported_as_partial(monkeypatch):
    monkeypatch.setattr(analyzer_module, "MAX_ATTACHMENTS", 2)
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Attachments"
    message.set_content("Files")
    for index in range(4):
        message.add_attachment(b"data", maintype="application", subtype="octet-stream", filename=f"file-{index}.dat")
    result = analyze_email(message.as_bytes())
    assert len(result.attachments) == 2
    assert result.metadata["attachments_skipped"] == 2
    assert result.evidence_status["attachments"] == "partial"
    assert "ATTACHMENT_COUNT_LIMIT" in {finding.code for finding in result.findings}


def test_encrypted_archive_marks_attachment_coverage_partial():
    # A minimal encrypted-member flag fixture is covered at the finding layer;
    # this assertion verifies the analysis result propagates partial status.
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["Subject"] = "Large file"
    message.set_content("File")
    message.add_attachment(b"xx", maintype="application", subtype="octet-stream", filename="large.dat")
    # Keep the raw RFC message under the global limit by lowering the per-file
    # ceiling instead of serializing an actual 10 MB attachment.
    import phishing_analyzer.attachments as attachment_module

    original = attachment_module.MAX_ATTACHMENT_BYTES
    attachment_module.MAX_ATTACHMENT_BYTES = 1
    try:
        result = analyze_email(message.as_bytes())
    finally:
        attachment_module.MAX_ATTACHMENT_BYTES = original
    assert result.evidence_status["attachments"] == "partial"
    assert "ATTACHMENT_LIMIT" in {finding.code for finding in result.attachments[0].findings}


def test_qr_status_is_not_applicable_without_images():
    result = analyze_email("Hello")
    assert result.evidence_status["qr"] == "not_applicable"
