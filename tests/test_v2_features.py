import base64
import io
import json
import zipfile
from email.message import EmailMessage

from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.domains import registrable_domain
from phishing_analyzer.report import docx_report, html_report, pdf_report, stix_report


def test_untrusted_authentication_results_are_not_scored():
    raw = "From: x@bank.example\nAuthentication-Results: forged.example; dmarc=pass; spf=pass\n\nHello"
    result = analyze_email(raw)
    assert "AUTH_RESULTS_UNTRUSTED" in {f.code for f in result.findings}
    assert result.evidence_status["authentication"] == "not_evaluated"


def test_rfc9989_alignment_detects_unaligned_pass():
    raw = (
        "From: x@bank.example\nAuthentication-Results: mx.example; spf=pass smtp.mailfrom=evil.test; dkim=pass header.d=evil.test\n\nHello"
    )
    result = analyze_email(raw, trusted_authserv_ids={"mx.example"})
    assert "DMARC_ALIGNMENT_FAILURE" in {f.code for f in result.findings}


def test_relaxed_alignment_uses_public_suffix():
    raw = "From: x@alerts.example.co.uk\nAuthentication-Results: mx.example; dkim=pass header.d=mail.example.co.uk\n\nHello"
    result = analyze_email(raw, trusted_authserv_ids={"mx.example"})
    assert not any(f.code == "DMARC_ALIGNMENT_FAILURE" for f in result.findings)


def test_riskiest_three_selected_not_first_three():
    raw = "https://example.com/a https://iana.org/b https://python.org/c https://trusted.example@evil.test/login"
    result = analyze_email(raw)
    chosen = [link for link in result.links if link.selected_for_deep_inspection]
    assert len(chosen) == 3
    assert any(link.host == "evil.test" for link in chosen)


def test_public_suffix_registrable_domain():
    assert registrable_domain("login.mail.example.co.uk") == "example.co.uk"


def test_unicode_mixed_script_and_brand_impersonation():
    result = analyze_email("https://аррle.example/login")
    codes = {f.code for link in result.links for f in link.findings}
    assert "PUNYCODE" in codes
    assert "BRAND_IMPERSONATION" in codes


def test_optional_osint_is_fail_closed_offline():
    result = analyze_email("https://example.com")
    assert result.links[0].osint["status"] == "not_evaluated"
    assert result.evidence_status["network_osint"] == "not_evaluated"


def test_default_analysis_makes_no_network_calls(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("network call attempted")

    monkeypatch.setattr("socket.getaddrinfo", blocked)
    monkeypatch.setattr("socket.create_connection", blocked)
    monkeypatch.setattr("http.client.HTTPSConnection", blocked)
    result = analyze_email("Urgent: verify at https://evil.test/login", network_enabled=True)
    assert result.links_checked == 1
    assert result.evidence_status["network_osint"] == "disabled_by_policy"
    assert result.links[0].osint["reason"] == "network_disabled_by_policy"


def test_local_feed_match_without_network(tmp_path):
    feed = tmp_path / "feed.txt"
    feed.write_text("evil.test\n", encoding="utf-8")
    result = analyze_email("https://evil.test/path", feed_paths=[str(feed)])
    assert result.links[0].reputation["status"] == "matched"
    assert any(f.code == "LOCAL_FEED_HIT" for f in result.links[0].findings)


def test_html_form_meta_svg_and_css_extraction():
    raw = """From: x@example.com
Content-Type: text/html

<meta http-equiv="refresh" content="0;url=https://meta.test/go">
<form action="https://form.test/login"><button formaction="https://button.test/pay">Go</button></form>
<svg><image href="https://svg.test/a.png" /></svg><style>x{background:url(https://css.test/a)}</style>
"""
    result = analyze_email(raw)
    hosts = {link.host for link in result.links}
    assert {"meta.test", "form.test", "button.test", "svg.test", "css.test"} <= hosts
    assert any(f.code == "ACTIVE_HTML_DESTINATION" for f in result.findings)


def test_percent_encoded_and_base64_url_extraction():
    encoded = base64.b64encode(b"https://encoded.test/login").decode()
    result = analyze_email(f"Go https%3A%2F%2Fpercent.test%2Flogin or {encoded}")
    assert {link.host for link in result.links} == {"percent.test", "encoded.test"}


def _message_with_attachment(filename: str, content_type: str, payload: bytes) -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["Subject"] = "Attachment"
    message.set_content("See attachment")
    maintype, subtype = content_type.split("/", 1)
    message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return message.as_bytes()


def test_pdf_active_content_static_analysis():
    raw = _message_with_attachment("invoice.pdf", "application/pdf", b"%PDF-1.4\n/JavaScript /OpenAction https://evil.test")
    result = analyze_email(raw)
    assert result.attachments[0].sha256
    assert any(f.code == "ACTIVE_PDF" for f in result.attachments[0].findings)


def test_ooxml_macro_and_external_relationship_analysis():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("word/vbaProject.bin", b"macro")
        archive.writestr("word/_rels/document.xml.rels", '<Relationship TargetMode="External" Target="https://evil.test/payload"/>')
    raw = _message_with_attachment("invoice.docm", "application/vnd.ms-word", buffer.getvalue())
    result = analyze_email(raw)
    codes = {f.code for f in result.attachments[0].findings}
    assert {"ACTIVE_ARCHIVE_CONTENT", "OOXML_EXTERNAL_REL"} <= codes
    assert "evil.test" in {link.host for link in result.links}


def test_multilingual_chinese_classification():
    result = analyze_email("紧急：请点击链接验证账户 https://evil.test/login")
    assert result.classification == "Credential phishing"
    assert "zh" in result.metadata["languages"]


def test_job_task_scam_classification():
    result = analyze_email("Remote job: complete simple tasks and earn commission. Top up a deposit to withdraw.")
    assert result.classification == "Job or task scam"


def test_negated_benign_statement_does_not_trigger():
    result = analyze_email("You do not need to verify your account. Never click a login link.")
    assert result.classification == "Pattern undetermined"


def test_thread_route_change_signal():
    raw = "From: boss@company.example\nReply-To: pay@other.test\nIn-Reply-To: <old@company.example>\nSubject: Re: invoice\n\nPlease proceed"
    result = analyze_email(raw)
    assert "THREAD_REPLY_ROUTE_CHANGED" in {f.code for f in result.findings}


def test_four_scoring_dimensions_are_reported():
    result = analyze_email("Urgent: verify your account at https://evil.test/login")
    assert result.dimensions.message_intent > 0
    assert result.dimensions.destination_risk > 0
    assert result.metadata["governance"]["score_is_probability"] is False


def test_reports_include_case_hash_and_are_valid_containers():
    result = analyze_email("Hello https://example.com")
    assert result.metadata["case_id"] in html_report(result)
    assert pdf_report(result).startswith(b"%PDF-1.4")
    with zipfile.ZipFile(io.BytesIO(docx_report(result))) as archive:
        assert "word/document.xml" in archive.namelist()
    assert json.loads(stix_report(result))["type"] == "bundle"
