import base64
import io
import stat
import zipfile
from email.message import EmailMessage

from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.attachments import analyze_attachment
from phishing_analyzer.extractor import RawAttachment
from phishing_analyzer.urls import analyze_url


def test_attached_eml_is_extracted_and_triaged():
    nested = EmailMessage()
    nested["From"] = "Security <alert@unrelated.test>"
    nested["Subject"] = "Urgent account verification"
    nested.set_content("Sign in to verify at https://credential.test/login")
    outer = EmailMessage()
    outer["From"] = "forwarder@example.test"
    outer["Subject"] = "Fwd"
    outer.set_content("See attached message")
    outer.add_attachment(nested, filename="forwarded.eml")
    result = analyze_email(outer.as_bytes())
    assert "EMBEDDED_EMAIL_LURE" in {finding.code for finding in result.attachments[0].findings}
    assert "credential.test" in {link.host for link in result.links}


def test_base64url_and_deep_percent_encoded_urls_are_extracted():
    token = base64.urlsafe_b64encode(b"https://encoded.test/login?a=1").decode().rstrip("=")
    result = analyze_email(f"Open {token} or https%253A%252F%252Fdouble.test%252Fverify")
    assert {"encoded.test", "double.test"} <= {link.host for link in result.links}


def test_obfuscated_integer_ipv4_is_high_risk():
    result = analyze_url("http://2130706433/login")
    codes = {finding.code for finding in result.findings}
    assert {"OBFUSCATED_IP", "IP_HOST", "NON_PUBLIC_IP"} <= codes
    assert result.score >= 75


def test_percent_encoded_hostname_is_surfaced():
    result = analyze_url("https://%65vil.test/login")
    assert result.host == "evil.test"
    assert "PERCENT_ENCODED_HOST" in {finding.code for finding in result.findings}


def test_base64url_redirect_destination_is_decoded():
    nested = base64.urlsafe_b64encode(b"https://redirected.test/signin").decode().rstrip("=")
    result = analyze_url(f"https://outer.test/go?target={nested}")
    codes = {finding.code for finding in result.findings}
    assert {"ENCODED_REDIRECT", "NESTED_REDIRECT", "CROSS_DOMAIN_REDIRECT"} <= codes


def test_html_entity_unsafe_scheme_and_forced_navigation():
    raw = """From: notice@example.test
Subject: Document
Content-Type: text/html

<a href="java&#x73;cript:alert(1)">Open</a><script>window.location.replace('https://evil.test')</script>
"""
    result = analyze_email(raw)
    codes = {finding.code for finding in result.findings}
    assert {"UNSAFE_URI_SCHEME", "HTML_FORCED_NAVIGATION"} <= codes


def test_multiple_from_headers_and_addresses_are_reported():
    raw = "From: Alice <alice@example.test>\nFrom: Accounts <pay@other.test>\nSubject: Hello\n\nBody"
    result = analyze_email(raw)
    codes = {finding.code for finding in result.findings}
    assert {"DUPLICATE_SECURITY_HEADER", "MULTIPLE_FROM_ADDRESSES"} <= codes


def test_sender_from_mismatch_is_supporting_evidence():
    raw = "From: Alice <alice@example.test>\nSender: relay@other.test\nSubject: Hello\n\nBody"
    result = analyze_email(raw)
    finding = next(item for item in result.findings if item.code == "SENDER_FROM_MISMATCH")
    assert finding.points == 6 and finding.severity == "low"


def _zip_attachment(entries):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, value in entries:
            if isinstance(value, zipfile.ZipInfo):
                archive.writestr(value, b"target")
            else:
                archive.writestr(name, value)
    return analyze_attachment(
        RawAttachment("document.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", buffer.getvalue())
    )


def test_archive_path_traversal_and_embedded_object():
    result = _zip_attachment([("../escape.exe", b"MZ"), ("word/embeddings/oleObject1.bin", b"object")])
    codes = {finding.code for finding in result.findings}
    assert {"ARCHIVE_PATH_TRAVERSAL", "ACTIVE_ARCHIVE_CONTENT", "EMBEDDED_OFFICE_OBJECT"} <= codes


def test_archive_symlink_is_reported():
    info = zipfile.ZipInfo("link")
    info.create_system = 3
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    result = _zip_attachment([("link", info)])
    assert "ARCHIVE_SYMLINK" in {finding.code for finding in result.findings}


def test_office_dde_field_is_reported():
    xml = b"<w:instrText>DDEAUTO c:\\windows\\system32\\cmd.exe</w:instrText>"
    result = _zip_attachment([("word/document.xml", xml)])
    assert "OFFICE_DDE_FIELD" in {finding.code for finding in result.findings}


def test_mhtml_extension_receives_active_html_analysis():
    payload = b'<html><form action="https://evil.test"><input type="password"></form></html>'
    result = analyze_attachment(RawAttachment("notice.mhtml", "application/octet-stream", payload))
    assert "ACTIVE_HTML_ATTACHMENT" in {finding.code for finding in result.findings}


def test_benign_archive_and_sender_header_do_not_escalate():
    result = _zip_attachment([("word/document.xml", b"<document>Hello</document>")])
    assert not {"ARCHIVE_PATH_TRAVERSAL", "ARCHIVE_SYMLINK", "OFFICE_DDE_FIELD"} & {finding.code for finding in result.findings}
    mail = analyze_email("From: Alice <alice@example.test>\nSender: relay@mail.example.test\nSubject: Hello\n\nBody")
    assert "SENDER_FROM_MISMATCH" not in {finding.code for finding in mail.findings}
