import io
import json
import zipfile
from email.message import EmailMessage

import pytest

from phishing_analyzer.advanced import ADVANCED_RULE_PACK_VERSION, extract_sensitive_indicators, validate_advanced_rules
from phishing_analyzer.analyzer import analyze_email


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("ADVANCED_TACTIC", "Approve permission access for this application to read your mailbox."),
        ("ADVANCED_TACTIC", "Use this device code and visit Microsoft to sign in."),
        ("ADVANCED_TACTIC", "MFA push notification: approve the login request now."),
        ("ADVANCED_TACTIC", "Your session expired. Re-authenticate and sign in to restore access."),
        ("ADVANCED_TACTIC", "Press Windows + R, paste this command, and run it."),
        ("ADVANCED_TACTIC", "Download AnyDesk and allow the support session using this code."),
        ("ADVANCED_TACTIC", "A SharePoint document was shared. Sign in to view the file."),
        ("ADVANCED_TACTIC", "Reply and provide the OTP verification code."),
        ("ADVANCED_TACTIC", "Scan the QR code to verify your MFA login."),
    ],
)
def test_advanced_tactic_rules(code, message):
    result = analyze_email(message)
    assert code in {finding.code for finding in result.findings}
    assert result.metadata["advanced_detection"]["attack_mappings"]


def test_callback_phishing_requires_lure_phone_and_call_action():
    result = analyze_email("Your antivirus subscription renewed for $499. Call +1 (202) 555-0198 for a refund.")
    assert "CALLBACK_PHISHING" in {finding.code for finding in result.findings}
    assert result.classification == "Callback phishing"


def test_plain_signature_phone_is_not_callback_phishing():
    result = analyze_email("Regards, Example User. Office phone: +1 202 555 0199")
    assert "CALLBACK_PHISHING" not in {finding.code for finding in result.findings}


def test_crypto_payment_destination_is_detected_and_redacted():
    wallet = "0x0123456789abcdef0123456789abcdef01234567"
    result = analyze_email(f"Pay the release fee by crypto to wallet {wallet}")
    assert "PAYMENT_DESTINATION" in {finding.code for finding in result.findings}
    rendered = json.dumps(result.to_dict())
    assert wallet not in rendered
    indicators = result.metadata["advanced_detection"]["sensitive_indicators"]
    assert indicators[0]["type"] == "ethereum_wallet"
    assert indicators[0]["masked"].endswith("4567")


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("phone", "+1 202 555 0199"),
        ("ethereum_wallet", "0x0123456789abcdef0123456789abcdef01234567"),
        ("bitcoin_wallet", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"),
        ("iban", "GB82 WEST 1234 5698 7654 32"),
        ("upi_id", "recipient@okaxis"),
    ],
)
def test_sensitive_indicator_types(kind, value):
    assert kind in {item["type"] for item in extract_sensitive_indicators(value)}


def test_html_smuggling_and_credential_form():
    raw = """From: Service <notice@example.com>
Subject: Shared file
Content-Type: text/html

<html><input type="password" name="password"><script>
const b = atob('SGVsbG8='); const u = URL.createObjectURL(new Blob([b]));
</script><a download="invoice.iso" href="data:application/octet-stream;base64,SGVsbG8=">Open</a></html>
"""
    result = analyze_email(raw)
    codes = {finding.code for finding in result.findings}
    assert {"HTML_SMUGGLING", "HTML_CREDENTIAL_FORM"} <= codes
    assert result.classification == "HTML smuggling or credential capture"


def test_brand_display_name_impersonation():
    result = analyze_email("From: Microsoft Security <alert@unrelated.test>\nSubject: Notice\nMessage-ID: <x@unrelated.test>\n\nHello")
    assert "DISPLAY_NAME_BRAND_IMPERSONATION" in {finding.code for finding in result.findings}


def test_official_brand_domain_is_not_display_name_impersonation():
    result = analyze_email("From: Microsoft Security <alert@microsoft.com>\nSubject: Notice\nMessage-ID: <x@microsoft.com>\n\nHello")
    assert "DISPLAY_NAME_BRAND_IMPERSONATION" not in {finding.code for finding in result.findings}


def test_message_id_domain_mismatch_is_supporting_evidence_only():
    result = analyze_email("From: Alice <alice@example.com>\nMessage-ID: <x@mailer.other.test>\nSubject: Hello\n\nMeeting notes")
    finding = next(item for item in result.findings if item.code == "MESSAGE_ID_DOMAIN_MISMATCH")
    assert finding.severity == "low"
    assert finding.points == 5


def _attachment_message(filename: str, content_type: str, payload: bytes) -> bytes:
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["Subject"] = "Attachment"
    message.set_content("See attachment")
    maintype, subtype = content_type.split("/", 1)
    message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    return message.as_bytes()


def test_deceptive_double_extension_attachment():
    result = analyze_email(_attachment_message("invoice.pdf.lnk", "application/octet-stream", b"shortcut"))
    codes = {finding.code for finding in result.attachments[0].findings}
    assert {"EXECUTABLE_ATTACHMENT", "DOUBLE_EXTENSION"} <= codes


def test_bidi_control_attachment_filename():
    result = analyze_email(_attachment_message("invoice\u202egnp.exe", "application/octet-stream", b"payload"))
    assert "FILENAME_BIDI_CONTROL" in {finding.code for finding in result.attachments[0].findings}


def test_calendar_invite_account_lure_and_url_extraction():
    ics = b"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nSUMMARY:Account verification\r\nDESCRIPTION:Sign in to verify your password https://evil.test/login\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    result = analyze_email(_attachment_message("invite.ics", "text/calendar", ics))
    assert "CALENDAR_INVITE_LURE" in {finding.code for finding in result.attachments[0].findings}
    assert "evil.test" in {link.host for link in result.links}


def test_nested_and_encrypted_archive_are_reported():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("inside.zip", b"not actually a zip")
    result = analyze_email(_attachment_message("documents.zip", "application/zip", buffer.getvalue()))
    assert "NESTED_ARCHIVE" in {finding.code for finding in result.attachments[0].findings}


def test_multitactic_correlation_requires_independent_advanced_sources():
    raw = """From: Microsoft Security <alert@unrelated.test>
Subject: Urgent security action
Content-Type: text/html

<p>Your subscription renewed. Call +1 202 555 0198 for a refund.</p>
<input type="password"><script>const x=atob('QQ=='); new Blob([x]);</script>
"""
    result = analyze_email(raw)
    assert "MULTI_TACTIC_CORROBORATION" in {finding.code for finding in result.findings}


def test_advanced_rule_pack_metadata_and_validation():
    assert validate_advanced_rules() == []
    result = analyze_email("hello")
    assert result.metadata["advanced_detection"]["version"] == ADVANCED_RULE_PACK_VERSION
    assert result.evidence_status["advanced_tactics"] == "not_observed"
    assert result.version == "2.4.1"
