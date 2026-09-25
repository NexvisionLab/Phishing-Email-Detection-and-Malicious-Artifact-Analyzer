"""What a decoded QR code will do when scanned. Pure functions: needs no image library."""
import pytest

from phishing_analyzer import qr


def kind(value):
    return qr.classify_payload(value).kind


@pytest.mark.parametrize("value,expected", [
    ("https://example.com/pay?id=1", "url"),
    ("HTTPS://EXAMPLE.COM/PAY", "url"),
    ("example.com/pay", "url"),
    ("www.example.com", "url"),
    ("bit.ly/3xYzAbC", "url"),
    ("WIFI:T:WPA;S:CafeGuest;P:s3cretpass;;", "wifi"),
    ("SMSTO:+6591234567:Send 50 dollars", "sms"),
    ("sms:+6591234567?body=hi", "sms"),
    ("tel:+6591234567", "tel"),
    ("mailto:pay@example.com?subject=refund", "email"),
    ("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.5", "crypto"),
    ("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme", "authenticator"),
    ("upi://pay?pa=merchant@bank&am=500", "payment"),
    ("javascript:alert(document.cookie)", "script"),
    ("data:text/html,<script>alert(1)</script>", "script"),
    ("file:///etc/passwd", "script"),
    ("itms-services://?action=download-manifest&url=https://x.example/a.plist", "app_install"),
    ("intent://scan/#Intent;scheme=zxing;end", "app_link"),
    ("market://details?id=com.example.app", "app_link"),
    ("acmepay://checkout/123", "app_link"),
    ("geo:1.3521,103.8198", "location"),
    ("BEGIN:VCARD\nVERSION:3.0\nFN:Bob\nEND:VCARD", "contact"),
    ("Table 12 - order 5541", "text"),
    ("", "text"),
])
def test_payload_kind_is_recognised(value, expected):
    assert kind(value) == expected


def test_a_web_address_without_a_scheme_is_checked_as_a_url():
    # Regression: example.com/pay and bit.ly/... inside a QR were ignored, because only http(s):// counted as a link.
    for value in ("example.com/pay", "www.example.com/pay", "bit.ly/3xYzAbC"):
        assert qr.classify_payload(value).url == "http://" + value


def test_a_link_inside_plain_text_is_still_found():
    payload = qr.classify_payload("Scan to pay: https://evil.example/pay now")
    assert (payload.kind, payload.url) == ("text", "https://evil.example/pay")


def test_things_that_are_not_web_addresses_are_not_treated_as_urls():
    for value in ("hello", "order 12.5", "a@b.example", "version 1.2.3 released", "3.14159", "file.txt", "report.pdf", "photo.png", "notes.docx"):
        assert qr.classify_payload(value).url == "", value


def test_scripts_and_app_installs_are_high_risk_and_payments_are_warnings():
    assert qr.classify_payload("javascript:alert(1)").risk == "high"
    assert qr.classify_payload("itms-services://?action=download-manifest").risk == "high"
    for value in ("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "upi://pay?pa=a@b", "tel:+65123", "WIFI:S:x;P:y;;"):
        assert qr.classify_payload(value).risk == "warn", value
    assert qr.classify_payload("https://example.com").risk == "info"


def test_secrets_never_appear_in_what_is_shown():
    wifi = qr.classify_payload("WIFI:T:WPA;S:CafeGuest;P:s3cretpass;;")
    assert "CafeGuest" in wifi.display and "s3cretpass" not in wifi.display + wifi.note
    otp = qr.classify_payload("otpauth://totp/Acme:alice?secret=JBSWY3DPEHPK3PXP&issuer=Acme")
    assert "JBSWY3DPEHPK3PXP" not in otp.display + otp.note and "alice" in otp.display
    coin = qr.classify_payload("bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.5")
    assert "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" not in coin.display and "0.5" in coin.display


def test_wifi_names_with_escaped_separators_are_read_whole():
    assert "My;Network" in qr.classify_payload(r"WIFI:T:WPA;S:My\;Network;P:pw;;").display


def test_an_sgqr_payment_code_shows_its_merchant():
    def tlv(tag, value):
        return f"{tag}{len(value):02d}{value}"

    emv = (tlv("00", "01") + tlv("01", "11") + tlv("26", tlv("00", "SG.PAYNOW") + tlv("01", "2") + tlv("02", "200000000A"))
           + tlv("52", "5411") + tlv("53", "702") + tlv("54", "5.00") + tlv("58", "SG") + tlv("59", "Acme Coffee Bar")
           + tlv("60", "Singapore") + tlv("63", "ABCD"))
    assert emv.startswith("000201")
    payload = qr.classify_payload(emv)
    assert (payload.kind, payload.risk) == ("payment", "warn")
    assert "Acme Coffee Bar" in payload.display


def test_control_characters_and_length_are_bounded_in_what_is_shown():
    payload = qr.classify_payload("plain\x00\x1b text " + "x" * 5000)
    assert "\x00" not in payload.display and "\x1b" not in payload.display
    assert len(payload.display) <= 300
