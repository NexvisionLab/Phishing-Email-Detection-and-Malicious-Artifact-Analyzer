"""QR decoding: limits, error handling and the attachment path. Needs the optional `qr` extra (OpenCV) and the `qrcode`
generator; skipped without them."""
import io
import sys
import time

import pytest

from phishing_analyzer import qr
from phishing_analyzer.attachments import analyze_attachment
from phishing_analyzer.extractor import RawAttachment

cv2 = pytest.importorskip("cv2")
qrcode = pytest.importorskip("qrcode")
from PIL import Image, ImageOps


def make(payload, box=10, border=4):
    generator = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=box, border=border)
    generator.add_data(payload)
    generator.make(fit=True)
    return generator.make_image(fill_color="black", back_color="white").convert("RGB")


def png(image):
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def test_a_clean_code_round_trips():
    result = qr.decode_qr_image(png(make("https://example.com/pay?id=8812")))
    assert (result.status, result.values) == ("evaluated", ["https://example.com/pay?id=8812"])


def test_a_light_on_dark_code_is_read_by_retrying_inverted():
    # Regression: inverted codes (dark-mode screens) were not found at all.
    result = qr.decode_qr_image(png(ImageOps.invert(make("https://example.com/pay"))))
    assert result.values == ["https://example.com/pay"]


def test_every_code_in_an_image_is_returned_not_just_one():
    sheet = Image.new("RGB", (900, 450), "white")
    sheet.paste(make("https://legit-bank.example/"), (10, 10))
    sheet.paste(make("https://evil-pay.example/steal"), (470, 10))
    assert sorted(qr.decode_qr_image(png(sheet)).values) == ["https://evil-pay.example/steal", "https://legit-bank.example/"]


def test_a_code_without_a_scheme_decodes_and_classifies_as_a_url():
    result = qr.decode_qr_image(png(make("bit.ly/3xYzAbC")))
    assert result.values == ["bit.ly/3xYzAbC"]
    assert qr.classify_payload(result.values[0]).url == "http://bit.ly/3xYzAbC"


def test_an_image_with_no_code_is_evaluated_with_no_symbols():
    result = qr.decode_qr_image(png(Image.new("RGB", (300, 300), "white")))
    assert (result.status, result.values) == ("evaluated", [])


def test_bad_input_returns_a_reason_and_never_raises():
    assert qr.decode_qr_image(b"").reason == "empty"
    assert qr.decode_qr_image(b"this is not an image").reason == "unreadable_image"
    assert qr.decode_qr_image(png(make("https://example.com"))[:150]).status in {"evaluated", "not_evaluated"}


def test_an_image_with_too_many_pixels_is_refused_before_it_is_decoded():
    # Regression: a 303 KB, 100-megapixel PNG made the decoder allocate 1.3 GB.
    side = 7000  # 49 megapixels, over the 36 megapixel limit
    buffer = io.BytesIO()
    Image.new("L", (side, side), 255).save(buffer, "PNG", optimize=True)
    started = time.monotonic()
    result = qr.decode_qr_image(buffer.getvalue())
    assert (result.status, result.reason, result.pixels) == ("not_evaluated", "image_too_large", side * side)
    assert time.monotonic() - started < 2


def test_a_decoder_that_raises_is_reported_not_propagated(monkeypatch):
    def broken(data, invert):
        raise cv2.error("simulated OpenCV failure")

    monkeypatch.setattr(qr, "_cv2_values", broken)
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", None)
    result = qr.decode_qr_image(png(make("https://example.com")))
    assert (result.status, result.reason) == ("not_evaluated", "decode_error")


def test_only_a_bounded_number_of_symbols_and_characters_are_kept(monkeypatch):
    monkeypatch.setattr(qr, "_cv2_values", lambda data, invert: [f"https://h{i}.example/" + "a" * 6000 for i in range(50)])
    monkeypatch.setitem(sys.modules, "pyzbar", None)
    monkeypatch.setitem(sys.modules, "pyzbar.pyzbar", None)
    result = qr.decode_qr_image(png(make("x")))
    assert len(result.values) == qr.MAX_QR_SYMBOLS
    assert all(len(v) == qr.MAX_PAYLOAD_CHARS for v in result.values)


def test_an_attached_qr_image_without_a_scheme_now_yields_its_link():
    item = RawAttachment("scan.png", "image/png", png(make("bit.ly/3xYzAbC")))
    result = analyze_attachment(item)
    assert "http://bit.ly/3xYzAbC" in result.extracted_urls
    assert "QR_URL" in {finding.code for finding in result.findings}
    assert result.qr["status"] == "evaluated" and result.qr["payload_kinds"] == ["url"]


def test_an_attached_oversized_image_is_reported_as_not_evaluated_not_decoded():
    buffer = io.BytesIO()
    Image.new("L", (7000, 7000), 255).save(buffer, "PNG", optimize=True)
    result = analyze_attachment(RawAttachment("huge.png", "image/png", buffer.getvalue()))
    assert result.qr == {"status": "not_evaluated", "reason": "image_too_large"}
