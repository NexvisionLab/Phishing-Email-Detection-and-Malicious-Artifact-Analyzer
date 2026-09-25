"""QR code decoding with resource limits, and classification of what a decoded code will do when scanned.

Decoding is offline. OpenCV (the optional ``qr`` extra) is the primary decoder; ``pyzbar`` is used as a fallback when it
is installed, because each decoder misses codes the other reads. Images are measured from their header before anything
is decoded: OpenCV needs about 13 bytes of memory per pixel, so a 300 KB PNG of 100 megapixels asked for 1.3 GB.

Classification never returns secrets. A Wi-Fi password, an authenticator secret and most of a wallet address are
replaced by a short description, so a report built from it can be shown or stored safely.
"""
from __future__ import annotations

import io
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

MAX_QR_IMAGE_PIXELS = 36_000_000  # about 6000 x 6000; roughly half a gigabyte to decode
MAX_QR_SYMBOLS = 10
MAX_PAYLOAD_CHARS = 4096

_URL_IN_TEXT = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
_BARE_HOST = re.compile(
    r"(?i)^(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?::\d{1,5})?(?:[/?#]\S*)?$"
)
# File extensions that read like a top-level domain: "report.pdf" or "photo.png" is a file name, not a web address.
_FILE_EXTENSIONS = frozenset({
    "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "png", "jpg", "jpeg", "gif", "bmp", "svg", "csv", "json",
    "xml", "html", "htm", "php", "css", "exe", "dll", "bat", "log", "md", "rtf", "tmp", "bak", "ini", "cfg",
})
_SCHEME = re.compile(r"(?i)^([a-z][a-z0-9+.\-]*):")
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass(slots=True)
class QrDecode:
    status: str  # "evaluated" or "not_evaluated"
    values: list[str] = field(default_factory=list)
    reason: str = ""
    pixels: int = 0


@dataclass(slots=True)
class QrPayload:
    kind: str
    label: str
    risk: str  # "high", "warn" or "info"
    note: str
    display: str = ""
    url: str = ""


# --------------------------------------------------------------------------- decoding


def _decode_bytes(raw: bytes) -> str:
    """zbar returns bytes. QR byte mode is ISO-8859-1 by the standard but almost every generator writes UTF-8."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _image_pixels(data: bytes) -> tuple[int, str]:
    """Returns (pixels, "") from the image header alone, or (0, reason) if it is not a readable image."""
    try:
        from PIL import Image
    except ImportError:  # Pillow arrives with reportlab, but never assume
        return 0, ""
    try:
        with Image.open(io.BytesIO(data)) as image:
            width, height = image.size
    except Image.DecompressionBombError:  # Pillow's own guard, tripped when the header alone claims a huge image
        return MAX_QR_IMAGE_PIXELS + 1, ""
    except (OSError, ValueError, SyntaxError):
        return 0, "unreadable_image"
    return width * height, ""


def _cv2_values(data: bytes, invert: bool) -> list[str]:
    import cv2
    import numpy as np

    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return []
    if invert:
        image = cv2.bitwise_not(image)
    detector = cv2.QRCodeDetector()
    ok, values, _, _ = detector.detectAndDecodeMulti(image)
    found = [v for v in values if v] if ok else []
    if not found:
        value, _, _ = detector.detectAndDecode(image)
        found = [value] if value else []
    return found


def _zbar_values(data: bytes, invert: bool) -> list[str]:
    from PIL import Image, ImageOps
    from pyzbar.pyzbar import decode

    with Image.open(io.BytesIO(data)) as source:
        grey = source.convert("L")
    if invert:
        grey = ImageOps.invert(grey)
    return [_decode_bytes(symbol.data) for symbol in decode(grey)]


def decode_qr_image(data: bytes) -> QrDecode:
    """Finds and decodes every QR code in an image.

    Never raises for a bad image: the reason is returned. Decoded text is capped, and at most MAX_QR_SYMBOLS are kept.
    """
    if not data:
        return QrDecode("not_evaluated", reason="empty")
    pixels, reason = _image_pixels(data)
    if reason:
        return QrDecode("not_evaluated", reason=reason)
    if pixels > MAX_QR_IMAGE_PIXELS:
        return QrDecode("not_evaluated", reason="image_too_large", pixels=pixels)

    decoders = []
    try:
        import cv2  # noqa: F401
        import numpy  # noqa: F401

        decoders.append(_cv2_values)
    except ImportError:
        pass
    try:
        import pyzbar.pyzbar  # noqa: F401

        decoders.append(_zbar_values)
    except (ImportError, OSError):  # OSError: the zbar shared library is missing
        pass
    if not decoders:
        return QrDecode("not_evaluated", reason="local_qr_decoder_unavailable", pixels=pixels)

    values: list[str] = []
    clean_runs = 0
    for attempt in (False, True):  # as given, then inverted (light modules on a dark background)
        for decoder in decoders:
            found: list[str] | None
            try:
                found = decoder(data, attempt)
            except Exception:  # noqa: BLE001 - OpenCV raises cv2.error, zbar and Pillow raise assorted errors
                found = None
            if found is None:
                continue
            clean_runs += 1
            for value in found:
                if value not in values:
                    values.append(value)
        if values:
            break
    if clean_runs == 0:
        return QrDecode("not_evaluated", reason="decode_error", pixels=pixels)
    clean = [unicodedata.normalize("NFC", v)[:MAX_PAYLOAD_CHARS] for v in values[:MAX_QR_SYMBOLS]]
    return QrDecode("evaluated", values=clean, pixels=pixels)


# ------------------------------------------------------------------------ classification


def _short(value: str, limit: int = 200) -> str:
    text = _CONTROL.sub(" ", value).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _mask_address(address: str) -> str:
    return address if len(address) <= 14 else f"{address[:6]}…{address[-6:]}"


def _wifi_field(body: str, key: str) -> str:
    match = re.search(rf"(?:^|;){key}:((?:\\.|[^;\\])*)", body)
    return re.sub(r"\\(.)", r"\1", match.group(1)) if match else ""


def _emv_merchant(value: str) -> str:
    """Merchant name (tag 59) from an EMV merchant-presented payment QR (SGQR, PayNow and similar), if it parses."""
    index, tags = 0, {}
    while index + 4 <= len(value):
        tag, length = value[index:index + 2], value[index + 2:index + 4]
        if not length.isdigit():
            return ""
        end = index + 4 + int(length)
        if end > len(value):
            return ""
        tags[tag] = value[index + 4:end]
        index = end
    return _short(tags.get("59", ""), 60)


_CRYPTO_SCHEMES = {"bitcoin", "ethereum", "litecoin", "monero", "ripple", "dogecoin", "solana", "tron", "bitcoincash", "dash"}
_SCRIPT_SCHEMES = {"javascript", "vbscript", "data", "file", "blob"}
_APP_SCHEMES = {"intent", "market", "android-app", "itms-apps", "itms-appss"}


def classify_payload(value: str) -> QrPayload:
    """Says what scanning this text would do, without revealing secrets in it."""
    text = (value or "").strip()
    if not text:
        return QrPayload("text", "Empty", "info", "The code contains no text.")
    scheme_match = _SCHEME.match(text)
    scheme = scheme_match.group(1).lower() if scheme_match else ""

    if scheme in ("http", "https"):
        return QrPayload("url", "Web link", "info", "Opens a web page.", display=_short(text, 300), url=text)
    if scheme in _SCRIPT_SCHEMES:
        return QrPayload("script", "Runs code or opens local content", "high",
                         "Scanning this can run a script in your browser or open local data. Do not scan it, and never enter anything if it opens.",
                         display=_short(text, 120))
    if scheme == "wifi":
        body = text[5:]
        name, kind = _wifi_field(body, "S"), _wifi_field(body, "T") or "open"
        return QrPayload("wifi", "Wi-Fi network", "warn",
                         "Joins a Wi-Fi network. A code from a stranger can connect you to a network an attacker controls. The password is hidden here.",
                         display=f"Network {_short(name, 60) or '(no name)'} ({kind})")
    if scheme in ("sms", "smsto", "mms", "mmsto"):
        number = _short(unquote(text.split(":", 1)[1].split(":", 1)[0].split("?", 1)[0]), 40)
        return QrPayload("sms", "Text message", "warn",
                         "Prepares a text message to a number. Scam codes use this to sign you up for premium services or to start a conversation.",
                         display=f"To {number}")
    if scheme == "tel":
        return QrPayload("tel", "Phone call", "warn", "Starts a phone call. Check the number before you confirm.",
                         display=_short(unquote(text[4:]), 40))
    if scheme == "mailto":
        return QrPayload("email", "Email", "info", "Prepares an email.", display=_short(unquote(text[7:].split("?", 1)[0]), 120))
    if scheme in _CRYPTO_SCHEMES:
        parsed = urlsplit(text)
        amount = (parse_qs(parsed.query).get("amount") or [""])[0]
        address = _mask_address(parsed.path or text.split(":", 1)[1].split("?", 1)[0])
        return QrPayload("crypto", "Cryptocurrency payment", "warn",
                         "Prepares a cryptocurrency payment. Payments cannot be reversed: confirm who is receiving it.",
                         display=f"{scheme.title()} address {address}" + (f", amount {_short(amount, 20)}" if amount else ""))
    if scheme == "upi":
        query = parse_qs(urlsplit(text).query)
        payee = (query.get("pa") or [""])[0]
        return QrPayload("payment", "Payment request", "warn", "Prepares a payment. Confirm the payee name in your payment app before you pay.",
                         display=f"Payee {_short(payee, 60) or '(none)'}" + (f", amount {_short(query['am'][0], 20)}" if query.get("am") else ""))
    if scheme in ("otpauth", "otpauth-migration"):
        label = _short(unquote(urlsplit(text).path.lstrip("/")), 80)
        return QrPayload("authenticator", "Login-code (two-factor) setup", "warn",
                         "Adds a code generator to your authenticator app. Only scan one you created yourself in that service's security settings. The secret is hidden here.",
                         display=label or "Authenticator account")
    if scheme == "itms-services":
        return QrPayload("app_install", "App installation", "high", "Installs an app outside the app store. Do not scan it unless your employer told you to.",
                         display=_short(text, 120))
    if scheme in _APP_SCHEMES:
        return QrPayload("app_link", "Opens or installs an app", "warn", "Opens an app or an app-store page. Check what it is before you install.",
                         display=_short(text, 120))
    if scheme in ("geo",):
        return QrPayload("location", "Map location", "info", "Opens a map location.", display=_short(text[4:], 60))
    if text.upper().startswith(("BEGIN:VCARD", "MECARD:", "BEGIN:VEVENT", "BEGIN:VCALENDAR")):
        return QrPayload("contact", "Contact or calendar entry", "info", "Adds a contact or an event to your phone.", display=_short(text.replace("\n", " "), 120))
    if text.startswith("000201") and _emv_merchant(text):
        return QrPayload("payment", "Payment request (SGQR/EMV)", "warn",
                         "A merchant payment code. Confirm the merchant name in your banking app before you pay.",
                         display=f"Merchant {_emv_merchant(text)}")
    if "://" in text[:40] and scheme:
        return QrPayload("app_link", "App link", "warn", f"Opens the {scheme} app or handler. Check what it is before you continue.",
                         display=_short(text, 120))
    host_part = re.split(r"[/?#:]", text, maxsplit=1)[0]
    if (
        "\n" not in text
        and " " not in text
        and len(text) <= 2048
        and _BARE_HOST.match(text)
        and host_part.rsplit(".", 1)[-1].lower() not in _FILE_EXTENSIONS
    ):
        return QrPayload("url", "Web address", "info",
                         "A web address written without http://. It is checked as if it were https://.",
                         display=_short(text, 300), url="http://" + text)
    embedded = _URL_IN_TEXT.search(text)
    if embedded:
        return QrPayload("text", "Text with a link", "info", "Plain text that contains a web link.", display=_short(text, 300), url=embedded.group(0))
    return QrPayload("text", "Plain text", "info", "Shows text. It does nothing else.", display=_short(text, 300))
