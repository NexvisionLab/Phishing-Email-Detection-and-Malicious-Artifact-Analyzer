from __future__ import annotations

import hashlib
import html
import io
import re
import zipfile
import zlib
from pathlib import Path, PurePosixPath

from .extractor import URL_RE, RawAttachment, extract_urls, parse_input
from .models import AttachmentResult, Finding
from .qr import classify_payload, decode_qr_image
from .urls import risk_label

MAX_ATTACHMENT_BYTES = 10_000_000
MAX_ARCHIVE_MEMBERS = 200
MAX_ARCHIVE_EXPANDED = 50_000_000
MAX_PDF_DECOMPRESSED = 5_000_000
MAX_PDF_STREAMS = 20
EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".bat",
    ".cmd",
    ".ps1",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".hta",
    ".lnk",
    ".url",
    ".reg",
    ".jar",
    ".chm",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".wim",
    ".xll",
    ".xlam",
    ".appinstaller",
    ".msix",
    ".one",
}
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"}
HTML_EXTENSIONS = {".htm", ".html", ".shtml", ".svg", ".mht", ".mhtml"}


def _pdf_static_content(data: bytes) -> tuple[str, bool]:
    """Extract bounded raw and FlateDecode text without interpreting the PDF."""
    scan = data[:MAX_PDF_DECOMPRESSED]
    chunks = [scan.decode("latin-1", errors="ignore")]
    limited = len(data) > len(scan)
    streams = list(re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", scan, re.DOTALL))
    if len(streams) > MAX_PDF_STREAMS:
        limited = True
    remaining = MAX_PDF_DECOMPRESSED
    for match in streams[:MAX_PDF_STREAMS]:
        prefix = scan[max(0, match.start() - 300) : match.start()]
        if b"/FlateDecode" not in prefix:
            continue
        try:
            inflater = zlib.decompressobj()
            decoded = inflater.decompress(match.group(1), remaining)
        except zlib.error:
            continue
        chunks.append(decoded.decode("latin-1", errors="ignore"))
        remaining -= len(decoded)
        if remaining <= 0 or inflater.unconsumed_tail:
            limited = True
            break
    return "\n".join(chunks), limited


def _detected_type(data: bytes) -> str:
    if data.startswith(b"%PDF-"):
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        return "zip"
    if data.startswith((b"MZ",)):
        return "pe_executable"
    if data.startswith((b"GIF8", b"\x89PNG", b"\xff\xd8\xff")):
        return "image"
    head = data[:1000].lstrip().lower()
    if head.startswith((b"<html", b"<!doctype html", b"<svg")):
        return "html_or_svg"
    return "unknown"


def _qr_urls(data: bytes) -> tuple[list[str], dict[str, object]]:
    decoded = decode_qr_image(data)
    if decoded.status != "evaluated":
        return [], {"status": "not_evaluated", "reason": decoded.reason}
    urls: list[str] = []
    fingerprints = []
    kinds = []
    for value in decoded.values:
        payload = classify_payload(value)
        kinds.append(payload.kind)
        if payload.url:
            urls.append(payload.url)
        if payload.kind != "url" or not value.lower().startswith(("http://", "https://")):
            fingerprints.append(
                {
                    "masked": f"***{value[-4:] if len(value) >= 4 else '****'}",
                    "sha256_prefix": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16],
                    "kind": payload.kind,
                }
            )
    return urls, {
        "status": "evaluated",
        "symbols": len(decoded.values),
        "payload_kinds": kinds,
        "non_url_payloads": fingerprints,
        "sensitive_values_redacted": True,
    }


def analyze_attachment(item: RawAttachment) -> AttachmentResult:
    data = item.payload
    digest = hashlib.sha256(data).hexdigest()
    detected = _detected_type(data)
    findings: list[Finding] = []
    urls: list[str] = []
    suffix = Path(item.filename).suffix.casefold()
    suffixes = [value.casefold() for value in Path(item.filename).suffixes]
    if len(data) > MAX_ATTACHMENT_BYTES:
        findings.append(
            Finding(
                "ATTACHMENT_LIMIT",
                "Attachment exceeds static-analysis limit",
                "medium",
                10,
                f"{len(data)} bytes",
                "attachment",
                "not_evaluated",
            )
        )
        return AttachmentResult(
            item.filename,
            item.content_type,
            len(data),
            digest,
            detected,
            10,
            "low",
            findings,
            [],
            {"status": "not_evaluated", "reason": "size_limit"},
        )
    if suffix in EXECUTABLE_EXTENSIONS or detected == "pe_executable":
        findings.append(
            Finding(
                "EXECUTABLE_ATTACHMENT",
                "Executable or script attachment",
                "high",
                65,
                f"{item.filename}; detected {detected}",
                "attachment",
            )
        )
    if len(suffixes) >= 2 and suffixes[-2] in DECOY_EXTENSIONS and suffixes[-1] in EXECUTABLE_EXTENSIONS:
        findings.append(
            Finding("DOUBLE_EXTENSION", "Attachment uses a deceptive double extension", "high", 40, item.filename, "attachment")
        )
    controls = [f"U+{ord(char):04X}" for char in item.filename if ord(char) in range(0x202A, 0x202F) or ord(char) in range(0x2066, 0x206A)]
    if controls:
        findings.append(
            Finding(
                "FILENAME_BIDI_CONTROL",
                "Attachment filename contains bidirectional controls",
                "high",
                35,
                f"{item.filename}; {', '.join(controls)}",
                "attachment",
            )
        )
    expected = {".pdf": "pdf", ".zip": "zip", ".png": "image", ".jpg": "image", ".jpeg": "image"}.get(suffix)
    if expected and expected != detected:
        findings.append(
            Finding(
                "FILE_TYPE_MISMATCH",
                "File extension does not match content",
                "high",
                30,
                f"Extension {suffix}; detected {detected}",
                "attachment",
            )
        )
    qr: dict[str, object] = {"status": "not_applicable"}
    if item.content_type.casefold() == "message/rfc822" or suffix == ".eml":
        parsed_nested = parse_input(data)
        nested_urls, _ = extract_urls(parsed_nested)
        urls.extend(nested_urls)
        lure_text = f"{parsed_nested.subject}\n{parsed_nested.body_text}"[:250_000]
        if re.search(r"(?i)\b(verify|login|sign[ -]?in|password|invoice|payment|refund|mfa|otp|call|urgent)\b", lure_text):
            findings.append(
                Finding(
                    "EMBEDDED_EMAIL_LURE",
                    "Attached email contains an account, payment, or callback lure",
                    "high",
                    30,
                    parsed_nested.subject[:200] or "Attached message body",
                    "attachment",
                )
            )
        if nested_urls:
            findings.append(
                Finding("EMBEDDED_EMAIL_URL", "Attached email contains a web destination", "medium", 14, nested_urls[0][:300], "attachment")
            )
    if detected == "image":
        qr_urls, qr = _qr_urls(data)
        urls.extend(qr_urls)
        if qr_urls:
            findings.append(Finding("QR_URL", "QR code contains a web destination", "medium", 14, qr_urls[0][:300], "attachment"))
    if detected == "pdf":
        text, pdf_limited = _pdf_static_content(data)
        urls.extend(URL_RE.findall(text))
        if re.search(r"/(JavaScript|JS|Launch|OpenAction|EmbeddedFile)\b", text):
            findings.append(
                Finding(
                    "ACTIVE_PDF",
                    "PDF contains active-content markers",
                    "high",
                    35,
                    "JavaScript, launch, open-action, or embedded-file marker",
                    "attachment",
                )
            )
        if pdf_limited:
            findings.append(
                Finding(
                    "PDF_STREAM_LIMIT",
                    "PDF static inspection reached a decompression or stream limit",
                    "medium",
                    8,
                    f"At most {MAX_PDF_STREAMS} streams and {MAX_PDF_DECOMPRESSED} decompressed bytes inspected",
                    "attachment",
                    "partial",
                )
            )
    if (
        detected == "html_or_svg"
        or suffix in HTML_EXTENSIONS
        or item.content_type.casefold() in {"text/html", "image/svg+xml", "multipart/related"}
    ):
        text = html.unescape(data.decode("utf-8", errors="replace"))
        urls.extend(URL_RE.findall(text))
        if re.search(r"(?i)<(script|form|iframe|object|embed)\b|on\w+\s*=", text):
            findings.append(
                Finding("ACTIVE_HTML_ATTACHMENT", "HTML/SVG attachment contains active elements", "high", 35, item.filename, "attachment")
            )
        if re.search(
            r"(?is)data:(?:text/html|application/octet-stream)[^,]{0,120};base64|\b(?:atob|createObjectURL|new\s+Blob)\s*\(|<a\b[^>]*\bdownload\s*=",
            text,
        ):
            findings.append(
                Finding(
                    "HTML_SMUGGLING_ATTACHMENT",
                    "HTML attachment constructs or downloads a client-side payload",
                    "high",
                    45,
                    item.filename,
                    "attachment",
                )
            )
    if suffix == ".ics" or item.content_type.casefold() == "text/calendar":
        text = data.decode("utf-8", errors="replace")
        urls.extend(URL_RE.findall(text))
        fields = {name.upper(): value.strip() for name, value in re.findall(r"(?im)^([A-Z-]+)(?:;[^:]*)?:(.*)$", text)}
        action_text = " ".join(fields.get(key, "") for key in ("SUMMARY", "DESCRIPTION", "LOCATION", "URL", "ATTACH"))
        if urls and re.search(r"(?i)\b(sign[ -]?in|login|verify|payment|invoice|password|mfa|call)\b", action_text):
            findings.append(
                Finding(
                    "CALENDAR_INVITE_LURE",
                    "Calendar invitation contains an account, payment, or callback lure",
                    "high",
                    28,
                    action_text[:300],
                    "attachment",
                )
            )
        elif urls:
            findings.append(
                Finding("CALENDAR_EXTERNAL_URL", "Calendar invitation contains an external URL", "low", 8, urls[0][:300], "attachment")
            )
    if detected == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                infos = archive.infolist()
                total = sum(info.file_size for info in infos)
                compressed = max(1, sum(info.compress_size for info in infos))
                unsafe_archive = len(infos) > MAX_ARCHIVE_MEMBERS or total > MAX_ARCHIVE_EXPANDED or total / compressed > 200
                if unsafe_archive:
                    findings.append(
                        Finding(
                            "ARCHIVE_LIMIT",
                            "Archive exceeds safe expansion limits",
                            "high",
                            30,
                            f"{len(infos)} members; {total} expanded bytes",
                            "attachment",
                            "not_evaluated",
                        )
                    )
                names = [info.filename.casefold() for info in infos[:MAX_ARCHIVE_MEMBERS]]
                traversal = [
                    info.filename
                    for info in infos[:MAX_ARCHIVE_MEMBERS]
                    if info.filename.startswith(("/", "\\")) or ".." in PurePosixPath(info.filename.replace("\\", "/")).parts
                ]
                symlinks = [info.filename for info in infos[:MAX_ARCHIVE_MEMBERS] if (info.external_attr >> 16) & 0o170000 == 0o120000]
                if traversal:
                    findings.append(
                        Finding(
                            "ARCHIVE_PATH_TRAVERSAL",
                            "Archive contains a path that escapes the extraction directory",
                            "high",
                            40,
                            ", ".join(traversal[:20]),
                            "attachment",
                        )
                    )
                if symlinks:
                    findings.append(
                        Finding(
                            "ARCHIVE_SYMLINK",
                            "Archive contains symbolic-link entries",
                            "medium",
                            18,
                            ", ".join(symlinks[:20]),
                            "attachment",
                        )
                    )
                encrypted = [info.filename for info in infos[:MAX_ARCHIVE_MEMBERS] if info.flag_bits & 0x1]
                if encrypted:
                    findings.append(
                        Finding(
                            "ENCRYPTED_ARCHIVE",
                            "Archive contains encrypted members that could not be inspected",
                            "high",
                            28,
                            ", ".join(encrypted[:20]),
                            "attachment",
                            "partial",
                        )
                    )
                if any(name.endswith(("vbaproject.bin", *EXECUTABLE_EXTENSIONS)) for name in names):
                    findings.append(
                        Finding(
                            "ACTIVE_ARCHIVE_CONTENT",
                            "Archive contains macro, executable, or script content",
                            "high",
                            45,
                            ", ".join(names[:20]),
                            "attachment",
                        )
                    )
                embedded = [name for name in names if "/embeddings/" in f"/{name}" or name.endswith(("oleobject.bin", ".bin"))]
                if embedded:
                    findings.append(
                        Finding(
                            "EMBEDDED_OFFICE_OBJECT",
                            "Office or archive container contains embedded objects",
                            "medium",
                            20,
                            ", ".join(embedded[:20]),
                            "attachment",
                        )
                    )
                nested_archives = [name for name in names if name.endswith((".zip", ".7z", ".rar", ".iso", ".img"))]
                if nested_archives:
                    findings.append(
                        Finding(
                            "NESTED_ARCHIVE",
                            "Archive contains another archive or disk image",
                            "medium",
                            18,
                            ", ".join(nested_archives[:20]),
                            "attachment",
                        )
                    )
                rel_names = [] if unsafe_archive else [n for n in names if n.endswith(".rels")]
                for rel_name in rel_names[:20]:
                    try:
                        rel = archive.read(rel_name).decode("utf-8", errors="ignore")
                    except (KeyError, RuntimeError, zipfile.BadZipFile):
                        continue
                    external: list[str] = []
                    for tag in re.findall(r"(?is)<Relationship\b[^>]*>", rel):
                        attrs = {name.casefold(): value for name, _, value in re.findall(r"([\w:.-]+)\s*=\s*(['\"])(.*?)\2", tag)}
                        if attrs.get("targetmode", "").casefold() == "external" and attrs.get("target"):
                            external.append(attrs["target"])
                    urls.extend(url for url in external if url.lower().startswith(("http://", "https://")))
                    if external:
                        findings.append(
                            Finding(
                                "OOXML_EXTERNAL_REL",
                                "Office document references external content",
                                "medium",
                                18,
                                external[0][:300],
                                "attachment",
                            )
                        )
                if not unsafe_archive:
                    for name in names[:MAX_ARCHIVE_MEMBERS]:
                        if not name.endswith((".xml", ".rels")):
                            continue
                        try:
                            xml_text = archive.read(name).decode("utf-8", errors="ignore")[:2_000_000]
                        except (KeyError, RuntimeError, zipfile.BadZipFile):
                            continue
                        if re.search(r"(?i)\bDDE(?:AUTO)?\b", xml_text):
                            findings.append(
                                Finding(
                                    "OFFICE_DDE_FIELD",
                                    "Office document contains a dynamic data exchange field",
                                    "high",
                                    32,
                                    name,
                                    "attachment",
                                )
                            )
                            break
        except (zipfile.BadZipFile, OSError, RuntimeError):
            findings.append(Finding("MALFORMED_ARCHIVE", "Archive could not be safely parsed", "medium", 18, item.filename, "attachment"))
    urls = list(dict.fromkeys(urls))[:50]
    score = min(100, sum(f.points for f in findings))
    return AttachmentResult(item.filename, item.content_type, len(data), digest, detected, score, risk_label(score), findings, urls, qr)
