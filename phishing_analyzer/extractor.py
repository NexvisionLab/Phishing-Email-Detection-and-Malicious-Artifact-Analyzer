from __future__ import annotations

import base64
import binascii
import hashlib
import html
import re
from dataclasses import dataclass, field
from email import policy
from email.parser import BytesParser, Parser
from html.parser import HTMLParser
from urllib.parse import unquote, urljoin

URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
TRAILING = ".,;:!?)]}>'\""
URL_ATTRS = {"href", "src", "action", "formaction", "poster", "data", "xlink:href", "background"}
MAX_EXTRACTED_URLS = 2_000
MAX_DECODED_TOKENS = 100
MAX_MIME_PARTS = 2_000


@dataclass(slots=True)
class RawAttachment:
    filename: str
    content_type: str
    payload: bytes


@dataclass(slots=True)
class ParsedInput:
    input_type: str
    subject: str
    body_text: str
    body_html: str
    headers: dict[str, str]
    body_text_is_html_fallback: bool = False
    attachments: list[RawAttachment] = field(default_factory=list)
    html_indicators: list[dict[str, str]] = field(default_factory=list)


class SafeHTMLExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.anchors: list[tuple[str, str]] = []
        self.indicators: list[dict[str, str]] = []
        self._anchor_href = ""
        self._anchor_text: list[str] = []
        self._in_style = False
        self._style_text: list[str] = []
        self._base_url = ""

    def _resolved(self, value: str) -> str:
        if not value:
            return ""
        return urljoin(self._base_url, value) if self._base_url else value

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): html.unescape(v or "") for k, v in attrs}
        if tag == "base" and not self._base_url:
            candidate = values.get("href", "")
            if candidate.casefold().startswith(("http://", "https://")):
                self._base_url = candidate
        if tag == "a":
            self._anchor_href = self._resolved(values.get("href", ""))
            self._anchor_text = []
        if tag == "style":
            self._in_style = True
        for name in URL_ATTRS:
            raw_value = values.get(name, "")
            if not raw_value:
                continue
            if raw_value.casefold().startswith(("mailto:", "tel:")):
                digest = hashlib.sha256(raw_value.encode("utf-8", errors="replace")).hexdigest()[:16]
                self.indicators.append({"type": "contact_uri", "value": f"redacted:sha256:{digest}"})
                continue
            value = self._resolved(raw_value)
            if value.lower().startswith(("http://", "https://")):
                self.urls.append(value)
                if tag in {"form", "button", "iframe", "script", "object", "embed", "svg", "image", "use", "base", "area", "input"}:
                    self.indicators.append({"type": f"{tag}_{name}", "value": value[:500]})
        if tag == "meta" and values.get("http-equiv", "").casefold() == "refresh":
            content = values.get("content", "")
            match = re.search(r"(?i)url\s*=\s*['\"]?([^'\";\s]+)", content)
            if match:
                self.urls.append(match.group(1))
                self.indicators.append({"type": "meta_refresh", "value": match.group(1)[:500]})
        for attr in ("style",):
            self._extract_css(values.get(attr, ""))

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._anchor_href:
            self.anchors.append((self._anchor_href, "".join(self._anchor_text).strip()))
            self._anchor_href, self._anchor_text = "", []
        if tag == "style":
            self._extract_css("".join(self._style_text))
            self._style_text = []
            self._in_style = False

    def handle_data(self, data: str) -> None:
        if self._anchor_href:
            self._anchor_text.append(data)
        else:
            self.urls.extend(match.rstrip(TRAILING) for match in URL_RE.findall(data))
        if self._in_style:
            self._style_text.append(data)

    def _extract_css(self, css: str) -> None:
        for match in re.finditer(r"(?is)url\(\s*['\"]?(https?://[^)'\"\s]+)", css):
            self.urls.append(match.group(1))
            self.indicators.append({"type": "css_url", "value": match.group(1)[:500]})


def _body_parts(message) -> tuple[str, str, list[RawAttachment], bool]:
    plain: list[str] = []
    rich: list[str] = []
    attachments: list[RawAttachment] = []
    parts = message.walk() if message.is_multipart() else [message]
    truncated = False
    for index, part in enumerate(parts):
        # Each part costs about 1 ms of header parsing, so an unbounded multipart body is a slow-input DoS.
        if index >= MAX_MIME_PARTS:
            truncated = True
            break
        disposition = (part.get_content_disposition() or "").lower()
        ctype = part.get_content_type()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            payload = part.get_payload(decode=True)
            if payload is None and ctype == "message/rfc822":
                nested = part.get_payload()
                if isinstance(nested, list) and nested:
                    payload = nested[0].as_bytes(policy=policy.default)
                elif hasattr(nested, "as_bytes"):
                    payload = nested.as_bytes(policy=policy.default)
            attachments.append(RawAttachment(filename or f"attachment-{index}", ctype, payload or b""))
            continue
        if ctype not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
        except (LookupError, TypeError, UnicodeError, ValueError):
            payload = part.get_payload(decode=True) or b""
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        (plain if ctype == "text/plain" else rich).append(str(content))
    return "\n".join(plain), "\n".join(rich), attachments, truncated


def parse_input(raw: str | bytes) -> ParsedInput:
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    header_like = bool(re.search(r"(?im)^(from|to|subject|date|message-id|received|authentication-results):\s*", text[:10000]))
    if not header_like:
        return ParsedInput("pasted_text", "", text, "", {})
    message = BytesParser(policy=policy.default).parsebytes(raw) if isinstance(raw, bytes) else Parser(policy=policy.default).parsestr(raw)
    plain, rich, attachments, parts_truncated = _body_parts(message)
    headers = {key.lower(): "\n".join(str(v) for v in message.get_all(key, [])) for key in message}
    html_fallback = not plain and bool(rich)
    if html_fallback:
        parser = SafeHTMLExtractor()
        parser.feed(rich)
        plain = html.unescape(re.sub(r"(?s)<[^>]+>", " ", rich))
    parsed = ParsedInput("eml", str(message.get("subject", "")), plain, rich, headers, html_fallback, attachments)
    if parts_truncated:
        parsed.html_indicators.append({"type": "mime_part_limit", "value": f"Only the first {MAX_MIME_PARTS} MIME parts were examined"})
    return parsed


def _decoded_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    decoded_text = html.unescape(text)
    layers = [decoded_text]
    for _ in range(3):
        value = unquote(layers[-1])
        if value == layers[-1]:
            break
        layers.append(value)
    escaped = re.sub(r"\\u([0-9a-fA-F]{4})", lambda match: chr(int(match.group(1), 16)), decoded_text)
    escaped = re.sub(r"\\x([0-9a-fA-F]{2})", lambda match: chr(int(match.group(1), 16)), escaped)
    layers.append(escaped)
    for value in layers:
        candidates.extend(match.rstrip(TRAILING) for match in URL_RE.findall(value))
    # Extract bounded standard and URL-safe base64 tokens without executing or fetching.
    for token_match in list(re.finditer(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{20,4096}={0,2}(?![A-Za-z0-9_+/=-])", text))[
        :MAX_DECODED_TOKENS
    ]:
        token = token_match.group(0)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(token + "=" * (-len(token) % 4)).decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            candidates.extend(match.rstrip(TRAILING) for match in URL_RE.findall(html.unescape(decoded)))
            break
    return candidates[:500]


def extract_urls(parsed: ParsedInput) -> tuple[list[str], list[tuple[str, str]]]:
    candidates = [] if parsed.body_text_is_html_fallback else _decoded_candidates(parsed.body_text or "")
    mismatches: list[tuple[str, str]] = []
    if parsed.body_html:
        parser = SafeHTMLExtractor()
        parser.feed(parsed.body_html)
        parsed.html_indicators.extend(parser.indicators)
        candidates.extend(parser.urls)
        for href, label in parser.anchors:
            candidates.append(href)
            visible = URL_RE.search(label)
            if visible and visible.group(0).rstrip(TRAILING).casefold() != href.rstrip(TRAILING).casefold():
                mismatches.append((visible.group(0).rstrip(TRAILING), href.rstrip(TRAILING)))
    unique: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        clean = html.unescape(url).rstrip(TRAILING)
        if clean.lower().startswith(("http://", "https://")) and clean.casefold() not in seen:
            seen.add(clean.casefold())
            unique.append(clean)
            if len(unique) >= MAX_EXTRACTED_URLS:
                parsed.html_indicators.append(
                    {"type": "url_extraction_limit", "value": f"Limited to {MAX_EXTRACTED_URLS} unique destinations"}
                )
                break
    return unique, mismatches
