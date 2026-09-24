from __future__ import annotations

import ipaddress
import unicodedata
from functools import lru_cache

try:
    from publicsuffix2 import get_sld
except ImportError:  # pragma: no cover - conservative fallback for bare installs
    get_sld = None


# High-value brands commonly impersonated in Singapore and international mail.
BRANDS = {
    "apple": {"apple.com"},
    "amazon": {"amazon.com", "amazon.sg"},
    "google": {"google.com"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com"},
    "paypal": {"paypal.com"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
    "singpost": {"singpost.com"},
    "dbs": {"dbs.com", "dbs.com.sg"},
    "posb": {"posb.com.sg", "dbs.com.sg"},
    "ocbc": {"ocbc.com"},
    "uob": {"uobgroup.com", "uob.com.sg"},
    "mas": {"mas.gov.sg"},
    "govtech": {"govtech.gov.sg"},
    "singpass": {"singpass.gov.sg"},
    "iras": {"iras.gov.sg"},
    "cpf": {"cpf.gov.sg"},
    "moh": {"moh.gov.sg"},
}

# A compact TR39-style confusable map. It deliberately focuses on characters
# used in domain impersonation and is paired with mixed-script detection.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "ɑ": "a",
        "α": "a",
        "е": "e",
        "ε": "e",
        "ё": "e",
        "і": "i",
        "ι": "i",
        "ӏ": "l",
        "ⅼ": "l",
        "Ӏ": "l",
        "ο": "o",
        "о": "o",
        "ρ": "p",
        "р": "p",
        "ѕ": "s",
        "с": "c",
        "ϲ": "c",
        "τ": "t",
        "т": "t",
        "υ": "u",
        "ν": "v",
        "ѵ": "v",
        "х": "x",
        "у": "y",
        "ʏ": "y",
        "ԁ": "d",
        "ԛ": "q",
        "ց": "g",
        "һ": "h",
        "ｍ": "m",
        "ｗ": "w",
        "０": "0",
        "１": "1",
        "３": "3",
        "５": "5",
    }
)


@lru_cache(maxsize=8192)
def registrable_domain(host: str) -> str:
    host = host.lower().strip(".[]")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if labels[-1:] and labels[-1] in {"example", "test", "invalid", "localhost"}:
        return ".".join(labels[-2:]) if len(labels) > 1 else host
    if get_sld:
        try:
            return (get_sld(host, strict=False) or host).lower()
        except (ValueError, UnicodeError, AttributeError):
            pass
    return ".".join(labels[-2:]) if len(labels) > 1 else host


def unicode_host(ascii_host: str) -> str:
    try:
        return ascii_host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeDecodeError):
        return ascii_host


def script_set(value: str) -> set[str]:
    scripts: set[str] = set()
    for char in value:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK", "HEBREW", "ARABIC", "ARMENIAN", "GEORGIAN", "CJK", "HIRAGANA", "KATAKANA", "HANGUL"):
            if script in name:
                scripts.add(script)
                break
    return scripts


def confusable_skeleton(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value.casefold())
    return "".join(c for c in normalized.translate(CONFUSABLES) if c.isalnum())


def brand_impersonation(host: str) -> list[dict[str, str]]:
    decoded = unicode_host(host)
    reg = registrable_domain(host)
    skeleton = confusable_skeleton(decoded.split(".", 1)[0])
    hits: list[dict[str, str]] = []
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        if brand in skeleton or _distance(skeleton, brand) <= 1:
            hits.append({"brand": brand, "observed": decoded, "official": ", ".join(sorted(official))})
    return hits


def _distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 1:
        return 99
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def unicode_risks(host: str) -> dict[str, object]:
    decoded = unicode_host(host)
    scripts = script_set(decoded)
    controls = [f"U+{ord(c):04X}" for c in decoded if unicodedata.category(c) in {"Cf", "Cc"}]
    return {
        "unicode_host": decoded,
        "scripts": sorted(scripts),
        "mixed_script": len(scripts) > 1,
        "invisible_or_bidi_controls": controls,
        "skeleton": confusable_skeleton(decoded),
        "brand_matches": brand_impersonation(host),
    }
