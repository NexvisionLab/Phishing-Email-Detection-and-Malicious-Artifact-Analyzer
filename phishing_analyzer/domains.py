from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache

try:
    from publicsuffix2 import get_sld
except ImportError:  # pragma: no cover - conservative fallback for bare installs
    get_sld = None


# High-value brands commonly impersonated in Singapore and international mail.
BRANDS = {
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.sg", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.in", "amazon.com.au",
               "amazon.co.jp", "amazonaws.com", "amazon.jobs"},
    "google": {"google.com", "google.co.uk", "google.com.sg", "google.ca", "google.de", "google.com.au", "googleapis.com",
               "gstatic.com", "googleusercontent.com", "googlemail.com", "gmail.com", "youtube.com", "goo.gl", "g.co"},
    "microsoft": {"microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com",
                  "sharepoint.com", "azure.com", "windows.com", "msn.com", "skype.com", "bing.com"},
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "dhl": {"dhl.com", "dhl.de", "dhl.co.uk", "dhl.com.sg"},
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


# ASCII look-alikes used to spell a brand with digits or symbols (micros0ft, paypa1, amaz0n).
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
# Words that turn a brand into a lure when joined to it: paypal-secure, microsoftsupport, verify-apple.
_LURE_WORDS = (
    "account", "accounts", "alert", "alerts", "billing", "care", "center", "centre", "confirm", "customer", "delivery",
    "help", "helpdesk", "id", "info", "invoice", "login", "logon", "mail", "official", "online", "pay", "payment",
    "payments", "portal", "recovery", "refund", "reset", "secure", "security", "service", "services", "signin", "support",
    "team", "track", "tracking", "update", "verify", "verification", "wallet", "web", "webmail",
)
_LURE_RUN = re.compile("(?:" + "|".join(sorted(_LURE_WORDS, key=len, reverse=True)) + ")*")


def _brand_forms(token: str) -> set[str]:
    """The spellings a label could be read as: as written, with digit look-alikes folded, and with rn or vv read as m or w."""
    base = confusable_skeleton(token)
    folded = confusable_skeleton(token.translate(_LEET))
    seeds = {base, folded}
    forms = seeds | {form.replace("rn", "m") for form in seeds} | {form.replace("vv", "w") for form in seeds}
    return {form for form in forms if form}


def _is_lure_affix(text: str) -> bool:
    return text == "" or _LURE_RUN.fullmatch(text) is not None


def brand_impersonation(host: str) -> list[dict[str, str]]:
    """Flags a host that spells or embeds a brand it does not own.

    Each dot-separated label to the left of the public suffix is split on hyphens. A token matches a brand when it
    is the brand, is the brand joined only to lure words (paypalsecure, verify-apple), or is a single edit away from
    a brand of five or more letters (paypa1, googel). Substring matching is deliberately not used: it flagged
    mashable.com and masterclass.com for containing "mas", and pineapple.com for containing "apple".
    A registrable domain the brand owns is never flagged.
    """
    decoded = unicode_host(host)
    reg = registrable_domain(host)
    labels = [label for label in decoded.lower().split(".") if label]
    suffix_labels = len(reg.split(".")) - 1 if reg else 1
    candidates = labels[:-suffix_labels] if len(labels) > suffix_labels else labels[:1]
    tokens: list[str] = []
    for label in candidates:
        tokens.extend(part for part in re.split(r"[-_]", label) if part)
    hits: list[dict[str, str]] = []
    for brand, official in BRANDS.items():
        if reg in official:
            continue
        matched = False
        for token in tokens:
            for form in _brand_forms(token):
                if form == brand:
                    matched = True
                elif brand in form:
                    before, _, after = form.partition(brand)
                    matched = _is_lure_affix(before) and _is_lure_affix(after)
                elif len(brand) >= 5 and (_distance(form, brand) <= 1 or _swapped_neighbours(form, brand)):
                    matched = True
                if matched:
                    break
            if matched:
                break
        if matched:
            hits.append({"brand": brand, "observed": decoded, "official": ", ".join(sorted(official))})
    return hits


def _swapped_neighbours(a: str, b: str) -> bool:
    """True when a and b differ only by two adjacent letters trading places (googel for google)."""
    if len(a) != len(b):
        return False
    diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


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
