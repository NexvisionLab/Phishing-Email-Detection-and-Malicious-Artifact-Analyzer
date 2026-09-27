"""Regression tests from the 2026-09-27 case review: twenty realistic emails (fifteen attacks and five tricky legitimate
messages, built by tests/make_cases.py) plus the bugs they and a malformed-input probe turned up:

- a made-up charset name crashed the analyzer;
- non-ASCII text in a message with headers was destroyed before any rule saw it;
- a link whose visible text differs from its destination was reported but never counted in the score;
- link text was compared as a whole string, so tracking parameters raised it and a bare domain ("paypal.com") did not;
- the sender's own domain was never checked for brand look-alikes;
- payroll diversion, wallet recovery-phrase requests and French tax-refund lures had no rule;
- lookalike letters, zero-width characters and letter-spacing hid keywords from the rules."""
import json
import os

import pytest

from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.extractor import parse_input

CASES = os.path.join(os.path.dirname(__file__), "cases")
ORDER = {"low": 0, "suspicious": 1, "likely_phishing": 2, "high": 3}
HDR = "From: A <a@example.org>\nTo: b@example.org\nSubject: hi\nDate: Thu, 24 Sep 2026 09:30:00 +0000\nMessage-ID: <1@example.org>\n"
ZW = chr(0x200B)
CYR_A, CYR_E, CYR_O = chr(0x0430), chr(0x0435), chr(0x043E)


def risk(raw):
    return analyze_email(raw, network_enabled=False)


def codes(result):
    return {f.code for f in result.findings}


# ---------------------------------------------------------------- the twenty cases
MANIFEST = json.load(open(os.path.join(CASES, "manifest.json"), encoding="utf-8"))


@pytest.mark.parametrize("case", MANIFEST, ids=[c["id"] for c in MANIFEST])
def test_case(case):
    raw = open(os.path.join(CASES, case["file"]), "rb").read()
    result = risk(raw)
    if case["expected"] == "phish":
        assert ORDER[result.risk] >= ORDER[case["min_risk"]], (case["title"], result.risk, result.score)
    else:
        assert result.risk == "low", (case["title"], result.risk, result.score, [f.code for f in result.findings])


# ---------------------------------------------------------------- crash
def test_unknown_charset_does_not_crash():
    raw = HDR + "Content-Type: text/plain; charset=nonsense-9\n\nverify your account now: http://x.example/login"
    assert risk(raw).risk in ORDER


# ---------------------------------------------------------------- non-ASCII text survives parsing
BODY = "caf" + chr(0xE9) + " " + chr(0x4F60) + chr(0x597D)


@pytest.mark.parametrize("prefix", [
    "",
    "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n",
])
def test_non_ascii_body_is_kept_for_pasted_text_with_headers(prefix):
    assert parse_input(HDR + prefix + "\n" + BODY).body_text.strip() == BODY


def test_non_ascii_body_is_kept_for_an_uploaded_file_without_a_charset():
    assert parse_input((HDR + "\n" + BODY).encode("utf-8")).body_text.strip() == BODY


def test_quoted_printable_and_base64_bodies_still_decode():
    import base64
    qp = HDR + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: quoted-printable\n\ncaf=C3=A9"
    b64 = HDR + "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n" + base64.b64encode("café".encode()).decode()
    assert parse_input(qp).body_text.strip() == "caf" + chr(0xE9)
    assert parse_input(b64).body_text.strip() == "caf" + chr(0xE9)


def test_french_tax_lure_is_caught_with_and_without_accents():
    accented = HDR + "\nVous avez droit à un remboursement d'impôts. Veuillez vérifier vos coordonnées bancaires avant 48 heures : http://impots-fr.example.com"
    plain = HDR + "\nVous avez droit a un remboursement d'impots. Veuillez verifier vos coordonnees bancaires avant 48 heures : http://impots-fr.example.com"
    assert risk(accented).risk != "low" and risk(plain).risk != "low"


# ---------------------------------------------------------------- link text versus destination
def html_link(label, href):
    return HDR + "Content-Type: text/html\n\n" + f'<a href="{href}">{label}</a>'


def test_a_mismatched_link_counts_toward_the_score():
    result = risk(html_link("https://www.google.com/account", "http://evil.example.net/x"))
    assert "DISPLAY_LINK_MISMATCH" in codes(result)
    assert result.dimensions.destination_risk >= 25
    assert result.risk != "low"


def test_a_bare_domain_label_over_another_site_is_a_mismatch():
    assert "DISPLAY_LINK_MISMATCH" in codes(risk(html_link("paypal.com", "http://evil.example.net/x")))
    assert "DISPLAY_LINK_MISMATCH" in codes(risk(html_link("www.paypal.com/signin", "http://evil.example.net/x")))


def test_the_same_site_with_tracking_parameters_is_not_a_mismatch():
    for label, href in (
        ("https://shop.example.com/sale", "https://shop.example.com/sale?utm_source=email&id=9"),
        ("https://shop.example.com", "https://click.shop.example.com/track?u=abc"),
        ("shop.example.com", "https://www.shop.example.com/"),
    ):
        assert "DISPLAY_LINK_MISMATCH" not in codes(risk(html_link(label, href))), (label, href)


def test_a_file_name_as_link_text_is_not_a_domain():
    for label in ("invoice.pdf", "setup.exe", "Report_Q3.xlsx", "photo.jpg"):
        assert "DISPLAY_LINK_MISMATCH" not in codes(risk(html_link(label, "https://files.example.com/d/1"))), label


def test_google_sites_shown_as_google_drive_is_a_mismatch():
    assert "DISPLAY_LINK_MISMATCH" in codes(risk(html_link("https://drive.google.com/file/d/1AbC/view", "https://sites.google.com/view/salary-portal")))


def test_a_userinfo_trick_is_a_mismatch():
    assert "DISPLAY_LINK_MISMATCH" in codes(risk(html_link("http://www.google.com/account", "http://www.google.com@evil.example.net/x")))


# ---------------------------------------------------------------- sender domain
def test_a_lookalike_sender_domain_is_flagged_even_with_a_plain_display_name():
    raw = "From: Support <help@micr0soft-online.com>\nTo: b@example.org\nSubject: Notice\nMessage-ID: <1@example.org>\n\nPlease review."
    assert "SENDER_DOMAIN_BRAND_IMPERSONATION" in codes(risk(raw))


def test_the_real_brand_domain_is_not_flagged_as_a_lookalike_sender():
    raw = "From: Microsoft <account-security-noreply@accountprotection.microsoft.com>\nTo: b@example.org\nSubject: Notice\nMessage-ID: <1@example.org>\n\nPlease review."
    assert "SENDER_DOMAIN_BRAND_IMPERSONATION" not in codes(risk(raw))


# ---------------------------------------------------------------- new rules, and what must stay quiet
def test_payroll_diversion_is_caught():
    assert risk(HDR + "\nHi, I have changed banks. Please update my direct deposit before Friday.").risk != "low"
    assert risk(HDR + "\nPlease update my direct deposit to the new account below before the next payroll run.").risk != "low"


def test_an_hr_notice_about_a_payroll_change_stays_low():
    assert risk(HDR + "\nYour direct deposit was updated as requested. If you did not make this change, contact HR.").risk == "low"
    assert risk(HDR + "\nWe updated our account settings and privacy policy. No action is needed.").risk == "low"


def test_a_recovery_phrase_request_is_high():
    result = risk(HDR + "\nYour wallet is suspended. To restore access, enter your 12-word recovery phrase at https://wallet-restore.example.net")
    assert result.risk in {"likely_phishing", "high"}
    assert result.classification == "Crypto wallet phishing"


def test_a_warning_never_to_share_a_recovery_phrase_stays_low():
    assert risk(HDR + "\nNever enter your seed phrase on any website. We will never ask for your recovery phrase.").risk == "low"


# ---------------------------------------------------------------- disguised wording
def test_zero_width_characters_do_not_hide_the_wording():
    body = "Please ve" + ZW + "rify your acc" + ZW + "ount now: https://secure-login.example.net/verify"
    assert "CONTENT_PATTERN" in codes(risk(HDR + "\n" + body))


def test_lookalike_letters_do_not_hide_the_wording():
    body = "Pl" + CYR_E + CYR_A + "se v" + CYR_E + "rify y" + CYR_O + "ur " + CYR_A + "cc" + CYR_O + "unt: https://secure-login.example.net/verify"
    assert "CONTENT_PATTERN" in codes(risk(HDR + "\n" + body))


def test_letter_spacing_does_not_hide_the_wording():
    assert risk(HDR + "\nTo restore your wallet, enter your s e e d   p h r a s e at https://wallet-restore.example.net").risk != "low"


def test_genuine_russian_text_is_not_folded_into_latin():
    from phishing_analyzer.content import normalize_text
    word = chr(0x043F) + chr(0x0440) + chr(0x0438) + chr(0x0432) + chr(0x0435) + chr(0x0442)  # "привет": Cyrillic only
    assert normalize_text(word) == word
