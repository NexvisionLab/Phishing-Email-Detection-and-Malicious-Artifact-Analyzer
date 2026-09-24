from phishing_analyzer.analyzer import analyze_email
from phishing_analyzer.urls import analyze_url


def test_plain_text_credential_lure():
    result = analyze_email("Urgent: verify your account now. Click the link: http://192.0.2.4/login")
    assert result.classification == "Credential phishing"
    assert result.links_checked == 1
    assert result.links[0].host == "192.0.2.4"
    assert result.score >= 25


def test_checks_only_first_three_unique_links():
    text = " ".join(f"https://example{i}.test/path" for i in range(5))
    result = analyze_email(text)
    assert result.links_found == 5
    assert result.links_checked == 3
    assert result.metadata["links_skipped"] == 2


def test_duplicate_link_is_only_counted_once():
    result = analyze_email("https://example.com/a https://EXAMPLE.com/a")
    assert result.links_found == 1


def test_html_display_destination_mismatch():
    raw = """From: Service <notice@example.com>
Subject: Notice
Content-Type: text/html

<a href="https://evil.test/login">https://example.com/login</a>
"""
    result = analyze_email(raw)
    assert any(f.code == "DISPLAY_LINK_MISMATCH" for f in result.findings)
    assert result.links_found == 1
    assert result.links[0].host == "evil.test"


def test_header_authentication_failure():
    raw = """From: Bank <notice@bank.example>
Reply-To: reply@other.example
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail
Subject: Account alert

Verify your account now.
"""
    result = analyze_email(raw, trusted_authserv_ids={"mx.example"})
    codes = {f.code for f in result.findings}
    assert {"SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL", "REPLY_TO_MISMATCH"} <= codes


def test_shortener_and_http_are_flagged():
    link = analyze_url("http://bit.ly/verify-account")
    codes = {f.code for f in link.findings}
    assert {"SHORTENER", "HTTP_ONLY", "PHISHING_TERMS"} <= codes


def test_punycode_is_flagged():
    link = analyze_url("https://xn--pple-43d.example/login")
    assert any(f.code == "PUNYCODE" for f in link.findings)


def test_ipv6_loopback_does_not_crash_and_is_flagged():
    result = analyze_email("Open http://[::1]/login")
    assert result.links[0].host == "::1"
    assert any(f.code == "NON_PUBLIC_IP" for f in result.links[0].findings)


def test_userinfo_deception_is_preserved_and_flagged():
    result = analyze_email("Open https://trusted.example@evil.test/login")
    assert result.links[0].host == "evil.test"
    assert any(f.code == "USERINFO" for f in result.links[0].findings)
    assert result.risk != "low"


def test_explicit_credential_lure_with_link_is_not_low_risk():
    result = analyze_email("Urgent: verify your account now at https://secure-login-example.test/verify")
    assert result.classification == "Credential phishing"
    assert result.risk in {"suspicious", "likely_phishing", "high"}


def test_shortener_with_phishing_terms_is_suspicious():
    result = analyze_email("Open https://bit.ly/account-verify")
    assert result.risk == "suspicious"


def test_unquoted_html_href_is_extracted():
    raw = """From: Service <notice@example.com>
Subject: Notice
Content-Type: text/html

<a href=https://evil.test/login>Continue</a>
"""
    result = analyze_email(raw)
    assert result.links_found == 1
    assert result.links[0].host == "evil.test"


def test_no_links_is_supported():
    result = analyze_email("Hello, our meeting is at 3 PM tomorrow.")
    assert result.links_checked == 0
    assert result.risk == "low"


def test_empty_input_rejected():
    try:
        analyze_email("   ")
    except ValueError as exc:
        assert "empty" in str(exc).lower()
    else:
        raise AssertionError("empty input should fail")


def test_eml_subject_is_included():
    result = analyze_email("Subject: Urgent payment transfer\nFrom: boss@example.com\n\nPlease proceed")
    assert result.classification == "Business email compromise"
