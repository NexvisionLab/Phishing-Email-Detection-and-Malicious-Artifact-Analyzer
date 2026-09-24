from phishing_analyzer.urls import analyze_url


def test_cross_domain_nested_redirect_is_surfaced_without_fetching():
    result = analyze_url("https://login.example/continue?next=https%253A%252F%252Fevil.test%252Fsignin")
    codes = {finding.code for finding in result.findings}
    assert {"NESTED_REDIRECT", "CROSS_DOMAIN_REDIRECT"} <= codes
    assert result.score >= 32


def test_same_domain_redirect_is_lower_weight():
    result = analyze_url("https://accounts.example/redirect?url=https%3A%2F%2Flogin.accounts.example%2Fhome")
    codes = {finding.code for finding in result.findings}
    assert "NESTED_REDIRECT" in codes
    assert "CROSS_DOMAIN_REDIRECT" not in codes


def test_unrelated_url_parameter_is_not_treated_as_redirect():
    result = analyze_url("https://example.test/search?query=https%3A%2F%2Fother.test")
    assert "NESTED_REDIRECT" not in {finding.code for finding in result.findings}
