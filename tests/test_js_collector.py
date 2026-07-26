from autofuzz.recon.js_collector import _same_domain


def test_same_domain_matches_exact():
    assert _same_domain("https://subdomain.dom.com/index.html", "subdomain.dom.com") is True


def test_same_domain_rejects_parent_domain():
    assert _same_domain("https://dom.com/home.html", "subdomain.dom.com") is False


def test_same_domain_rejects_other_subdomain():
    assert _same_domain("https://other.dom.com/x", "subdomain.dom.com") is False


def test_same_domain_handles_malformed_url():
    assert _same_domain("not a url ::::", "subdomain.dom.com") is False
