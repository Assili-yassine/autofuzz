from autofuzz.recon.endpoint_extractor import extract_from_source


def test_extracts_fetch_call():
    src = "fetch('/api/v1/users').then(r => r.json())"
    result = extract_from_source(src)
    assert "/api/v1/users" in result["calls"]


def test_extracts_axios_call():
    src = "axios.get('/api/v2/orders')"
    result = extract_from_source(src)
    assert "/api/v2/orders" in result["calls"]


def test_extracts_versioned_path():
    src = "const u = '/graphql/internal';"
    result = extract_from_source(src)
    assert "/graphql/internal" in result["paths"]


def test_extracts_location_assignment():
    src = "window.location = '/admin/dashboard';"
    result = extract_from_source(src)
    assert "/admin/dashboard" in result["locations"]


def test_no_false_positive_on_plain_string():
    src = "const greeting = 'hello world';"
    result = extract_from_source(src)
    assert result["calls"] == []
    assert result["paths"] == []
