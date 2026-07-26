from autofuzz.utils import normalize_url, dedupe_lines, safe_slug, read_targets


def test_normalize_url_adds_scheme():
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_scheme():
    assert normalize_url("http://example.com/") == "http://example.com"


def test_normalize_url_strips_path():
    assert normalize_url("https://example.com/foo/bar") == "https://example.com"


def test_dedupe_lines_preserves_order():
    assert dedupe_lines(["b", "a", "b", "c", "a"]) == ["b", "a", "c"]


def test_dedupe_lines_strips_blank():
    assert dedupe_lines(["a", "", "  ", "b"]) == ["a", "b"]


def test_safe_slug():
    assert safe_slug("https://api.example.com:8443/path") == "api.example.com_8443"


def test_read_targets_from_single(tmp_path):
    targets = read_targets(None, "example.com")
    assert targets == ["https://example.com"]


def test_read_targets_from_file(tmp_path):
    f = tmp_path / "domains.txt"
    f.write_text("example.com\nhttps://foo.com\n# comment\n\n", encoding="utf-8")
    targets = read_targets(str(f), None)
    assert targets == ["https://example.com", "https://foo.com"]
