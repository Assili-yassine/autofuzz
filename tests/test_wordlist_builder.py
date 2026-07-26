from autofuzz.recon.wordlist_builder import (
    DEFAULT_SKIP_EXTENSIONS,
    build_wordlist,
    load_extra_wordlist,
    _normalize_entry,
    _param_signature,
    _split_path_and_query,
)


# ---- _split_path_and_query ---------------------------------------------------

def test_split_path_and_query_from_url():
    assert _split_path_and_query("https://example.com/api/v1/users?x=1") == ("api/v1/users", "x=1")


def test_split_path_and_query_from_raw_path():
    assert _split_path_and_query("/admin/panel") == ("admin/panel", "")


def test_split_path_and_query_without_leading_slash_unchanged():
    assert _split_path_and_query("admin/panel") == ("admin/panel", "")


def test_split_path_and_query_rejects_root():
    assert _split_path_and_query("/") is None
    assert _split_path_and_query("") is None


def test_split_path_and_query_raw_string_with_query():
    assert _split_path_and_query("search?q=kimi") == ("search", "q=kimi")


# ---- extension filtering (images / static assets) ---------------------------

def test_normalize_entry_drops_image_extension():
    seen: set[str] = set()
    assert _normalize_entry("https://example.com/logo.png", DEFAULT_SKIP_EXTENSIONS, seen) is None
    assert _normalize_entry("assets/photo.jpg", DEFAULT_SKIP_EXTENSIONS, seen) is None
    assert _normalize_entry("icon.svg", DEFAULT_SKIP_EXTENSIONS, seen) is None


def test_normalize_entry_keeps_non_asset_extension():
    seen: set[str] = set()
    assert _normalize_entry("api/export.json", DEFAULT_SKIP_EXTENSIONS, seen) == "api/export.json"


def test_skip_extensions_is_configurable():
    seen: set[str] = set()
    custom_skip = frozenset({".pdf"})
    assert _normalize_entry("logo.png", custom_skip, seen) == "logo.png"  # not in custom set
    assert _normalize_entry("report.pdf", custom_skip, seen) is None


# ---- parameter-set deduplication --------------------------------------------

def test_param_signature_ignores_values_uses_param_names():
    assert _param_signature("search", "q=kimi") == _param_signature("search", "q=home")


def test_param_signature_differs_for_different_param_names():
    assert _param_signature("search", "q=kimi") != _param_signature("search", "lang=en")


def test_param_signature_differs_when_extra_param_added():
    assert _param_signature("search", "q=kimi") != _param_signature("search", "q=kimi&f=15")


def test_normalize_entry_keeps_first_value_drops_later_same_signature():
    seen: set[str] = set()
    urls = [
        "https://www.domain.com/search?q=kimi",
        "https://www.domain.com/search?q=home",
        "https://www.domain.com/search?q=test",
        "https://www.domain.com/search?q=back",
    ]
    results = [_normalize_entry(u, DEFAULT_SKIP_EXTENSIONS, seen) for u in urls]
    assert results == ["search?q=kimi", None, None, None]


def test_normalize_entry_multi_param_scenario_from_request():
    """Exact scenario: mixing single-param and two-param variants of the
    same base path should keep exactly one example per distinct parameter
    NAME set — {q} and {q, f} — and drop every other repeat, including
    other values for a two-param combo."""
    seen: set[str] = set()
    urls = [
        "https://www.domain.com/search?q=kimi",
        "https://www.domain.com/search?q=home",
        "https://www.domain.com/search?q=test",
        "https://www.domain.com/search?q=back",
        "https://www.domain.com/search?q=kimi&f=15",
        "https://www.domain.com/search?q=home",
        "https://www.domain.com/search?q=test&f=38",
        "https://www.domain.com/search?q=back",
    ]
    results = [_normalize_entry(u, DEFAULT_SKIP_EXTENSIONS, seen) for u in urls]
    kept = [r for r in results if r]
    assert kept == ["search?q=kimi", "search?q=kimi&f=15"]


# ---- build_wordlist end-to-end ----------------------------------------------

def test_build_wordlist_no_leading_slashes(tmp_path):
    out = tmp_path / "wordlist.txt"
    build_wordlist(
        linkfinder_endpoints=["/api/v1/users"],
        js_endpoints=[], wayback_urls=[], gau_urls=[], katana_urls=[],
        output_path=out,
    )
    lines = out.read_text(encoding="utf-8").splitlines()
    assert "api" in lines
    assert "api/v1" in lines
    assert "api/v1/users" in lines
    assert not any(line.startswith("/") for line in lines)


def test_build_wordlist_multi_param_scenario_from_request(tmp_path):
    """End-to-end version of the exact request scenario."""
    out = tmp_path / "wordlist.txt"
    entries = build_wordlist(
        linkfinder_endpoints=[],
        js_endpoints=[],
        wayback_urls=[
            "https://www.domain.com/search?q=kimi",
            "https://www.domain.com/search?q=home",
            "https://www.domain.com/search?q=test",
            "https://www.domain.com/search?q=back",
            "https://www.domain.com/search?q=kimi&f=15",
            "https://www.domain.com/search?q=home",
            "https://www.domain.com/search?q=test&f=38",
            "https://www.domain.com/search?q=back",
        ],
        gau_urls=[], katana_urls=[],
        output_path=out,
    )
    param_entries = [e for e in entries if e.startswith("search?")]
    assert param_entries == ["search?q=kimi", "search?q=kimi&f=15"]
    assert "search" in entries  # bare directory still present


def test_build_wordlist_drops_image_extensions(tmp_path):
    out = tmp_path / "wordlist.txt"
    entries = build_wordlist(
        linkfinder_endpoints=[],
        js_endpoints=["assets/logo.png", "assets/photo.jpg", "assets/icon.svg", "api/data.json"],
        wayback_urls=[], gau_urls=[], katana_urls=[],
        output_path=out,
    )
    assert not any(e.endswith((".png", ".jpg", ".svg")) for e in entries)
    assert "api/data.json" in entries


def test_build_wordlist_merges_extra_wordlist_file(tmp_path):
    out = tmp_path / "wordlist.txt"
    entries = build_wordlist(
        linkfinder_endpoints=[], js_endpoints=[], wayback_urls=[], gau_urls=[], katana_urls=[],
        output_path=out,
        extra_wordlist=["custom/path.php", "/another/one"],
    )
    assert "custom/path.php" in entries
    assert "another/one" in entries


def test_build_wordlist_custom_skip_extensions_override(tmp_path):
    out = tmp_path / "wordlist.txt"
    entries = build_wordlist(
        linkfinder_endpoints=[], js_endpoints=["report.pdf", "logo.png"],
        wayback_urls=[], gau_urls=[], katana_urls=[],
        output_path=out,
        skip_extensions={".pdf"},
    )
    assert "report.pdf" not in entries
    assert "logo.png" in entries  # not in the custom skip set


# ---- load_extra_wordlist -----------------------------------------------------

def test_load_extra_wordlist_missing_file_returns_empty(tmp_path):
    assert load_extra_wordlist(str(tmp_path / "nope.txt")) == []


def test_load_extra_wordlist_reads_lines(tmp_path):
    f = tmp_path / "extra.txt"
    f.write_text("endpoint1/test.js\nendpoint2/test.js\n\n", encoding="utf-8")
    assert load_extra_wordlist(str(f)) == ["endpoint1/test.js", "endpoint2/test.js"]
