from autofuzz.recon.secret_scanner import (
    _is_low_entropy_or_placeholder,
    _shannon_entropy,
    scan_many,
    scan_source,
)


# ---- basic detection (existing coverage, kept) -------------------------------

def test_detects_aws_access_key():
    src = "const key = 'AKIAABCDEFGHIJKLMNOP';"
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "AWS Access Key ID" for f in findings)


def test_detects_jwt():
    fake_jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGhpc2lzbm90cmVhbA"
    findings = scan_source(f"const t = '{fake_jwt}';", "test.js")
    assert any(f["type"] == "JWT" for f in findings)


def test_truncates_match():
    src = "const key = 'AKIAABCDEFGHIJKLMNOP';"
    findings = scan_source(src, "test.js")
    match = next(f["match"] for f in findings if f["type"] == "AWS Access Key ID")
    assert "..." in match
    assert len(match) < len("AKIAABCDEFGHIJKLMNOP")


def test_no_match_on_clean_source():
    findings = scan_source("const x = 1 + 1;", "test.js")
    assert findings == []


# ---- confidence scoring -------------------------------------------------------

def test_format_specific_matches_are_high_confidence():
    src = "const k = 'AKIAABCDEFGHIJKLMNOP'; const s = 'sk_live_51H8abcdefghijklmnopqrstuvwx';"
    findings = scan_source(src, "test.js")
    types = {f["type"]: f["confidence"] for f in findings}
    assert types["AWS Access Key ID"] == "high"
    assert types["Stripe Live Secret Key"] == "high"


def test_placeholder_value_downgrades_confidence():
    findings = scan_source('const apiKey = "your_api_key_here_1234567890";', "test.js")
    hit = next(f for f in findings if f["type"] == "Generic API Key Assignment")
    assert hit["confidence"] == "low"


def test_realistic_random_value_keeps_higher_confidence():
    findings = scan_source('const apiKey = "Zk9mP2qXrT7vB4nL8wJ1cH6sD3fY0aE5";', "test.js")
    hit = next(f for f in findings if f["type"] == "Generic API Key Assignment")
    assert hit["confidence"] == "medium"  # not downgraded to low


def test_repeated_character_value_is_placeholder():
    findings = scan_source('const secretToken = "xxxxxxxxxxxxxxxxxxxxxxxx";', "test.js")
    hit = next(f for f in findings if "Assignment" in f["type"])
    assert hit["confidence"] == "low"


def test_sequential_digits_value_is_placeholder():
    findings = scan_source('const token = "1234567890123456789012";', "test.js")
    hit = next(f for f in findings if "Assignment" in f["type"])
    assert hit["confidence"] == "low"


# ---- entropy helper -----------------------------------------------------------

def test_entropy_zero_for_empty_string():
    assert _shannon_entropy("") == 0.0


def test_entropy_higher_for_random_than_repeated():
    random_ish = "Zk9mP2qXrT7vB4nL8wJ1cH6sD3fY0aE5"
    repeated = "a" * 32
    assert _shannon_entropy(random_ish) > _shannon_entropy(repeated)


def test_is_placeholder_detects_known_keywords():
    assert _is_low_entropy_or_placeholder("changeme123") is True
    assert _is_low_entropy_or_placeholder("your_api_key_here") is True


def test_is_placeholder_false_for_realistic_secret():
    assert _is_low_entropy_or_placeholder("Zk9mP2qXrT7vB4nL8wJ1cH6sD3fY0aE5") is False


# ---- overlap deduplication -----------------------------------------------------

def test_specific_pattern_wins_over_generic_wrapping_match():
    """A generic 'token: "..."' pattern's span can fully wrap a more
    specific GitHub-token match — the specific, higher-confidence finding
    must win, not get silently swallowed by the generic one."""
    src = 'const githubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz12";'
    findings = scan_source(src, "test.js")
    types = [f["type"] for f in findings]
    assert "GitHub Token" in types
    # The generic assignment pattern's overlapping match must NOT also be
    # reported for the same span.
    assert "Generic Secret/Token Assignment" not in types


def test_no_duplicate_reports_for_same_span():
    src = "const key = 'AKIAABCDEFGHIJKLMNOP';"
    findings = scan_source(src, "test.js")
    aws_hits = [f for f in findings if f["type"] == "AWS Access Key ID"]
    assert len(aws_hits) == 1


# ---- broadened coverage --------------------------------------------------------

def test_detects_private_key_block():
    src = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "Private Key Block" for f in findings)


def test_detects_connection_string_credentials():
    src = 'const dbUrl = "postgres://admin:S3cr3tP4ss@db.internal.example.com:5432/prod";'
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "Credentials in Connection String" for f in findings)


def test_detects_gitlab_pat():
    src = "const t = 'glpat-A1b2C3d4E5f6G7h8I9j0';"
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "GitLab Personal Access Token" for f in findings)


def test_detects_npm_token():
    src = "const t = 'npm_" + "a" * 36 + "';"
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "NPM Access Token" for f in findings)


def test_detects_sendgrid_key():
    src = "const t = 'SG." + "a" * 22 + "." + "b" * 43 + "';"
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "SendGrid API Key" for f in findings)


def test_detects_discord_bot_token():
    part1 = "N" + "z" * 23   # 24 chars total
    part2 = "X" * 6            # 6 chars
    part3 = "a" * 27              # 27 chars
    src = f"const t = '{part1}.{part2}.{part3}';"
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "Discord Bot Token" for f in findings)


def test_detects_azure_storage_account_key():
    src = "AccountKey=" + "A" * 86 + "=="
    findings = scan_source(src, "test.js")
    assert any(f["type"] == "Azure Storage Account Key" for f in findings)


# ---- scan_many ------------------------------------------------------------------

def test_scan_many_tags_source_reference():
    sources = {
        "https://x/a.js": "const k = 'AKIAABCDEFGHIJKLMNOP';",
        "https://x/b.js": "nothing here",
    }
    findings = scan_many(sources)
    assert len(findings) == 1
    assert findings[0]["source"] == "https://x/a.js"


def test_scan_many_skips_empty_sources():
    findings = scan_many({"https://x/a.js": "", "https://x/b.js": None})
    assert findings == []
