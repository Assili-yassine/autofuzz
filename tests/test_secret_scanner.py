from autofuzz.recon.secret_scanner import scan_source


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
