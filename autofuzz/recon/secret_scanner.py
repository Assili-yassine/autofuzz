"""Stage 5: flag substrings that *look like* credentials in already-fetched JS.

These are the same publicly documented pattern families used by tools like
gitleaks/truffleHog for triage. AutoFuzz never verifies, uses, or exfiltrates
any matched value — it only reports (file, pattern-name, match) so a tester
can confirm and get the owner to rotate the real secret. Matches are
truncated in the report to avoid needlessly persisting full key material.
"""
from __future__ import annotations

import re

_SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "AWS Access Key ID": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "AWS Secret Access Key (heuristic)": re.compile(
        r"""(?i)aws(.{0,20})?(secret|key)(.{0,3})?['"]\s*[:=]\s*['"][0-9a-zA-Z/+]{40}['"]"""
    ),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "Firebase URL": re.compile(r"\b[a-z0-9-]+\.firebaseio\.com\b"),
    "Stripe Live Key": re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    "Stripe Publishable Key": re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "Slack/Discord Webhook": re.compile(
        r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks)/[A-Za-z0-9/_-]+"
    ),
    "GitHub Token": re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"),
    "Generic Bearer Token": re.compile(r"""(?i)bearer\s+[a-z0-9\-_.=]{15,}"""),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    "Generic API Key Assignment": re.compile(
        r"""(?i)(api[_-]?key|apikey|secret)['"]?\s*[:=]\s*['"][0-9a-zA-Z\-_]{16,}['"]"""
    ),
}


def _truncate(match: str, keep: int = 8) -> str:
    if len(match) <= keep * 2:
        return match
    return f"{match[:keep]}...{match[-4:]}"


def scan_source(source: str, source_ref: str) -> list[dict[str, str]]:
    """Scan one blob of JS text and return findings (with truncated match)."""
    findings: list[dict[str, str]] = []
    for name, pattern in _SECRET_PATTERNS.items():
        for m in pattern.finditer(source):
            findings.append(
                {
                    "type": name,
                    "match": _truncate(m.group(0)),
                    "source": source_ref,
                }
            )
    return findings


def scan_many(sources: dict[str, str]) -> list[dict[str, str]]:
    """sources: mapping of {url_or_ref: js_text}."""
    findings: list[dict[str, str]] = []
    for ref, text in sources.items():
        if text:
            findings.extend(scan_source(text, ref))
    return findings
