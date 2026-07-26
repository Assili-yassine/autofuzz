"""Stage 5: flag substrings that *look like* credentials in already-fetched JS.

These are the same publicly documented pattern families used by tools like
gitleaks/truffleHog for triage. AutoFuzz never verifies, uses, or exfiltrates
any matched value — it only reports (file, pattern-name, match, confidence)
so a tester can confirm and get the owner to rotate the real secret. Matches
are truncated in the report to avoid needlessly persisting full key material.

Compared to a plain pattern list, this scanner adds three things that
matter a lot for signal quality on real-world JS bundles:

1. **Much broader coverage** — cloud providers, CI/package registries, chat
   platforms, payment processors, database connection strings, and raw
   private-key blocks, not just a handful of the most common formats.

2. **Confidence scoring, not a binary yes/no.** Generic patterns (a
   "secret"/"token"/"password" assignment, a bearer token) are prone to
   matching placeholder values (`"apiKey": "your_api_key_here"`) just as
   loudly as real ones. Every finding gets a "high"/"medium"/"low"
   confidence: format-specific patterns with a fixed, distinctive prefix
   (AKIA..., sk_live_..., ghp_...) are high confidence; generic
   keyword+value patterns are downgraded to medium/low when the captured
   value looks like a placeholder (common dummy words, sequential
   characters, a single repeated character) or has low Shannon entropy for
   its length (real keys/tokens are high-entropy; "xxxxxxxxxxxxxxxx" is
   not). Nothing is silently dropped — low-confidence hits are still
   reported, just labeled, so a human reviewer isn't misled either way.

3. **Overlap deduplication.** A single real match (e.g. a bearer-prefixed
   JWT) can satisfy more than one pattern at once. Only the most specific
   (longest, earliest) match at a given position is kept, so the same
   credential doesn't show up multiple times under different labels.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

Confidence = str  # "high" | "medium" | "low"


@dataclass(frozen=True)
class _PatternSpec:
    name: str
    pattern: re.Pattern[str]
    confidence: Confidence = "high"
    # Which regex group holds the actual secret value to entropy-check and
    # placeholder-check (0 = the whole match). Format-specific patterns with
    # a distinctive fixed prefix don't need this — they're high confidence
    # by construction. Generic keyword+value patterns use this to downgrade
    # confidence for placeholder-looking captures.
    value_group: int = 0
    heuristic: bool = False


# ---------------------------------------------------------------------------
# Pattern library, most specific/distinctive first so overlap dedup prefers
# a precise provider match over a generic catch-all at the same position.
# ---------------------------------------------------------------------------
_PATTERNS: list[_PatternSpec] = [
    # ---- Cloud providers ---------------------------------------------------
    _PatternSpec("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    _PatternSpec(
        "AWS Secret Access Key (heuristic)",
        re.compile(r"""(?i)aws(.{0,20})?(secret|key)(.{0,3})?['"]\s*[:=]\s*['"]([0-9a-zA-Z/+]{40})['"]"""),
        confidence="medium", value_group=4, heuristic=True,
    ),
    _PatternSpec("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    _PatternSpec("Google OAuth Client Secret", re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b")),
    _PatternSpec("Firebase Realtime DB URL", re.compile(r"\b[a-z0-9-]+\.firebaseio\.com\b"), confidence="medium"),
    _PatternSpec("Firebase Cloud Messaging Key", re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b")),
    _PatternSpec(
        "Azure Storage Account Key",
        re.compile(r"(?i)accountkey\s*=\s*([A-Za-z0-9+/]{86}==)"),
        value_group=1,
    ),
    _PatternSpec("Azure SAS Token", re.compile(r"\bsv=\d{4}-\d{2}-\d{2}&s[ist]=[^&\s'\"]+&"), confidence="medium"),

    # ---- Payments -----------------------------------------------------------
    _PatternSpec("Stripe Live Secret Key", re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")),
    _PatternSpec("Stripe Restricted Key", re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b")),
    _PatternSpec("Stripe Publishable Key", re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), confidence="medium"),
    _PatternSpec("Square Access Token", re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b")),
    _PatternSpec("Square OAuth Secret", re.compile(r"\bsq0csp-[0-9A-Za-z\-_]{43}\b")),
    _PatternSpec(
        "PayPal/Braintree Access Token",
        re.compile(r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ),

    # ---- Chat / collaboration platforms -------------------------------------
    _PatternSpec("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    _PatternSpec("Slack App-Level Token", re.compile(r"\bxapp-[0-9A-Za-z-]{10,}\b")),
    _PatternSpec(
        "Slack/Discord Webhook",
        re.compile(r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks)/[A-Za-z0-9/_-]+"),
    ),
    _PatternSpec("Discord Bot Token", re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b")),

    # ---- Source control / package registries ---------------------------------
    _PatternSpec("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    _PatternSpec("GitHub Fine-Grained PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b")),
    _PatternSpec("GitLab Personal Access Token", re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b")),
    _PatternSpec("NPM Access Token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b")),
    _PatternSpec("PyPI API Token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z\-_]{50,}\b")),
    _PatternSpec("Docker Hub / Registry Auth (base64 config)", re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'), confidence="medium"),

    # ---- Comms / email / SMS ---------------------------------------------------
    _PatternSpec("SendGrid API Key", re.compile(r"\bSG\.[A-Za-z0-9_\-\.]{22}\.[A-Za-z0-9_\-\.]{43}\b")),
    _PatternSpec("Mailgun API Key", re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), confidence="medium"),
    _PatternSpec("Mailchimp API Key", re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b")),
    _PatternSpec("Twilio API Key SID", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    _PatternSpec("Twilio Account SID", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), confidence="medium"),

    # ---- Generic secret material --------------------------------------------
    _PatternSpec(
        "Private Key Block",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP)?\s?PRIVATE KEY-----", re.MULTILINE),
    ),
    _PatternSpec(
        "Credentials in Connection String",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:'\"]+:[^/\s@'\"]+@[^/\s'\"]+"),
    ),
    _PatternSpec(
        "Basic Auth Credentials in URL",
        re.compile(r"\bhttps?://[^/\s:'\"]+:[^/\s@'\"]+@[^/\s'\"]+"),
        confidence="medium",
    ),
    _PatternSpec("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    _PatternSpec(
        "Generic Bearer Token",
        re.compile(r"""(?i)bearer\s+([a-z0-9\-_.=]{15,})"""),
        confidence="medium", value_group=1, heuristic=True,
    ),
    _PatternSpec(
        "Generic API Key Assignment",
        re.compile(r"""(?i)(?:api[_-]?key|apikey)['"]?\s*[:=]\s*['"]([0-9a-zA-Z\-_]{16,})['"]"""),
        confidence="medium", value_group=1, heuristic=True,
    ),
    _PatternSpec(
        "Generic Secret/Token Assignment",
        re.compile(
            r"""(?i)(?:secret|token|auth[_-]?key|access[_-]?key)['"]?\s*[:=]\s*['"]([0-9a-zA-Z\-_/+]{16,})['"]"""
        ),
        confidence="medium", value_group=1, heuristic=True,
    ),
    _PatternSpec(
        "Generic Password Assignment",
        re.compile(r"""(?i)(?:password|passwd|pwd)['"]?\s*[:=]\s*['"]([^\s'"]{6,})['"]"""),
        confidence="low", value_group=1, heuristic=True,
    ),
]


# ---------------------------------------------------------------------------
# False-positive filtering for heuristic/generic patterns
# ---------------------------------------------------------------------------
_PLACEHOLDER_KEYWORDS = (
    "example", "changeme", "change_me", "your_api_key", "your-api-key",
    "insert_key_here", "replace_me", "placeholder", "dummy", "sample",
    "test_key", "testkey", "fake", "xxxxxxxx", "todo", "tbd", "n/a",
    "notasecret", "not_a_secret", "redacted", "undefined", "null",
)


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


_DIGIT_CYCLE = "0123456789" * 6
_ALPHA_CYCLE = "abcdefghijklmnopqrstuvwxyz" * 3


def _is_sequential_run(value: str) -> bool:
    """True if `value` is a straight ascending/descending run of digits or
    letters (e.g. "1234567890123456789012", "abcdefghijklmnop"), regardless
    of length or where in the cycle it starts."""
    lowered = value.lower()
    if lowered.isdigit():
        return lowered in _DIGIT_CYCLE or lowered in _DIGIT_CYCLE[::-1]
    if lowered.isalpha():
        return lowered in _ALPHA_CYCLE or lowered in _ALPHA_CYCLE[::-1]
    return False


def _is_low_entropy_or_placeholder(value: str) -> bool:
    """True if `value` looks like a dummy/placeholder rather than a real
    secret: a known placeholder keyword, an all-repeated character, a
    simple sequential run (0123..., abcdef...) of any length, or low
    randomness overall relative to its length."""
    lowered = value.lower()
    if any(kw in lowered for kw in _PLACEHOLDER_KEYWORDS):
        return True
    if len(set(lowered)) <= 2:  # e.g. "aaaaaaaaaaaa", "0101010101"
        return True
    if _is_sequential_run(value):
        return True

    # Real API keys/tokens are high-entropy; short repetitive or patterned
    # strings score low. Threshold scales gently with length so short
    # generic-pattern captures aren't unfairly flagged.
    entropy = _shannon_entropy(value)
    threshold = 2.0 if len(value) < 24 else 2.8
    return entropy < threshold


def _truncate(match: str, keep: int = 8) -> str:
    match = match.strip()
    if len(match) <= keep * 2:
        return match
    return f"{match[:keep]}...{match[-4:]}"


def _resolve_confidence(spec: _PatternSpec, m: re.Match[str]) -> Confidence:
    if not spec.heuristic:
        return spec.confidence
    try:
        value = m.group(spec.value_group)
    except IndexError:  # defensive: pattern/group index mismatch
        return spec.confidence
    if not value:
        return spec.confidence
    if _is_low_entropy_or_placeholder(value):
        # Downgrade one step: high->medium, medium->low, low stays low.
        return {"high": "medium", "medium": "low", "low": "low"}[spec.confidence]
    return spec.confidence


def _spans_overlap(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _dedupe_overlaps(raw: list[tuple[int, int, dict, tuple]]) -> list[dict]:
    """Keep the most specific match covering each region of text.

    Priority (lowest sorts first, wins): non-heuristic/format-specific
    patterns beat generic keyword+value patterns outright, regardless of
    which span is longer — a generic `token: "..."` match that happens to
    wrap around a precise `ghp_...` GitHub token match should never bury
    it. Ties within the same specificity tier prefer the longer, then
    earlier, match. Once priority order is resolved, any candidate whose
    span overlaps at all with an already-accepted span is dropped — not
    just full containment, since a generic match's span typically extends
    a little past the specific one (e.g. it also covers the surrounding
    quotes/keyword).
    """
    raw.sort(key=lambda item: item[3])
    accepted: list[tuple[int, int]] = []
    kept: list[tuple[int, dict]] = []
    for start, end, finding, _priority in raw:
        if any(_spans_overlap(start, end, a_start, a_end) for a_start, a_end in accepted):
            continue
        accepted.append((start, end))
        kept.append((start, finding))
    kept.sort(key=lambda item: item[0])  # report in source order, top to bottom
    return [finding for _start, finding in kept]


def scan_source(source: str, source_ref: str) -> list[dict[str, str]]:
    """Scan one blob of JS text and return findings (with truncated match).

    Each finding: {"type", "match", "source", "confidence"}. Confidence is
    "high" for distinctive format-specific patterns, "medium"/"low" for
    generic keyword+value patterns depending on how random/non-placeholder
    the captured value looks. Overlapping matches at the same position are
    deduplicated, keeping the most specific one.
    """
    if not source:
        return []

    raw: list[tuple[int, int, dict, tuple]] = []
    for spec in _PATTERNS:
        for m in spec.pattern.finditer(source):
            confidence = _resolve_confidence(spec, m)
            start, end = m.start(), m.end()
            # Priority: non-heuristic (format-specific) patterns always
            # beat heuristic/generic ones; ties prefer longer, then
            # earlier matches. Lower tuple sorts first == wins.
            priority = (0 if not spec.heuristic else 1, -(end - start), start)
            raw.append((
                start, end,
                {
                    "type": spec.name,
                    "match": _truncate(m.group(0)),
                    "source": source_ref,
                    "confidence": confidence,
                },
                priority,
            ))
    return _dedupe_overlaps(raw)


def scan_many(sources: dict[str, str]) -> list[dict[str, str]]:
    """sources: mapping of {url_or_ref: js_text}."""
    findings: list[dict[str, str]] = []
    for ref, text in sources.items():
        if text:
            findings.extend(scan_source(text, ref))
    return findings
