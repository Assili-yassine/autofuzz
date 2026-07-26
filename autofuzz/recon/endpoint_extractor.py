"""Stage 4: extract endpoint-shaped strings directly out of JS source.

This complements LinkFinder with a lightweight, dependency-free pass that
looks for common call patterns (fetch/axios/XHR/$.ajax), versioned API
paths, and window.location assignments.
"""
from __future__ import annotations

import logging
import re
import urllib.error
import urllib.request

from ..utils import dedupe_lines

_CALL_PATTERNS = [
    re.compile(r"""fetch\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""axios\.\w+\(\s*['"]([^'"]+)['"]"""),
    re.compile(r"""\$\.ajax\(\s*\{[^}]*url\s*:\s*['"]([^'"]+)['"]"""),
    re.compile(r"""new\s+XMLHttpRequest\(\)[^;]*\.open\(\s*['"]\w+['"]\s*,\s*['"]([^'"]+)['"]"""),
]

_PATH_PATTERN = re.compile(
    r"""['"](/(?:api|v[0-9]+|graphql|upload|login|admin|config)[a-zA-Z0-9_\-/]*)['"]"""
)

_LOCATION_PATTERN = re.compile(
    r"""(?:window\.location|location\.href|location\.pathname)\s*=\s*['"]([^'"]+)['"]"""
)


def extract_from_source(js_source: str) -> dict[str, list[str]]:
    calls: list[str] = []
    for pattern in _CALL_PATTERNS:
        calls.extend(pattern.findall(js_source))

    paths = _PATH_PATTERN.findall(js_source)
    locations = _LOCATION_PATTERN.findall(js_source)

    return {
        "calls": dedupe_lines(calls),
        "paths": dedupe_lines(paths),
        "locations": dedupe_lines(locations),
    }


def fetch_js_source(js_url: str, logger: logging.Logger, timeout: int, user_agent: str) -> str:
    req = urllib.request.Request(js_url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
            return raw.decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        logger.debug("Could not fetch JS %s: %s", js_url, exc)
        return ""


def extract_endpoints_from_js_files(
    js_files: list[str],
    logger: logging.Logger,
    timeout: int,
    user_agent: str,
) -> list[str]:
    """Fetch each JS file and pull out endpoint-like strings."""
    found: list[str] = []
    for js_url in js_files:
        source = fetch_js_source(js_url, logger, timeout, user_agent)
        if not source:
            continue
        extracted = extract_from_source(source)
        found.extend(extracted["calls"])
        found.extend(extracted["paths"])
        found.extend(extracted["locations"])
    return dedupe_lines(found)
