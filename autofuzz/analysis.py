"""Stages 12-14: classify ffuf results, highlight interesting content, fingerprint tech."""
from __future__ import annotations

import re

from .config import AutoFuzzConfig

_TECH_SIGNATURES: dict[str, re.Pattern[str]] = {
    "nginx": re.compile(r"nginx", re.I),
    "Apache": re.compile(r"apache", re.I),
    "IIS": re.compile(r"microsoft-iis", re.I),
    "Cloudflare": re.compile(r"cloudflare", re.I),
    "Akamai": re.compile(r"akamaighost", re.I),
    "Fastly": re.compile(r"fastly", re.I),
    "AWS": re.compile(r"amazons3|awselb|cloudfront", re.I),
    "Laravel": re.compile(r"laravel_session|x-powered-by:\s*php", re.I),
    "Spring": re.compile(r"spring|jsessionid", re.I),
    "ASP.NET": re.compile(r"asp\.net|x-aspnet-version", re.I),
    "Express": re.compile(r"x-powered-by:\s*express", re.I),
    "Django": re.compile(r"csrftoken|django", re.I),
}


def classify_interesting(ffuf_results: list[dict], cfg: AutoFuzzConfig) -> list[dict]:
    match_codes = set(cfg.get("ffuf", "match_codes", default=[]))
    filter_codes = set(cfg.get("ffuf", "filter_codes", default=[]))
    keywords = [k.lower() for k in cfg.get("content_keywords", default=[])]

    interesting: list[dict] = []
    for r in ffuf_results:
        status = r.get("status")
        if status in filter_codes:
            continue
        if match_codes and status not in match_codes:
            continue
        url = (r.get("url") or "").lower()
        reasons = []
        if status in match_codes:
            reasons.append(f"status {status}")
        for kw in keywords:
            if kw in url:
                reasons.append(f"keyword '{kw}'")
        if reasons:
            interesting.append({**r, "reasons": reasons})
    return interesting


def detect_technologies(headers_blob: str) -> list[str]:
    """headers_blob: concatenated response headers (and optionally body) text."""
    found = []
    for name, pattern in _TECH_SIGNATURES.items():
        if pattern.search(headers_blob):
            found.append(name)
    return sorted(set(found))
