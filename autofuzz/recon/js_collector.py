"""Stage 2: collect JavaScript file URLs via katana, gau, wayback."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from ..utils import dedupe_lines, run_command


def _filter_js(urls: list[str]) -> list[str]:
    return [u for u in urls if u.split("?")[0].endswith(".js")]


def _same_domain(url: str, target_domain: str) -> bool:
    """True if url's netloc exactly matches the target domain (subdomain-exact)."""
    try:
        return urlparse(url).netloc == target_domain
    except ValueError:
        return False


def run_katana(url: str, domain: str, logger: logging.Logger, timeout: int) -> list[str]:
    """Crawl with katana, keeping only URLs on the exact target (sub)domain.

    katana will happily follow links off to other domains (CDNs, third-party
    scripts, etc.) — if the target was `subdomain.dom.com`, a result like
    `dom.com/home.html` is a different host and is dropped here.
    """
    result = run_command(
        ["katana", "-u", url, "-silent", "-jc", "-timeout", str(timeout)],
        logger,
        timeout=max(timeout * 10, 60),
    )
    if not result.ok:
        return []
    lines = dedupe_lines(result.stdout.splitlines())
    return [line for line in lines if _same_domain(line, domain)]


def run_gau(domain: str, logger: logging.Logger, timeout: int, proxy: str | None = None) -> list[str]:
    cmd = ["gau", "--subs", domain]
    if proxy:
        cmd += ["--proxy", proxy]
    result = run_command(cmd, logger, timeout=max(timeout * 10, 60))
    return dedupe_lines(result.stdout.splitlines()) if result.ok else []


def run_waybackurls(domain: str, logger: logging.Logger, timeout: int) -> list[str]:
    result = run_command(
        ["wayback", domain, "-p"],
        logger,
        timeout=max(timeout * 10, 60),
    )
    return dedupe_lines(result.stdout.splitlines()) if result.ok else []


def collect_js(
    url: str,
    domain: str,
    logger: logging.Logger,
    timeout: int,
    available: dict[str, str | None],
    proxy: str | None = None,
) -> dict[str, list[str]]:
    """Returns a dict with raw URL lists per tool plus a merged js_files list."""
    katana_urls = run_katana(url, domain, logger, timeout) if available.get("katana") else []
    gau_urls = run_gau(domain, logger, timeout, proxy=proxy) if available.get("gau") else []
    wayback_urls = run_waybackurls(domain, logger, timeout) if available.get("wayback") else []

    all_urls = katana_urls + gau_urls + wayback_urls
    js_files = dedupe_lines(_filter_js(all_urls))

    return {
        "katana_urls": katana_urls,
        "gau_urls": gau_urls,
        "wayback_urls": wayback_urls,
        "js_files": js_files,
    }
