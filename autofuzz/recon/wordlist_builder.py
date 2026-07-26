"""Stage 6: build a custom wordlist from everything discovered so far.

Entries are stored WITHOUT a leading slash (e.g. "endpoint1/test.js", not
"/endpoint1/test.js") because ffuf is invoked as `https://target/FUZZ`, so
FUZZ already sits right after the slash — a wordlist entry with its own
leading slash would produce a double slash in the fuzzed URL.

Two extra normalization passes happen here:

1. Low-value static assets (images, fonts, media, etc.) are dropped
   entirely — a hit on /logo.png carries no security signal and just wastes
   requests. Controlled by config.yaml: wordlists.skip_extensions.

2. Parameterized URLs from gau/wayback/katana commonly show up as many
   near-duplicates that only differ by query *value*, or by one extra
   parameter tacked on, e.g.:
       https://www.domain.com/search?q=kimi
       https://www.domain.com/search?q=home
       https://www.domain.com/search?q=test
       https://www.domain.com/search?q=back
       https://www.domain.com/search?q=kimi&f=15
       https://www.domain.com/search?q=home
       https://www.domain.com/search?q=test&f=38
       https://www.domain.com/search?q=back
   Grouping by (path, sorted parameter NAMES) — not values — collapses
   this to exactly two distinct signatures: {q} and {q, f}. Only the first
   URL seen for each signature is kept:
       search?q=kimi          (first with just {q})
       search?q=kimi&f=15     (first with {q, f})
   every other value for an already-seen parameter-name combination is
   dropped. The bare path (e.g. "search") is still added separately via
   the normal intermediate-segment expansion below, so plain directory
   fuzzing of that path is unaffected.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from ..utils import dedupe_lines

_PATH_LIKE = re.compile(r"^/[a-zA-Z0-9_\-./]*$")

# Extensions with no meaningful security signal for directory/endpoint
# fuzzing — hits on these are essentially always just static assets.
# Override via config.yaml: wordlists.skip_extensions.
DEFAULT_SKIP_EXTENSIONS = frozenset({
    # images
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff", ".avif",
    # fonts
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    # styling / source maps
    ".css", ".map",
    # media
    ".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".wav",
})


def _split_path_and_query(candidate: str) -> tuple[str, str] | None:
    """Pull (path, query) out of a URL or raw path/path?query string.

    Path is returned with no leading/trailing slash. Returns None if there's
    no usable path at all.
    """
    candidate = candidate.strip()
    if not candidate:
        return None

    if candidate.startswith("http://") or candidate.startswith("https://"):
        parsed = urlparse(candidate)
        path, query = parsed.path, parsed.query
    elif "?" in candidate:
        path, _, query = candidate.partition("?")
    else:
        path, query = candidate, ""

    path = path.split("#")[0].strip("/")
    query = query.split("#")[0]

    if not path:
        return None
    if not _PATH_LIKE.match("/" + path):
        return None
    return path, query


def _has_skippable_extension(path: str, skip_extensions: frozenset[str]) -> bool:
    return Path(path).suffix.lower() in skip_extensions


def _param_signature(path: str, query: str) -> str:
    """Dedup key covering the path plus the *set* of parameter names (not
    their values or how many there are per URL), so all of:
        search?q=kimi
        search?q=home
    collapse to signature "search?q", while
        search?q=kimi&f=15
    is a genuinely different signature "search?f,q" (different parameter
    *set*) and is kept as its own example."""
    param_names = sorted(parse_qs(query, keep_blank_values=True).keys())
    return f"{path}?{','.join(param_names)}"


def _normalize_entry(
    candidate: str,
    skip_extensions: frozenset[str],
    seen_param_signatures: set[str],
) -> str | None:
    """Return a wordlist entry for `candidate`, or None if it should be
    dropped (empty/invalid, a skippable static asset, or a repeat for an
    already-seen parameter-name combination on the same path)."""
    split = _split_path_and_query(candidate)
    if split is None:
        return None
    path, query = split

    if _has_skippable_extension(path, skip_extensions):
        return None

    if not query:
        return path

    signature = _param_signature(path, query)
    if signature in seen_param_signatures:
        return None  # already kept one example of this exact parameter-name combo
    seen_param_signatures.add(signature)
    return f"{path}?{query}"


def load_extra_wordlist(path: str | None, logger: logging.Logger | None = None) -> list[str]:
    """Read a user-supplied wordlist file (-w) so its lines feed into the merge."""
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        if logger:
            logger.warning("[yellow]-w wordlist file not found: %s (skipping)[/]", path)
        return []
    return [line.strip() for line in p.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip()]


def build_wordlist(
    linkfinder_endpoints: list[str],
    js_endpoints: list[str],
    wayback_urls: list[str],
    gau_urls: list[str],
    katana_urls: list[str],
    output_path: Path,
    extra_wordlist: list[str] | None = None,
    skip_extensions: frozenset[str] | set[str] | None = None,
) -> list[str]:
    """Merge every discovered source (plus an optional -w file) into one
    deduplicated, verified, sorted wordlist with no leading slashes.

    - Entries with a low-value static-asset extension (images, fonts, etc.)
      are dropped entirely.
    - For parameterized URLs, only one example per (path, parameter-NAME
      set) is kept; other values — or other URLs sharing that exact same
      set of parameter names — are dropped. A URL with an *additional*
      parameter (a different name set) is treated as a distinct endpoint
      and kept as its own example.
    """
    skip_ext = frozenset(e.lower() for e in (skip_extensions or DEFAULT_SKIP_EXTENSIONS))

    raw = (
        linkfinder_endpoints
        + js_endpoints
        + wayback_urls
        + gau_urls
        + katana_urls
        + list(extra_wordlist or [])
    )

    paths: list[str] = []
    seen_param_signatures: set[str] = set()
    for item in raw:
        entry = _normalize_entry(item, skip_ext, seen_param_signatures)
        if not entry:
            continue
        paths.append(entry)

        # Also add the base path and each of its intermediate segments, e.g.
        # api/v1/users -> api, api/v1, api/v1/users. This runs even when
        # `entry` itself is parameterized (path?query), so the bare
        # directory is still available for plain directory fuzzing.
        base_path = entry.split("?", 1)[0]
        parts = base_path.split("/")
        for i in range(1, len(parts) + 1):
            paths.append("/".join(parts[:i]))

    paths = dedupe_lines(paths)
    paths.sort()

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(paths), encoding="utf-8")
    return paths
