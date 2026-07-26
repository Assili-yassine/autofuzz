"""Global fuzzing summary, generated only for -i (multi-domain) runs.

Produces a single text file shaped like:

    ===== https://tldkit.ascio.com =====
    %5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwinnt%5cwin.ini [Status: 403, Size: 312]
    ?mobile=1&mp_idx=%22;$.getScript(%27//127.0.0.1/z%27);// [Status: 301, Size: 122]
    ===== https://toad.exacthosting.com =====
    .htaccess               [Status: 403, Size: 10402]
    ...
"""
from __future__ import annotations

from pathlib import Path

from ..models import TargetResult


def _fuzz_value(item: dict) -> str:
    """Pull the raw fuzzed value (ffuf's `input.FUZZ`) out of a result entry."""
    fuzz = (item.get("input") or {}).get("FUZZ")
    if fuzz:
        return fuzz
    # Fallback: derive from the URL if `input` wasn't present in the JSON.
    url = item.get("url", "")
    return url.rsplit("/", 1)[-1] if url else ""


def render_global_fuzzing_report(results: list[TargetResult], output_path: Path) -> None:
    lines: list[str] = []
    for r in results:
        lines.append(f"===== {r.url} =====")
        for item in r.interesting:
            value = _fuzz_value(item)
            status = item.get("status")
            size = item.get("length")
            lines.append(f"{value:<24} [Status: {status}, Size: {size}]")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
