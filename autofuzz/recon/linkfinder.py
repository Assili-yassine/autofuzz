"""Stage 3: run LinkFinder against each discovered JS file.

LinkFinder (https://github.com/GerbenJavado/LinkFinder) must be installed
separately; this module simply shells out to it (`linkfinder.py -i URL -o cli`)
and parses the endpoints it prints.
"""
from __future__ import annotations

import logging
from pathlib import Path

from ..utils import dedupe_lines, run_command


def run_linkfinder(js_url: str, logger: logging.Logger, timeout: int) -> list[str]:
    result = run_command(
        ["linkfinder", "-i", js_url, "-o", "cli"],
        logger,
        timeout=timeout,
    )
    if not result.ok:
        return []
    endpoints = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return dedupe_lines(endpoints)


def run_linkfinder_batch(
    js_files: list[str],
    logger: logging.Logger,
    timeout: int,
    output_path: Path,
    has_linkfinder: bool,
) -> list[str]:
    if not has_linkfinder or not js_files:
        return []
    all_endpoints: list[str] = []
    for js_url in js_files:
        endpoints = run_linkfinder(js_url, logger, timeout)
        all_endpoints.extend(endpoints)

    all_endpoints = dedupe_lines(all_endpoints)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(all_endpoints), encoding="utf-8")
    return all_endpoints
