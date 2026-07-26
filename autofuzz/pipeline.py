"""Orchestrates the per-target pipeline (stages 1 through 10)."""
from __future__ import annotations

import logging
import time
from pathlib import Path
from urllib.parse import urlparse

from .analysis import classify_interesting, detect_technologies
from .config import AutoFuzzConfig
from .fuzz.api_fuzzer import discover_api_endpoints
from .fuzz.ffuf_runner import run_ffuf
from .models import TargetResult
from .recon.endpoint_extractor import extract_from_source, fetch_js_source
from .recon.httpx_check import check_alive
from .recon.js_collector import collect_js
from .recon.linkfinder import run_linkfinder_batch
from .recon.secret_scanner import scan_many
from .recon.wordlist_builder import build_wordlist, load_extra_wordlist
from .status import StatusReporter
from .utils import safe_slug


def run_pipeline_for_target(
    url: str,
    cfg: AutoFuzzConfig,
    logger: logging.Logger,
    reporter: StatusReporter,
    available_bins: dict[str, str | None],
    output_root: Path,
    proxy: str | None = None,
    cookies: str | None = None,
    headers: list[str] | None = None,
    extra_wordlist_path: str | None = None,
    save_wordlist: bool = False,
) -> TargetResult:
    start = time.time()
    slug = safe_slug(url)
    target_dir = output_root / slug
    result = TargetResult(url=url, slug=slug, output_dir=target_dir)
    result.ensure_dirs()

    timeout = cfg.get("general", "timeout", default=10)
    user_agent = cfg.get("general", "user_agent", default="AutoFuzz/1.0")

    # ---- Stage 1: liveness -------------------------------------------------
    t0 = time.time()
    reporter.stage_start(url, 1)
    result.alive = check_alive(url, logger, timeout, user_agent, bool(available_bins.get("httpx")))
    elapsed = time.time() - t0
    if not result.alive:
        reporter.dead(url, elapsed)
        result.elapsed_seconds = time.time() - start
        return result
    reporter.alive(url, elapsed)

    # ---- Stage 2: JS collection ---------------------------------------------
    t0 = time.time()
    reporter.stage_start(url, 2)
    domain = urlparse(url).netloc
    js_data = collect_js(url, domain, logger, timeout, available_bins, proxy=proxy)
    result.js_files = js_data["js_files"]
    result.katana_urls = js_data["katana_urls"]
    result.gau_urls = js_data["gau_urls"]
    result.wayback_urls = js_data["wayback_urls"]
    elapsed = time.time() - t0
    reporter.stage_done(
        url, 2, elapsed,
        detail=(
            f"{len(result.js_files)} JS files "
            f"(katana:{len(result.katana_urls)} gau:{len(result.gau_urls)} wayback:{len(result.wayback_urls)})"
        ),
    )

    # ---- Stage 3: LinkFinder -------------------------------------------------
    t0 = time.time()
    if not available_bins.get("linkfinder"):
        reporter.stage_skipped(url, 3, "linkfinder binary not found")
        result.linkfinder_endpoints = []
    else:
        reporter.stage_start(url, 3, label=f"LinkFinder on {len(result.js_files)} JS files")
        result.linkfinder_endpoints = run_linkfinder_batch(
            result.js_files, logger, timeout, target_dir / ".linkfinder_tmp.txt", True
        )
        (target_dir / ".linkfinder_tmp.txt").unlink(missing_ok=True)
        elapsed = time.time() - t0
        reporter.stage_done(url, 3, elapsed, detail=f"{len(result.linkfinder_endpoints)} endpoints")

    # ---- Stage 4 + 5: fetch JS, extract endpoints + scan for secrets --------
    t0 = time.time()
    reporter.stage_start(url, 4, label=f"Fetching + parsing {min(len(result.js_files), 200)} JS files")
    js_sources: dict[str, str] = {}
    for js_url in result.js_files[:200]:  # sane cap to avoid unbounded fetch storms
        js_sources[js_url] = fetch_js_source(js_url, logger, timeout, user_agent)

    js_endpoints: list[str] = []
    for src in js_sources.values():
        if not src:
            continue
        extracted = extract_from_source(src)
        js_endpoints.extend(extracted["calls"] + extracted["paths"] + extracted["locations"])
    result.js_endpoints = sorted(set(js_endpoints))
    elapsed = time.time() - t0
    reporter.stage_done(url, 4, elapsed, detail=f"{len(result.js_endpoints)} endpoints")

    t0 = time.time()
    reporter.stage_start(url, 5)
    result.secrets = scan_many(js_sources)
    (target_dir / "secret.txt").write_text(
        "\n".join(f"{s['type']}\t{s['match']}\t{s['source']}" for s in result.secrets),
        encoding="utf-8",
    )
    elapsed = time.time() - t0
    reporter.stage_done(url, 5, elapsed, detail=f"{len(result.secrets)} hits")

    # ---- Stage 6: wordlist ----------------------------------------------------
    t0 = time.time()
    reporter.stage_start(url, 6)
    extra_lines = load_extra_wordlist(extra_wordlist_path, logger)
    wordlist_path = target_dir / "custom_wordlist.txt"
    wordlist_entries = build_wordlist(
        result.linkfinder_endpoints,
        result.js_endpoints,
        result.wayback_urls,
        result.gau_urls,
        result.katana_urls,
        wordlist_path,
        extra_wordlist=extra_lines,
        skip_extensions=set(cfg.get("wordlists", "skip_extensions", default=[]) or []) or None,
    )
    result.wordlist_path = wordlist_path
    elapsed = time.time() - t0
    reporter.stage_done(url, 6, elapsed, detail=f"{len(wordlist_entries)} entries")

    # ---- Stage 7: ffuf ----------------------------------------------------------
    t0 = time.time()
    if not available_bins.get("ffuf"):
        reporter.stage_skipped(url, 7, "ffuf binary not found")
        result.ffuf_results = []
    else:
        ffuf_threads = cfg.get("ffuf", "threads", default=40)
        reporter.stage_start(
            url, 7,
            label=f"ffuf ({ffuf_threads} threads, {len(wordlist_entries)} wordlist entries" +
                  (f", proxy {proxy}" if proxy else "") + ")",
        )
        extensions = cfg.get("extensions", default=[])
        result.ffuf_results = run_ffuf(
            url,
            wordlist_path,
            target_dir,
            cfg,
            logger,
            True,
            extensions=extensions,
            proxy=proxy,
            cookies=cookies,
            headers=headers,
        )
        elapsed = time.time() - t0
        reporter.stage_done(url, 7, elapsed, detail=f"{len(result.ffuf_results)} results")

    # The generated wordlist is a temporary fuzzing artifact — delete it
    # after the run unless the user passed -s/--save-wordlist.
    if not save_wordlist:
        wordlist_path.unlink(missing_ok=True)
        result.wordlist_path = None

    # ---- Stage 8: API discovery --------------------------------------------------
    t0 = time.time()
    reporter.stage_start(url, 8)
    result.api_endpoints = discover_api_endpoints(url, cfg, logger)
    elapsed = time.time() - t0
    reporter.stage_done(url, 8, elapsed, detail=f"{len(result.api_endpoints)} endpoints")

    # ---- Stage 9: interesting / keyword classification ----------------------------
    t0 = time.time()
    reporter.stage_start(url, 9)
    result.interesting = classify_interesting(result.ffuf_results, cfg)
    (target_dir / "interesting.txt").write_text(
        "\n".join(f"{i.get('status')}\t{i.get('url')}\t{','.join(i.get('reasons', []))}" for i in result.interesting),
        encoding="utf-8",
    )
    elapsed = time.time() - t0
    reporter.stage_done(url, 9, elapsed, detail=f"{len(result.interesting)} interesting")

    # ---- Stage 10: technology fingerprinting ---------------------------------------
    t0 = time.time()
    reporter.stage_start(url, 10)
    headers_blob = " ".join(str(r) for r in result.ffuf_results[:50])
    result.technologies = detect_technologies(headers_blob)
    elapsed = time.time() - t0
    reporter.stage_done(url, 10, elapsed, detail=", ".join(result.technologies) or "none detected")

    result.elapsed_seconds = time.time() - start
    reporter.complete(url, result.elapsed_seconds)
    return result
