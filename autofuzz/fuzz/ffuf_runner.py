"""Stages 7, 9, 10: drive ffuf for directory, wordlist, and extension fuzzing.

## Why response-shape dedup is done in Python on ffuf.json, not by piping
## stdout into a Bash filter (e.g. `myfuzz`)

`ffuf -o ffuf.json -of json` writes its JSON output from its own internal
result buffer — a channel that is completely independent of stdout. Piping
stdout into a downstream filter (`ffuf ... | myfuzz`) can only change what
that filter sees or prints; a Unix pipe is one-directional, so nothing a
stdout consumer does can reach back into ffuf's process and change what it
already decided to write to `-o ffuf.json`. That file is finalized before
(or regardless of) whatever a pipe reader does with the terminal stream.
Concretely, that meant a previous `ffuf | myfuzz` design filtered what
appeared on screen while `ffuf.json` on disk silently kept every duplicate.

The fix: `ffuf` writes structured JSON where `words` (word count) is already
a plain int field — exactly the value a Bash filter would otherwise have to
regex out of colored terminal text. Deduplicating by that field directly on
the parsed JSON is strictly better:
  - no ANSI-color stripping or fragile regex over terminal text,
  - no external Bash binary dependency, no pipe lifecycle / SIGPIPE risk,
  - and — the actual point — there is only one code path now, so what gets
    saved to ffuf.txt and returned to the rest of the pipeline is
    *guaranteed* to reflect the same filtering, instead of two channels
    (stdout vs. -o file) that could silently disagree.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ..config import AutoFuzzConfig
from ..utils import describe_returncode, run_command


def build_ffuf_command(
    target_url: str,
    wordlist_path: Path,
    output_json: Path,
    cfg: AutoFuzzConfig,
    extensions: list[str] | None = None,
    proxy: str | None = None,
    cookies: str | None = None,
    headers: list[str] | None = None,
) -> list[str]:
    """Build the ffuf argv. Always a plain, independent subprocess — no
    shell, no pipe. Response-shape deduplication (formerly done by piping
    into a Bash `myfuzz` filter) now happens in Python, on the parsed JSON,
    after this process exits — see dedupe_results_by_words() below.

    Recursion and extension-fuzzing are both OFF by default (see
    config.yaml: ffuf.recursion, ffuf.use_extensions) because they multiply
    the effective request count by a large factor — recursion re-runs the
    *entire* wordlist against every discovered directory, and extensions
    re-tries every single wordlist entry once per extension. Combined with
    a large merged wordlist (JS endpoints + LinkFinder + gau/katana/wayback
    + a user -w file) this can balloon into millions of requests. Turn them
    back on in config.yaml if you specifically want that behavior.
    """
    ffuf_cfg = cfg.get("ffuf", default={})
    general_cfg = cfg.get("general", default={})

    fuzz_url = target_url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", str(wordlist_path),
        "-t", str(ffuf_cfg.get("threads", 40)),
        "-mc", ",".join(str(c) for c in ffuf_cfg.get("match_codes", [200])),
        "-fc", ",".join(str(c) for c in ffuf_cfg.get("filter_codes", [404])),
        "-of", "json",
        "-o", str(output_json),
        "-timeout", str(general_cfg.get("timeout", 10)),
        "-H", f"User-Agent: {general_cfg.get('user_agent', 'AutoFuzz/1.0')}",
        "-s",
    ]

    if ffuf_cfg.get("filter_size") not in (None, 0, "0"):
        cmd += ["-fs", str(ffuf_cfg["filter_size"])]
    if ffuf_cfg.get("auto_calibrate"):
        cmd.append("-ac")
    if ffuf_cfg.get("recursion"):
        cmd += ["-recursion", "-recursion-depth", str(ffuf_cfg.get("recursion_depth", 2))]
    if extensions and ffuf_cfg.get("use_extensions"):
        cmd += ["-e", ",".join(extensions)]
    if general_cfg.get("rate_limit"):
        cmd += ["-rate", str(general_cfg["rate_limit"])]
    if proxy:
        cmd += ["-x", proxy]
    if cookies:
        cmd += ["-b", cookies]
    for h in headers or []:
        cmd += ["-H", h]

    return cmd


def dedupe_results_by_words(results: list[dict]) -> list[dict]:
    """Deduplicate ffuf JSON results by response word count ("words").

    This is a direct, behavior-preserving port of the retired `myfuzz` Bash
    filter to Python, operating on ffuf's own structured JSON instead of
    grepping "Words: N" out of colored terminal text:

        declare -A seen_sizes
        while IFS= read -r line; do
            size=$(echo "$line" | grep -oP 'Words: \\K\\d+')
            if [[ -z "${seen_sizes[$size]}" ]]; then
                echo "$line"
                seen_sizes[$size]=1
            fi
        done

    Semantics are matched exactly: results are walked in ffuf's own reported
    order, the FIRST result seen for a given word count is kept, and every
    later result sharing that same word count is dropped — regardless of
    URL, status code, or any other field. Each kept result dict is returned
    completely unmodified, so every ffuf metadata field (status, length,
    lines, content-type, url, host, ...) is preserved.

    Note this is a coarse response-*shape* heuristic, not a smart similarity
    filter — many distinct soft-404/templated pages can share a word count
    and would still collapse into one entry. That's inherited as-is from the
    original filter (changing the heuristic itself wasn't the ask here); if
    you want finer-grained dedup, key on (words, lines, length) together, or
    swap in ffuf's own -ac (auto-calibrate) instead.
    """
    seen_word_counts: set[object] = set()
    deduped: list[dict] = []
    for r in results:
        words = r.get("words")
        if words in seen_word_counts:
            continue
        seen_word_counts.add(words)
        deduped.append(r)
    return deduped


def run_ffuf(
    target_url: str,
    wordlist_path: Path,
    output_dir: Path,
    cfg: AutoFuzzConfig,
    logger: logging.Logger,
    has_ffuf: bool,
    **kwargs,
) -> list[dict]:
    if not has_ffuf:
        logger.warning("[yellow]ffuf binary not found — skipping fuzzing for %s[/]", target_url)
        return []
    if not wordlist_path.exists() or wordlist_path.stat().st_size == 0:
        logger.warning("Wordlist empty for %s, skipping ffuf run.", target_url)
        return []

    output_json = output_dir / "ffuf.json"

    # No wall-clock timeout: a fuzzing run should be allowed to run to
    # completion no matter how long it takes. It only ends when ffuf itself
    # finishes, or the user interrupts it (Ctrl+C).
    cmd = build_ffuf_command(target_url, wordlist_path, output_json, cfg, **kwargs)
    result = run_command(cmd, logger, timeout=None)

    if not output_json.exists():
        logger.warning(
            "[yellow]ffuf produced no output file for %s (%s). Run with --debug to see the full "
            "command and stderr.[/]",
            target_url, describe_returncode(result.returncode),
        )
        logger.debug("ffuf command: %s", cmd)
        logger.debug("ffuf stderr: %s", result.stderr[:2000])
        return []

    try:
        raw = output_json.read_text(encoding="utf-8")
        data = json.loads(raw)
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning(
            "[yellow]ffuf's JSON output for %s could not be parsed (likely an interrupted/incomplete "
            "write). Run with --debug for details.[/]",
            target_url,
        )
        logger.debug("ffuf JSON parse error for %s: %s", target_url, exc)
        logger.debug("ffuf command: %s", cmd)
        logger.debug("ffuf stderr: %s", result.stderr[:2000])
        return []

    raw_results = data.get("results", [])
    results = dedupe_results_by_words(raw_results)

    if raw_results and len(results) < len(raw_results):
        logger.info(
            "ffuf: deduped %d raw result(s) down to %d by response word count for %s.",
            len(raw_results), len(results), target_url,
        )

    if not results:
        logger.info(
            "ffuf completed for %s with 0 matching results. If you expected hits, check config.yaml: "
            "'ffuf.auto_calibrate: true' can suppress real findings on targets that return a consistent "
            "catch-all/soft-404 response for unknown paths (common on SPAs) — try setting it to false.",
            target_url,
        )

    # Write a plain-text summary alongside the JSON, reflecting the SAME
    # deduped set returned to the rest of the pipeline — full ffuf metadata
    # is preserved (status, words, lines, length, url), not just a subset.
    txt_path = output_dir / "ffuf.txt"
    lines = [
        f"{r.get('status')}\t{r.get('words')}\t{r.get('lines')}\t{r.get('length')}\t{r.get('url')}"
        for r in results
    ]
    txt_path.write_text("\n".join(lines), encoding="utf-8")

    # The raw ffuf.json (pre-dedup, as ffuf wrote it) is an intermediate
    # artifact; the deduped plain-text summary (ffuf.txt) is the
    # deliverable AutoFuzz keeps.
    output_json.unlink(missing_ok=True)

    return results
