"""CLI entrypoint: argument parsing, threading, resume, reporting glue."""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.table import Table

from .config import AutoFuzzConfig
from .models import TargetResult
from .pipeline import run_pipeline_for_target
from .report.global_report import render_global_fuzzing_report
from .report.html_report import render_report
from .state import RunState
from .status import StatusReporter, TOTAL_STAGES as STAGE_COUNT
from .utils import read_targets, require_binaries, setup_logging

EXTERNAL_BINARIES = ["httpx", "katana", "gau", "wayback", "ffuf", "linkfinder"]
DEFAULT_TOR_PROXY = "socks5://127.0.0.1:9050"

BANNER = r"""
   _         _        ______
  / \  _   _| |_ ___  |  ____|   _ ________
 / _ \| | | | __/ _ \ | |_ | | | |_  /_  /
/ ___ \ |_| | || (_) ||  _|| |_| |/ / / /
/_/   \_\__,_|\__\___/ |_|   \__,_/___/___|
by assili_yassine

 https://github.com/Assili-yassine
  Authorized recon + ffuf orchestration
"""


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="autofuzz",
        description="AutoFuzz: recon + ffuf orchestration for authorized bug bounty testing.",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("-i", "--input", dest="input_file", help="File with one target per line.")
    src.add_argument("-d", "--domain", dest="domain", help="Single target URL/domain.")

    p.add_argument(
        "--config", default=None,
        help=(
            "Path to config.yaml. If omitted, AutoFuzz looks for ./config.yaml in the "
            "current directory, then ~/.config/autofuzz/config.yaml, then falls back "
            "to its built-in defaults."
        ),
    )
    p.add_argument("--threads", type=int, default=None, help="Worker/ffuf thread count.")
    p.add_argument(
        "-p", "--proxy",
        nargs="?",
        const=DEFAULT_TOR_PROXY,
        default=None,
        help=(
            "Use a proxy for gau and ffuf only. Bare '-p' defaults to "
            f"{DEFAULT_TOR_PROXY} (local Tor). Pass a value to use a specific "
            "proxy, e.g. -p socks5://8.16.42.30:8060. Omit entirely for no proxy."
        ),
    )
    p.add_argument("--rate", type=int, default=None, help="Request rate limit (req/s).")
    p.add_argument("--timeout", type=int, default=None, help="Per-request timeout in seconds.")
    p.add_argument("--cookies", default=None, help="Cookie header value to send with ffuf requests.")
    p.add_argument("--headers", action="append", default=[], help="Extra header 'Name: Value' (repeatable).")
    p.add_argument("--extensions", default=None, help="Comma-separated extension list overriding config.yaml.")
    p.add_argument(
        "-w", "--wordlist",
        dest="wordlist_file",
        default=None,
        help="Extra wordlist file merged into every target's generated wordlist.",
    )
    p.add_argument(
        "-s", "--save-wordlist",
        action="store_true",
        help="Keep the generated custom_wordlist.txt after fuzzing instead of deleting it.",
    )
    p.add_argument("--resume", action="store_true", help="Skip targets already completed in a prior run.")
    p.add_argument("--json", dest="write_json", action="store_true", help="Write a consolidated results.json.")
    p.add_argument("--html", dest="write_html", action="store_true", help="Write results/report.html.")
    p.add_argument("--silent", action="store_true", help="Suppress non-essential console output.")
    p.add_argument("--debug", action="store_true", help="Verbose debug logging.")
    p.add_argument("--max-workers", type=int, default=4, help="Number of targets processed concurrently.")
    return p


def print_summary_table(console: Console, results: list[TargetResult]) -> None:
    table = Table(title="AutoFuzz Summary")
    for col in ["Target", "Alive", "JS", "Endpoints", "Secrets", "ffuf", "Interesting", "API", "Time (s)"]:
        table.add_column(col)
    for r in results:
        table.add_row(
            r.url,
            "✓" if r.alive else "✗",
            str(len(r.js_files)),
            str(len(r.js_endpoints)),
            str(len(r.secrets)),
            str(len(r.ffuf_results)),
            str(len(r.interesting)),
            str(len(r.api_endpoints)),
            f"{r.elapsed_seconds:.1f}",
        )
    console.print(table)


def result_to_dict(r: TargetResult) -> dict:
    return {
        "url": r.url,
        "alive": r.alive,
        "js_files": r.js_files,
        "linkfinder_endpoints": r.linkfinder_endpoints,
        "js_endpoints": r.js_endpoints,
        "secrets": r.secrets,
        "ffuf_results": r.ffuf_results,
        "interesting": r.interesting,
        "api_endpoints": r.api_endpoints,
        "technologies": r.technologies,
        "elapsed_seconds": r.elapsed_seconds,
    }


def resolve_config_path(explicit: str | None) -> tuple[str | None, str | None]:
    """Decide which config.yaml (if any) to load.

    Returns (path_to_use, warning_message). `path_to_use` is None when
    falling back entirely to built-in defaults — this is normal and not an
    error, since AutoFuzz is designed to run from anywhere (including a
    freshly `pip install`-ed global `autofuzz` command with no project
    directory at all).

    Search order:
      1. --config PATH, if explicitly given — must exist, or a warning is
         returned and defaults are used instead.
      2. ./config.yaml in the current working directory (project-local).
      3. ~/.config/autofuzz/config.yaml (a persistent global config for the
         installed command, so you don't need a config.yaml in every
         directory you run `autofuzz` from).
      4. Built-in defaults — always available, no file needed.
    """
    if explicit:
        if Path(explicit).exists():
            return explicit, None
        return None, f"--config '{explicit}' not found — using built-in defaults instead."

    cwd_config = Path("config.yaml")
    if cwd_config.exists():
        return str(cwd_config), None

    home_config = Path.home() / ".config" / "autofuzz" / "config.yaml"
    if home_config.exists():
        return str(home_config), None

    return None, None


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    config_path, config_warning = resolve_config_path(args.config)
    cfg = AutoFuzzConfig.load(config_path)
    cfg.apply_cli_overrides(args)

    logger = setup_logging(debug=cfg.get("general", "debug", default=False),
                            silent=cfg.get("general", "silent", default=False))
    console = Console(quiet=cfg.get("general", "silent", default=False))
    reporter = StatusReporter(console)

    if not cfg.get("general", "silent", default=False):
        console.print(f"[bold cyan]{BANNER}[/]")
        if config_warning:
            console.print(f"[yellow]{config_warning}[/]")
        elif config_path:
            console.print(f"[dim]Using config: {config_path}[/]")
        if args.proxy:
            console.print(f"[cyan]Proxy enabled (gau + ffuf only):[/] {args.proxy}")

    try:
        targets = read_targets(args.input_file, args.domain)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/]")
        return 2

    if not targets:
        console.print("[red]No valid targets provided.[/]")
        return 2

    available_bins = require_binaries(EXTERNAL_BINARIES, logger)

    output_root = Path(cfg.get("general", "output_dir", default="results"))
    output_root.mkdir(parents=True, exist_ok=True)

    state = RunState.load(output_root)
    if not args.resume:
        state.clear()

    pending = [t for t in targets if not (args.resume and state.is_done(t))]
    if args.resume:
        console.print(f"[cyan]Resume mode: {len(targets) - len(pending)} target(s) already completed, "
                       f"{len(pending)} remaining.[/]")

    console.print(
        f"[dim]{len(pending)} target(s), {max(1, args.max_workers)} running concurrently, "
        f"{STAGE_COUNT} stage(s) per target[/]\n"
    )

    results: list[TargetResult] = []
    start_all = time.time()

    with ThreadPoolExecutor(max_workers=max(1, args.max_workers)) as executor:
        future_to_target = {
            executor.submit(
                run_pipeline_for_target,
                t,
                cfg,
                logger,
                reporter,
                available_bins,
                output_root,
                args.proxy,
                args.cookies,
                args.headers,
                args.wordlist_file,
                args.save_wordlist,
            ): t
            for t in pending
        }
        for future in as_completed(future_to_target):
            target = future_to_target[future]
            try:
                result = future.result()
                results.append(result)
                state.mark_done(target)
            except Exception as exc:  # noqa: BLE001
                logger.error("[red]Pipeline failed for %s: %s[/]", target, exc)

    console.print(f"\n[bold]Completed {len(results)} target(s) in {time.time() - start_all:.1f}s[/]")
    print_summary_table(console, results)

    if args.write_json:
        json_path = output_root / "results.json"
        json_path.write_text(json.dumps([result_to_dict(r) for r in results], indent=2), encoding="utf-8")
        console.print(f"[green]JSON written to {json_path}[/]")

    if args.write_html:
        html_path = output_root / "report.html"
        render_report(results, html_path)
        console.print(f"[green]HTML report written to {html_path}[/]")

    # Only generated for multi-domain (-i) runs.
    if args.input_file:
        global_path = output_root / "global_fuzzing_results.txt"
        render_global_fuzzing_report(results, global_path)
        console.print(f"[green]Global fuzzing summary written to {global_path}[/]")

    return 0


if __name__ == "__main__":
    sys.exit(main())
