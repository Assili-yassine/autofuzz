"""Thread-safe, detailed status reporting for concurrent multi-target runs.

The stock ThreadPoolExecutor run interleaves each target's print statements
with no labeling, so with >1 target it's impossible to tell which line
belongs to which host or which pipeline stage. StatusReporter fixes that by
prefixing every line with a timestamp, the target's hostname, and a
"[step/total]" stage counter, and by reporting a duration + result detail
when each stage finishes.
"""
from __future__ import annotations

import threading
import time

from rich.console import Console

TOTAL_STAGES = 10

STAGE_NAMES = {
    1: "Liveness check (httpx)",
    2: "Collect JS files (katana/gau/wayback)",
    3: "LinkFinder endpoint extraction",
    4: "JS endpoint extraction (fetch/axios/ajax/location)",
    5: "Secret-pattern scan",
    6: "Build wordlist",
    7: "ffuf fuzzing",
    8: "API/schema discovery",
    9: "Classify interesting responses",
    10: "Technology fingerprinting",
}


class StatusReporter:
    def __init__(self, console: Console):
        self._console = console
        self._lock = threading.Lock()

    @staticmethod
    def _ts() -> str:
        return time.strftime("%H:%M:%S")

    @staticmethod
    def _host(target: str) -> str:
        return target.split("://", 1)[-1]

    def _line(self, color: str, icon: str, target: str, text: str) -> None:
        host = self._host(target)
        with self._lock:
            self._console.print(f"[dim]{self._ts()}[/] [{color}]{icon}[/] [bold]{host:<34}[/] {text}")

    def stage_start(self, target: str, step: int, label: str | None = None) -> None:
        label = label or STAGE_NAMES.get(step, f"stage {step}")
        self._line("cyan", "▶", target, f"[{step}/{TOTAL_STAGES}] {label}...")

    def stage_done(self, target: str, step: int, elapsed: float, detail: str = "", label: str | None = None) -> None:
        label = label or STAGE_NAMES.get(step, f"stage {step}")
        suffix = f" — {detail}" if detail else ""
        self._line("green", "✓", target, f"[{step}/{TOTAL_STAGES}] {label} done in {elapsed:.1f}s{suffix}")

    def stage_skipped(self, target: str, step: int, reason: str, label: str | None = None) -> None:
        label = label or STAGE_NAMES.get(step, f"stage {step}")
        self._line("yellow", "-", target, f"[{step}/{TOTAL_STAGES}] {label} skipped ({reason})")

    def alive(self, target: str, elapsed: float) -> None:
        self._line("green", "●", target, f"[1/{TOTAL_STAGES}] alive ({elapsed:.1f}s)")

    def dead(self, target: str, elapsed: float) -> None:
        self._line("red", "○", target, f"[1/{TOTAL_STAGES}] dead ({elapsed:.1f}s) — skipping remaining stages")

    def warn(self, target: str, text: str) -> None:
        self._line("yellow", "!", target, text)

    def info(self, target: str, text: str) -> None:
        self._line("white", "·", target, text)

    def complete(self, target: str, elapsed: float) -> None:
        self._line("bold green", "★", target, f"all stages complete in {elapsed:.1f}s")
