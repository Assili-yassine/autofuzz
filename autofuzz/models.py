"""Dataclasses shared across AutoFuzz pipeline stages."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TargetResult:
    """Accumulates everything discovered for a single target."""

    url: str
    slug: str
    output_dir: Path
    alive: bool = False
    js_files: list[str] = field(default_factory=list)
    linkfinder_endpoints: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)
    wayback_urls: list[str] = field(default_factory=list)
    gau_urls: list[str] = field(default_factory=list)
    katana_urls: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    wordlist_path: Path | None = None
    ffuf_results: list[dict] = field(default_factory=list)
    interesting: list[dict] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    elapsed_seconds: float = 0.0

    def ensure_dirs(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
