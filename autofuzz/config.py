"""Configuration loading for AutoFuzz (YAML + CLI overrides)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "general": {
        "threads": 25,
        "timeout": 10,
        "rate_limit": 0,
        "user_agent": "AutoFuzz/1.0 (+authorized-recon)",
        "output_dir": "results",
        "silent": False,
        "debug": False,
    },
    "ffuf": {
        "threads": 40,
        "match_codes": [200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500, 502, 503],
        "filter_codes": [404, 400],
        "recursion": False,
        "recursion_depth": 2,
        "use_extensions": False,
        "filter_size": 0,
        "auto_calibrate": True,
    },
    "extensions": [
        ".php", ".aspx", ".asp", ".jsp", ".do", ".action", ".cgi", ".json",
        ".xml", ".bak", ".old", ".zip", ".tar", ".gz", ".env", ".git",
    ],
    "wordlists": {
        "seclists_directory_medium": "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        "seclists_raft_small": "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
        "custom_output": "custom_wordlist.txt",
        "skip_extensions": [
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp", ".tiff", ".avif",
            ".woff", ".woff2", ".ttf", ".eot", ".otf",
            ".css", ".map",
            ".mp4", ".mp3", ".avi", ".mov", ".webm", ".ogg", ".wav",
        ],
    },
    "content_keywords": [
        "login", "admin", "dashboard", "graphql", "swagger", "api",
        "upload", "debug", "internal",
    ],
    "api_discovery_paths": [
        "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
        "/v2/api-docs", "/graphql", "/graphiql",
    ],
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class AutoFuzzConfig:
    data: dict[str, Any] = field(default_factory=lambda: dict(DEFAULT_CONFIG))

    @classmethod
    def load(cls, path: str | None) -> "AutoFuzzConfig":
        merged = dict(DEFAULT_CONFIG)
        if path:
            p = Path(path)
            if p.exists():
                with p.open("r", encoding="utf-8") as fh:
                    user_cfg = yaml.safe_load(fh) or {}
                merged = _deep_merge(merged, user_cfg)
        return cls(data=merged)

    def apply_cli_overrides(self, args: Any) -> None:
        """Overlay argparse.Namespace values on top of the loaded config."""
        if args.threads is not None:
            self.data["general"]["threads"] = args.threads
            self.data["ffuf"]["threads"] = args.threads
        if args.timeout is not None:
            self.data["general"]["timeout"] = args.timeout
        if args.rate is not None:
            self.data["general"]["rate_limit"] = args.rate
        if args.silent:
            self.data["general"]["silent"] = True
        if args.debug:
            self.data["general"]["debug"] = True
        if args.extensions:
            self.data["extensions"] = [
                e if e.startswith(".") else f".{e}" for e in args.extensions.split(",")
            ]

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self.data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node
