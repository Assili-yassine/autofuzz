"""Stage 11: detect and parse API schema endpoints (swagger/openapi/graphql)."""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from ..config import AutoFuzzConfig


def _fetch(url: str, timeout: int, user_agent: str) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            if resp.status != 200:
                return None
            return resp.read().decode("utf-8", errors="ignore")
    except (urllib.error.URLError, TimeoutError, ValueError):
        return None


def _paths_from_openapi(doc: dict) -> list[str]:
    return list(doc.get("paths", {}).keys())


def discover_api_endpoints(
    base_url: str,
    cfg: AutoFuzzConfig,
    logger: logging.Logger,
) -> list[str]:
    discovered: list[str] = []
    timeout = cfg.get("general", "timeout", default=10)
    user_agent = cfg.get("general", "user_agent", default="AutoFuzz/1.0")
    candidate_paths = cfg.get("api_discovery_paths", default=[])

    for path in candidate_paths:
        full_url = base_url.rstrip("/") + path
        body = _fetch(full_url, timeout, user_agent)
        if not body:
            continue
        discovered.append(full_url)
        if path.endswith(".json") or "swagger" in path or "openapi" in path:
            try:
                doc = json.loads(body)
                discovered.extend(base_url.rstrip("/") + p for p in _paths_from_openapi(doc))
            except json.JSONDecodeError:
                logger.debug("Response at %s wasn't valid JSON, skipping schema parse.", full_url)

    return sorted(set(discovered))
