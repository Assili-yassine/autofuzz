"""Stage 1: liveness probing.

Prefers the `httpx` (projectdiscovery) CLI when available; falls back to a
plain HTTP HEAD/GET request via urllib so the pipeline still works in
environments where the binary isn't installed.
"""
from __future__ import annotations

import logging
import urllib.error
import urllib.request

from ..utils import CommandResult, run_command


def check_alive_httpx_binary(url: str, logger: logging.Logger, timeout: int) -> bool:
    result: CommandResult = run_command(
        ["httpx", "-silent", "-u", url, "-timeout", str(timeout)],
        logger,
        timeout=timeout + 5,
    )
    return result.ok and url.split("://", 1)[-1] in result.stdout


def check_alive_fallback(url: str, logger: logging.Logger, timeout: int, user_agent: str) -> bool:
    req = urllib.request.Request(url, headers={"User-Agent": user_agent}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (scheme validated upstream)
            return 200 <= resp.status < 500
    except urllib.error.HTTPError as exc:
        # Any HTTP response, even an error status, means the host is alive.
        return exc.code is not None
    except Exception as exc:  # noqa: BLE001
        logger.debug("Liveness check failed for %s: %s", url, exc)
        return False


def check_alive(url: str, logger: logging.Logger, timeout: int, user_agent: str, has_httpx: bool) -> bool:
    if has_httpx:
        try:
            return check_alive_httpx_binary(url, logger, timeout)
        except Exception as exc:  # noqa: BLE001
            logger.debug("httpx binary check errored for %s: %s", url, exc)
    return check_alive_fallback(url, logger, timeout, user_agent)
