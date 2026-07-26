"""Shared utilities used across AutoFuzz stages."""
from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from rich.logging import RichHandler


def setup_logging(debug: bool = False, silent: bool = False) -> logging.Logger:
    """Configure a Rich-backed logger shared by every module."""
    level = logging.DEBUG if debug else (logging.CRITICAL if silent else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=debug)],
    )
    return logging.getLogger("autofuzz")


def which(binary: str) -> str | None:
    """Return the resolved path of an external tool, or None if missing."""
    return shutil.which(binary)


def require_binaries(names: Iterable[str], logger: logging.Logger) -> dict[str, str | None]:
    """Check availability of external binaries and warn about missing ones."""
    found: dict[str, str | None] = {}
    for name in names:
        path = which(name)
        found[name] = path
        if path is None:
            logger.warning(
                "[yellow]'%s' not found on PATH — the stage(s) that use it will be skipped.[/]",
                name,
            )
    return found


def normalize_url(raw: str) -> str:
    """Normalize a user-supplied domain/URL into a scheme://host[:port] form."""
    raw = raw.strip()
    if not raw:
        return raw
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    parsed = urlparse(raw)
    netloc = parsed.netloc.rstrip("/")
    return f"{parsed.scheme}://{netloc}"


def read_targets(path: str | None, single: str | None) -> list[str]:
    """Build a deduplicated target list from -i / -d input."""
    targets: list[str] = []
    if path:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Input file not found: {path}")
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                targets.append(normalize_url(line))
    if single:
        targets.append(normalize_url(single))
    # Dedup, preserve order.
    seen: set[str] = set()
    ordered: list[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            ordered.append(t)
    return ordered


def safe_slug(url: str) -> str:
    """Turn a URL into a filesystem-safe directory name."""
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    return host.replace(":", "_")


@dataclass
class CommandResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int
    elapsed: float


# Distinct from any real OS signal-based returncode (those are small negative
# ints like -9 for SIGKILL, -15 for SIGTERM), so a timeout can never be
# confused with the process actually having been killed by something else.
TIMEOUT_RETURNCODE = -999


def describe_returncode(rc: int | None) -> str:
    """Human-readable explanation of a subprocess return code, including
    the common "OS killed it" (SIGKILL/OOM) and "we timed it out" cases."""
    if rc is None:
        return "unknown exit status"
    if rc == TIMEOUT_RETURNCODE:
        return "timed out"
    if rc >= 0:
        return f"exit code {rc}"
    import signal as _signal

    sig_num = -rc
    try:
        sig_name = _signal.Signals(sig_num).name
    except ValueError:
        sig_name = f"signal {sig_num}"
    hint = ""
    if sig_num == _signal.SIGKILL:
        hint = " — likely killed by the OS (commonly the OOM killer) due to memory usage"
    return f"killed by {sig_name}{hint}"


def run_command(
    cmd: list[str],
    logger: logging.Logger,
    timeout: int | None = 120,
    input_text: str | None = None,
) -> CommandResult:
    """Run an external command safely, capturing output and timing it.

    No shell=True is ever used; cmd must be an argv list so there is no
    shell-injection surface regardless of what data flows into arguments.

    timeout=None means "wait indefinitely" (passed straight through to
    subprocess.run) — use this for long-running fuzzing jobs that should
    never be killed by AutoFuzz itself, only by the user (Ctrl+C) or a
    binary's own internal limits.
    """
    start = time.time()
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = time.time() - start
        ok = proc.returncode == 0
        if not ok:
            logger.debug("Command %s exited %s: %s", cmd, proc.returncode, proc.stderr[:300])
        return CommandResult(ok, proc.stdout, proc.stderr, proc.returncode, elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - start
        logger.warning("Command timed out after %ss: %s", timeout, " ".join(cmd))
        return CommandResult(False, exc.stdout or "", str(exc), TIMEOUT_RETURNCODE, elapsed)
    except FileNotFoundError:
        logger.debug("Binary not found for command: %s", cmd[0])
        return CommandResult(False, "", "binary not found", -2, 0.0)


def dedupe_lines(lines: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for line in lines:
        line = line.strip()
        if line and line not in seen:
            seen.add(line)
            out.append(line)
    return out


def run_piped_command(cmd: list[str], logger: logging.Logger, timeout: int | None = 1800) -> CommandResult:
    """Run a command that may include a trailing pipe stage, e.g. [..., "| myfuzz"].

    subprocess with an argv list can't express a shell pipe, so this rebuilds
    the command as a shell string — but every real argument is escaped with
    shlex.quote() first, and only the literal '|' operator is left bare. That
    keeps this safe from shell injection even though shell=True is used: a
    malicious value in a URL or path can't break out of its quoting to inject
    additional shell syntax.

    A token that is exactly "|" or starts with "|" (e.g. "| myfuzz") marks the
    pipe boundary; anything after it is treated as the next pipeline stage.

    Because this is a real shell pipe, the left-hand command's stdout (e.g.
    ffuf's) is connected directly to the right-hand command's stdin at the
    OS level — it is never buffered through this Python process, no matter
    how much output it produces. What subprocess.run captures here as
    "stdout" is only the *last* pipeline stage's output.

    timeout=None means "wait indefinitely" — see run_command().
    """
    import shlex

    quoted: list[str] = []
    for token in cmd:
        if token == "|":
            quoted.append("|")
        elif token.startswith("|"):
            quoted.append("|")
            remainder = token[1:].strip()
            if remainder:
                quoted.extend(shlex.quote(p) for p in shlex.split(remainder))
        else:
            quoted.append(shlex.quote(token))

    shell_str = " ".join(quoted)
    start = time.time()
    try:
        proc = subprocess.run(
            shell_str,
            shell=True,  # noqa: S602 — every dynamic token above is shlex-quoted
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        elapsed = time.time() - start
        ok = proc.returncode == 0
        if not ok:
            logger.debug("Piped command exited %s: %s", proc.returncode, proc.stderr[:300])
        return CommandResult(ok, proc.stdout, proc.stderr, proc.returncode, elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - start
        logger.warning("Piped command timed out after %ss: %s", timeout, shell_str)
        return CommandResult(False, exc.stdout or "", str(exc), TIMEOUT_RETURNCODE, elapsed)
