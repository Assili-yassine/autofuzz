import json
import logging
from pathlib import Path

from autofuzz.config import AutoFuzzConfig
from autofuzz.fuzz.ffuf_runner import build_ffuf_command, dedupe_results_by_words, run_ffuf


def _cfg():
    return AutoFuzzConfig.load(None)


def _logger():
    return logging.getLogger("test")


# ---- build_ffuf_command -----------------------------------------------------

def test_command_never_contains_a_pipe():
    """ffuf always runs as a plain, independent subprocess now — dedup
    happens in Python on the parsed JSON, not via a shell pipe."""
    cmd = build_ffuf_command("https://example.com", Path("wl.txt"), Path("out.json"), _cfg())
    assert not any("|" in c for c in cmd)


def test_command_always_uses_silent_flag():
    cmd = build_ffuf_command("https://example.com", Path("wl.txt"), Path("out.json"), _cfg())
    assert "-s" in cmd
    assert "-v" not in cmd


def test_command_has_expected_core_flags():
    cmd = build_ffuf_command("https://example.com", Path("wl.txt"), Path("out.json"), _cfg())
    assert "-u" in cmd
    assert "https://example.com/FUZZ" in cmd
    assert "-w" in cmd
    assert "-o" in cmd
    assert "out.json" in cmd


def test_recursion_off_by_default():
    cmd = build_ffuf_command("https://example.com", Path("wl.txt"), Path("out.json"), _cfg())
    assert "-recursion" not in cmd


def test_extensions_off_by_default():
    cmd = build_ffuf_command(
        "https://example.com", Path("wl.txt"), Path("out.json"), _cfg(), extensions=[".php"]
    )
    assert "-e" not in cmd


# ---- dedupe_results_by_words (the myfuzz replacement) -----------------------

def test_dedupe_keeps_first_occurrence_per_word_count():
    results = [
        {"status": 200, "words": 10, "url": "https://x/a"},
        {"status": 200, "words": 10, "url": "https://x/b"},  # dropped: dup words
        {"status": 403, "words": 25, "url": "https://x/c"},
        {"status": 200, "words": 10, "url": "https://x/d"},  # dropped: dup words
        {"status": 200, "words": 30, "url": "https://x/e"},
    ]
    deduped = dedupe_results_by_words(results)
    assert [r["url"] for r in deduped] == ["https://x/a", "https://x/c", "https://x/e"]


def test_dedupe_preserves_full_metadata_on_kept_results():
    results = [
        {
            "status": 200, "words": 10, "lines": 5, "length": 123,
            "url": "https://x/a", "content-type": "text/html", "host": "x",
        },
    ]
    deduped = dedupe_results_by_words(results)
    assert deduped[0] == results[0]  # untouched — every field preserved


def test_dedupe_empty_input():
    assert dedupe_results_by_words([]) == []


def test_dedupe_matches_original_bash_semantics_for_missing_words():
    """Mirrors the bash script's behavior when `Words: N` fails to match
    (empty string key): the first such result is kept, subsequent ones with
    the same missing value are dropped."""
    results = [
        {"status": 200, "url": "https://x/a"},  # no "words" key -> None
        {"status": 200, "url": "https://x/b"},  # also None -> dropped
        {"status": 200, "words": 5, "url": "https://x/c"},
    ]
    deduped = dedupe_results_by_words(results)
    assert [r["url"] for r in deduped] == ["https://x/a", "https://x/c"]


# ---- run_ffuf integration: dedup applied end-to-end, ffuf.txt has full metadata

def test_run_ffuf_applies_dedup_and_writes_full_metadata(tmp_path, monkeypatch):
    from autofuzz.fuzz import ffuf_runner

    def fake_run_command(cmd, logger, timeout=None, input_text=None):
        from autofuzz.utils import CommandResult
        output_json = None
        for i, tok in enumerate(cmd):
            if tok == "-o":
                output_json = Path(cmd[i + 1])
        output_json.write_text(json.dumps({
            "results": [
                {"status": 200, "words": 10, "lines": 2, "length": 100, "url": "https://x/a"},
                {"status": 200, "words": 10, "lines": 2, "length": 100, "url": "https://x/b"},
                {"status": 403, "words": 25, "lines": 4, "length": 400, "url": "https://x/c"},
            ]
        }))
        return CommandResult(True, "", "", 0, 0.1)

    monkeypatch.setattr(ffuf_runner, "run_command", fake_run_command)

    wl = tmp_path / "wl.txt"
    wl.write_text("a\nb\nc\n")
    outdir = tmp_path / "out"
    outdir.mkdir()

    results = run_ffuf("https://example.com", wl, outdir, _cfg(), _logger(), has_ffuf=True)

    assert len(results) == 2  # deduped from 3 to 2
    assert {r["url"] for r in results} == {"https://x/a", "https://x/c"}

    txt = (outdir / "ffuf.txt").read_text()
    assert "words" not in txt  # header-less, tab-separated data
    assert "200\t10\t2\t100\thttps://x/a" in txt
    assert "403\t25\t4\t400\thttps://x/c" in txt
    assert "https://x/b" not in txt  # deduped result never written to disk

    # Intermediate JSON is cleaned up; ffuf.txt is the kept deliverable.
    assert not (outdir / "ffuf.json").exists()
    assert (outdir / "ffuf.txt").exists()
