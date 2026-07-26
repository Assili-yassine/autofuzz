from rich.console import Console

from autofuzz.status import StatusReporter, TOTAL_STAGES


def _reporter_with_capture():
    console = Console(record=True, width=200)
    return console, StatusReporter(console)


def test_stage_start_includes_target_and_step():
    console, reporter = _reporter_with_capture()
    reporter.stage_start("https://example.com", 2)
    text = console.export_text()
    assert "example.com" in text
    assert f"[2/{TOTAL_STAGES}]" in text


def test_stage_done_includes_elapsed_and_detail():
    console, reporter = _reporter_with_capture()
    reporter.stage_done("https://example.com", 6, 3.25, detail="42 entries")
    text = console.export_text()
    assert "3.2s" in text or "3.3s" in text
    assert "42 entries" in text


def test_dead_and_alive_are_distinguishable():
    console, reporter = _reporter_with_capture()
    reporter.alive("https://a.com", 0.5)
    reporter.dead("https://b.com", 0.5)
    text = console.export_text()
    assert "alive" in text
    assert "dead" in text


def test_two_targets_stay_distinguishable_in_output():
    console, reporter = _reporter_with_capture()
    reporter.stage_start("https://host-a.com", 1)
    reporter.stage_start("https://host-b.com", 1)
    text = console.export_text()
    assert "host-a.com" in text
    assert "host-b.com" in text
