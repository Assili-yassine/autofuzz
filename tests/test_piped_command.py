import logging

from autofuzz.utils import run_piped_command


def _logger():
    return logging.getLogger("test")


def test_piped_command_runs_simple_echo():
    result = run_piped_command(["echo", "hello"], _logger())
    assert result.ok
    assert "hello" in result.stdout


def test_piped_command_quotes_dangerous_argument():
    # A value with shell metacharacters must be treated as a literal string,
    # not executed — this is the injection case run_piped_command must avoid.
    dangerous = "hello; touch /tmp/should_not_exist_afz_test"
    result = run_piped_command(["echo", dangerous], _logger())
    assert result.ok
    assert "should_not_exist_afz_test" in result.stdout  # printed literally
    import os
    assert not os.path.exists("/tmp/should_not_exist_afz_test")


def test_piped_command_supports_pipe_stage():
    result = run_piped_command(["echo", "hello world", "| grep world"], _logger())
    assert result.ok
    assert "world" in result.stdout
