import os
from pathlib import Path

from autofuzz.cli import resolve_config_path


def test_explicit_path_used_when_it_exists(tmp_path, monkeypatch):
    cfg = tmp_path / "myconfig.yaml"
    cfg.write_text("general:\n  threads: 99\n")
    path, warning = resolve_config_path(str(cfg))
    assert path == str(cfg)
    assert warning is None


def test_explicit_path_missing_returns_warning_and_no_path():
    path, warning = resolve_config_path("/nonexistent/path/config.yaml")
    assert path is None
    assert warning is not None
    assert "not found" in warning


def test_falls_back_to_cwd_config_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text("general:\n  threads: 5\n")
    path, warning = resolve_config_path(None)
    assert path == "config.yaml"
    assert warning is None


def test_falls_back_to_home_config_when_no_cwd_config(tmp_path, monkeypatch):
    empty_cwd = tmp_path / "somewhere_empty"
    empty_cwd.mkdir()
    monkeypatch.chdir(empty_cwd)

    fake_home = tmp_path / "fakehome"
    (fake_home / ".config" / "autofuzz").mkdir(parents=True)
    (fake_home / ".config" / "autofuzz" / "config.yaml").write_text("general:\n  threads: 7\n")
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    path, warning = resolve_config_path(None)
    assert path == str(fake_home / ".config" / "autofuzz" / "config.yaml")
    assert warning is None


def test_no_config_anywhere_falls_back_to_builtin_defaults(tmp_path, monkeypatch):
    empty_cwd = tmp_path / "somewhere_else_empty"
    empty_cwd.mkdir()
    monkeypatch.chdir(empty_cwd)

    fake_home = tmp_path / "fakehome_empty"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: fake_home)

    path, warning = resolve_config_path(None)
    assert path is None
    assert warning is None  # this is expected, not an error
