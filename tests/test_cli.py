"""End-to-end tests for configuration and baseline CLI behavior."""

import json
import sys
from pathlib import Path

from secret_scanner.main import main


def _run(monkeypatch, *args: str) -> int:
    monkeypatch.setattr(sys, "argv", ["secret-scanner", *args])
    return main()


def test_update_baseline_then_hides_existing_finding(tmp_path: Path, monkeypatch):
    (tmp_path / "config.py").write_text('password = "secret123"\n', encoding="utf-8")
    baseline = tmp_path / ".secretscanner-baseline.json"

    result = _run(
        monkeypatch,
        "--path",
        str(tmp_path),
        "--update-baseline",
        str(baseline),
    )
    assert result == 0
    assert baseline.is_file()
    assert _run(monkeypatch, "--path", str(tmp_path), "--baseline", str(baseline)) == 0


def test_new_finding_is_not_hidden_by_baseline(tmp_path: Path, monkeypatch):
    first = tmp_path / "first.py"
    first.write_text('password = "secret123"\n', encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    assert _run(
        monkeypatch,
        "--path",
        str(tmp_path),
        "--update-baseline",
        str(baseline),
    ) == 0

    (tmp_path / "second.py").write_text('api_key = "new-example-key"\n', encoding="utf-8")
    assert _run(monkeypatch, "--path", str(tmp_path), "--baseline", str(baseline)) == 1


def test_auto_discovers_config_and_baseline(tmp_path: Path, monkeypatch):
    (tmp_path / ".secretscanner.toml").write_text(
        '[allowlist]\npaths = ["ignored.py"]\n', encoding="utf-8"
    )
    (tmp_path / "ignored.py").write_text('password = "secret123"\n', encoding="utf-8")
    assert _run(monkeypatch, "--path", str(tmp_path)) == 0


def test_invalid_baseline_returns_configuration_error(tmp_path: Path, monkeypatch):
    baseline = tmp_path / "baseline.json"
    baseline.write_text(json.dumps({"version": 99, "findings": []}), encoding="utf-8")
    assert _run(monkeypatch, "--path", str(tmp_path), "--baseline", str(baseline)) == 2
