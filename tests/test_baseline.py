"""Tests for privacy-preserving baseline files."""

import json
from pathlib import Path

import pytest

from secret_scanner.scanner.baseline import (
    BaselineError,
    filter_baseline,
    load_baseline,
    write_baseline,
)

FINDING = {
    "type": "Hardcoded Password",
    "severity": "HIGH",
    "file": "config.py",
    "line": 2,
    "content": 'password = "sec***123"',
    "fingerprint": "v1:abc123",
}


def test_missing_baseline_is_empty(tmp_path: Path):
    assert load_baseline(tmp_path / "missing.json") == frozenset()


def test_round_trip_does_not_store_content(tmp_path: Path):
    path = tmp_path / "baseline.json"
    write_baseline(path, [FINDING])
    data = path.read_text(encoding="utf-8")
    assert "sec***123" not in data
    assert load_baseline(path) == frozenset({"v1:abc123"})


def test_filter_removes_known_finding():
    assert filter_baseline([FINDING], frozenset({"v1:abc123"})) == []
    assert filter_baseline([FINDING], frozenset()) == [FINDING]


@pytest.mark.parametrize(
    "payload",
    [
        {"version": 2, "findings": []},
        {"version": 1, "findings": "invalid"},
        {"version": 1, "findings": [{}]},
    ],
)
def test_rejects_invalid_baseline(tmp_path: Path, payload: dict):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)
