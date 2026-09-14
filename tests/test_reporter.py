"""
tests/test_reporter.py – Tests for scanner/reporter.py

Verifies that export_json and export_csv create correct output files.
"""

import csv
import json
import os
from pathlib import Path

import pytest

from secret_scanner.scanner.reporter import export_json, export_csv


# ── Fixtures ───────────────────────────────────────────────────────────────
SAMPLE_FINDINGS = [
    {
        "type": "Hardcoded Password",
        "severity": "HIGH",
        "file": "app/settings.py",
        "line": 12,
        "content": 'pass***d = "hun***2"',
    },
    {
        "type": "AWS Access Key",
        "severity": "HIGH",
        "file": "config/aws.py",
        "line": 5,
        "content": "AKI***ODNN7EXAM***E",
    },
]


# ── export_json ────────────────────────────────────────────────────────────
class TestExportJSON:
    def test_creates_file(self, tmp_path):
        out = str(tmp_path / "output" / "report.json")
        export_json(SAMPLE_FINDINGS, out)
        assert Path(out).exists()

    def test_creates_parent_directory(self, tmp_path):
        nested = str(tmp_path / "a" / "b" / "c" / "report.json")
        export_json(SAMPLE_FINDINGS, nested)
        assert Path(nested).exists()

    def test_content_is_valid_json(self, tmp_path):
        out = str(tmp_path / "report.json")
        export_json(SAMPLE_FINDINGS, out)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert isinstance(data, list)

    def test_content_matches_findings(self, tmp_path):
        out = str(tmp_path / "report.json")
        export_json(SAMPLE_FINDINGS, out)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert len(data) == len(SAMPLE_FINDINGS)
        assert data[0]["type"] == SAMPLE_FINDINGS[0]["type"]
        assert data[0]["line"] == SAMPLE_FINDINGS[0]["line"]

    def test_empty_findings_produces_empty_list(self, tmp_path):
        out = str(tmp_path / "empty.json")
        export_json([], out)
        with open(out, encoding="utf-8") as fh:
            data = json.load(fh)
        assert data == []

    def test_json_is_indented(self, tmp_path):
        out = str(tmp_path / "pretty.json")
        export_json(SAMPLE_FINDINGS, out)
        raw = Path(out).read_text(encoding="utf-8")
        # Indented JSON contains newlines
        assert "\n" in raw


# ── export_csv ─────────────────────────────────────────────────────────────
class TestExportCSV:
    def test_creates_file(self, tmp_path):
        out = str(tmp_path / "output" / "report.csv")
        export_csv(SAMPLE_FINDINGS, out)
        assert Path(out).exists()

    def test_creates_parent_directory(self, tmp_path):
        nested = str(tmp_path / "deep" / "dir" / "report.csv")
        export_csv(SAMPLE_FINDINGS, nested)
        assert Path(nested).exists()

    def test_has_header_row(self, tmp_path):
        out = str(tmp_path / "report.csv")
        export_csv(SAMPLE_FINDINGS, out)
        with open(out, newline="", encoding="utf-8") as fh:
            reader = csv.reader(fh)
            header = next(reader)
        assert "type" in header
        assert "severity" in header
        assert "file" in header
        assert "line" in header
        assert "content" in header

    def test_row_count_matches_findings(self, tmp_path):
        out = str(tmp_path / "report.csv")
        export_csv(SAMPLE_FINDINGS, out)
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert len(rows) == len(SAMPLE_FINDINGS)

    def test_content_matches_findings(self, tmp_path):
        out = str(tmp_path / "report.csv")
        export_csv(SAMPLE_FINDINGS, out)
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows[0]["type"] == SAMPLE_FINDINGS[0]["type"]
        assert int(rows[0]["line"]) == SAMPLE_FINDINGS[0]["line"]

    def test_empty_findings_produces_only_header(self, tmp_path):
        out = str(tmp_path / "empty.csv")
        export_csv([], out)
        with open(out, newline="", encoding="utf-8") as fh:
            rows = list(csv.DictReader(fh))
        assert rows == []
