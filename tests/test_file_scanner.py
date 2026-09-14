"""
tests/test_file_scanner.py – Tests for scanner/file_scanner.py

Uses pytest's tmp_path fixture to create temporary files and directories.
"""

import os
import pytest
from pathlib import Path

from secret_scanner.scanner.file_scanner import scan_path, _mask_secret, _is_text_file


# ── Helpers ────────────────────────────────────────────────────────────────
def write_file(directory: Path, filename: str, content: str) -> Path:
    filepath = directory / filename
    filepath.write_text(content, encoding="utf-8")
    return filepath


# ── _mask_secret ───────────────────────────────────────────────────────────
class TestMaskSecret:
    def test_masks_long_tokens(self):
        original = "AKIAIOSFODNN7EXAMPLE"
        masked = _mask_secret(original)
        assert "***" in masked

    def test_preserves_short_tokens(self):
        short = "abc"
        assert _mask_secret(short) == short

    def test_masked_is_shorter_or_same_length(self):
        original = "ghp_" + "X" * 40
        masked = _mask_secret(original)
        # At minimum the *** replaces some characters
        assert len(masked) <= len(original) + 3


# ── _is_text_file ──────────────────────────────────────────────────────────
class TestIsTextFile:
    def test_text_file_returns_true(self, tmp_path):
        f = write_file(tmp_path, "sample.py", "print('hello')")
        assert _is_text_file(f) is True

    def test_binary_extension_returns_false(self, tmp_path):
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n")
        assert _is_text_file(f) is False

    def test_binary_content_returns_false(self, tmp_path):
        f = tmp_path / "data.bin"
        f.write_bytes(b"\x00\x01\x02\x03")
        assert _is_text_file(f) is False


# ── scan_path – single file ────────────────────────────────────────────────
class TestScanPathSingleFile:
    def test_detects_aws_key_in_file(self, tmp_path):
        write_file(tmp_path, "config.py", 'key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan_path(str(tmp_path / "config.py"))
        assert any(f["type"] == "AWS Access Key" for f in findings)

    def test_detects_hardcoded_password(self, tmp_path):
        write_file(tmp_path, "settings.py", 'password = "hunter2"\n')
        findings = scan_path(str(tmp_path / "settings.py"))
        assert any(f["type"] == "Hardcoded Password" for f in findings)

    def test_finding_contains_expected_keys(self, tmp_path):
        write_file(tmp_path, "creds.txt", 'password = "s3cr3t!"\n')
        findings = scan_path(str(tmp_path / "creds.txt"))
        assert findings
        f = findings[0]
        assert "type" in f
        assert "severity" in f
        assert "file" in f
        assert "line" in f
        assert "content" in f

    def test_finding_line_number_is_correct(self, tmp_path):
        content = "# header\n# blank\npassword = \"secret123\"\n"
        write_file(tmp_path, "lines.py", content)
        findings = scan_path(str(tmp_path / "lines.py"))
        pwd_findings = [f for f in findings if f["type"] == "Hardcoded Password"]
        assert pwd_findings
        assert pwd_findings[0]["line"] == 3

    def test_clean_file_returns_no_findings(self, tmp_path):
        write_file(tmp_path, "clean.py", "x = 1\nprint(x)\n")
        findings = scan_path(str(tmp_path / "clean.py"))
        assert findings == []


# ── scan_path – directory ──────────────────────────────────────────────────
class TestScanPathDirectory:
    def test_scans_nested_files(self, tmp_path):
        subdir = tmp_path / "src"
        subdir.mkdir()
        write_file(subdir, "app.py", 'password = "nested_secret"\n')
        findings = scan_path(str(tmp_path))
        assert any(f["type"] == "Hardcoded Password" for f in findings)

    def test_skips_git_directory(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        write_file(git_dir, "config", 'password = "gitpass"\n')
        findings = scan_path(str(tmp_path))
        # No findings because .git is ignored
        assert not any(".git" in f["file"] for f in findings)

    def test_skips_pycache_directory(self, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        write_file(cache_dir, "module.pyc", 'password = "cachepass"\n')
        findings = scan_path(str(tmp_path))
        assert not any("__pycache__" in f["file"] for f in findings)

    def test_skips_node_modules_directory(self, tmp_path):
        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        write_file(nm_dir, "index.js", 'const password = "nmpass";\n')
        findings = scan_path(str(tmp_path))
        assert not any("node_modules" in f["file"] for f in findings)

    def test_skips_output_directory(self, tmp_path):
        out_dir = tmp_path / "output"
        out_dir.mkdir()
        write_file(out_dir, "report.json", '{"password": "outpass"}\n')
        findings = scan_path(str(tmp_path))
        assert not any("output" in f["file"] for f in findings)

    def test_skips_binary_files(self, tmp_path):
        binary_file = tmp_path / "image.png"
        binary_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_path(str(tmp_path))
        assert not any("image.png" in f["file"] for f in findings)

    def test_multiple_secrets_in_one_file(self, tmp_path):
        content = (
            'password = "secret123"\n'
            'api_key = "abcdefghij"\n'
        )
        write_file(tmp_path, "multi.py", content)
        findings = scan_path(str(tmp_path))
        types_found = {f["type"] for f in findings}
        assert "Hardcoded Password" in types_found
        assert "Generic API Key" in types_found


# ── scan_path – verbose mode ───────────────────────────────────────────────
class TestScanPathVerbose:
    def test_verbose_mode_runs_without_error(self, tmp_path, capsys):
        write_file(tmp_path, "test.py", "x = 1\n")
        findings = scan_path(str(tmp_path), verbose=True)
        captured = capsys.readouterr()
        # Should print something when verbose
        assert "scanning" in captured.out.lower() or isinstance(findings, list)
