"""Recursive, privacy-preserving secret scanner."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from pathlib import Path
from typing import Any

from secret_scanner.scanner.config import ScannerConfig
from secret_scanner.scanner.patterns import PATTERNS

BINARY_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".tiff",
    ".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz",
    ".bz2", ".rar", ".7z", ".pdf", ".docx", ".xlsx", ".pptx",
    ".pyc", ".pyo",
}

IGNORED_DIRS: set[str] = {
    ".git", "__pycache__", "node_modules", "output", ".venv", "venv",
    ".tox", "dist", "build", ".mypy_cache", ".ruff_cache",
}


def _mask_secret(text: str) -> str:
    """Return text with every token-like value redacted."""
    def _replace(match: re.Match[str]) -> str:
        value = match.group(0)
        if len(value) <= 6:
            return value
        keep = max(3, len(value) // 5)
        return value[:keep] + "***" + value[-keep:]

    return re.sub(r"[A-Za-z0-9\+/=_\-]{7,}", _replace, text)


def _fingerprint(secret_type: str, relative_path: str, value: str) -> str:
    """Create a stable identifier without retaining the detected value."""
    material = f"{secret_type}\0{relative_path}\0{value}".encode()
    return "v1:" + hashlib.sha256(material).hexdigest()


def _is_text_file(filepath: Path) -> bool:
    """Return whether a file is likely to contain text."""
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        return False
    try:
        with filepath.open("rb") as handle:
            return b"\x00" not in handle.read(1024)
    except OSError:
        return False


def scan_path(
    path: str,
    verbose: bool = False,
    config: ScannerConfig | None = None,
) -> list[dict[str, Any]]:
    """Scan a file or directory using an optional project policy."""
    settings = config or ScannerConfig()
    root = Path(path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")
    base_dir = root.parent if root.is_file() else root
    files = [root] if root.is_file() else _walk_directory(root)
    findings: list[dict[str, Any]] = []
    allowlist_patterns = settings.compiled_allowlist_patterns()

    for filepath in files:
        relative_path = _relative_path(filepath, base_dir)
        if _matches_any(relative_path, settings.exclude_paths):
            continue
        if _matches_any(relative_path, settings.allowlist_paths):
            continue
        if not _is_text_file(filepath):
            continue
        if verbose:
            print(f"  [scanning] {relative_path}")
        _scan_file(
            filepath,
            relative_path,
            findings,
            settings,
            allowlist_patterns,
        )

    return findings


def _relative_path(filepath: Path, base_dir: Path) -> str:
    try:
        return filepath.relative_to(base_dir).as_posix()
    except ValueError:
        return filepath.as_posix()


def _matches_any(relative_path: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(relative_path, pattern) for pattern in patterns)


def _walk_directory(root: Path) -> list[Path]:
    """Walk a directory while pruning built-in ignored directories."""
    result: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [directory for directory in dirnames if directory not in IGNORED_DIRS]
        result.extend(Path(dirpath) / filename for filename in filenames)
    return result


def _scan_file(
    filepath: Path,
    relative_path: str,
    findings: list[dict[str, Any]],
    config: ScannerConfig,
    allowlist_patterns: tuple[re.Pattern[str], ...],
) -> None:
    """Append non-allowlisted findings from one text file."""
    try:
        with filepath.open(encoding="utf-8", errors="replace") as handle:
            for line_number, line in enumerate(handle, start=1):
                if any(pattern.search(line) for pattern in allowlist_patterns):
                    continue
                for detector in PATTERNS:
                    for match in detector["pattern"].finditer(line):
                        fingerprint = _fingerprint(detector["name"], relative_path, match.group(0))
                        if fingerprint in config.allowlist_fingerprints:
                            continue
                        findings.append(
                            {
                                "type": detector["name"],
                                "severity": detector["severity"],
                                "file": relative_path,
                                "line": line_number,
                                "content": _mask_secret(line.rstrip()),
                                "fingerprint": fingerprint,
                            }
                        )
    except OSError:
        return
