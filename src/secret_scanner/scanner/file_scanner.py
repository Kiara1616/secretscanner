"""
file_scanner.py – Recursive file scanner that applies PATTERNS to every
                  readable text file found under a given path.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Any

from secret_scanner.scanner.patterns import PATTERNS

# ── Constants ──────────────────────────────────────────────────────────────
BINARY_EXTENSIONS: set[str] = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".tiff",
    ".exe", ".dll", ".so", ".dylib",
    ".zip", ".tar", ".gz", ".bz2", ".rar", ".7z",
    ".pdf", ".docx", ".xlsx", ".pptx",
    ".pyc", ".pyo",
}

IGNORED_DIRS: set[str] = {
    ".git", "__pycache__", "node_modules", "output",
    ".venv", "venv", ".tox", "dist", "build", ".mypy_cache",
}


def _mask_secret(text: str) -> str:
    """Return the line with the middle portion of each token replaced by ***."""
    # Mask every word longer than 6 chars that looks like a secret value
    def _replace(m: re.Match) -> str:
        s = m.group(0)
        if len(s) <= 6:
            return s
        keep = max(3, len(s) // 5)
        return s[:keep] + "***" + s[-keep:]

    return re.sub(r"[A-Za-z0-9\+/=_\-]{7,}", _replace, text)


def _is_text_file(filepath: Path) -> bool:
    """Return True if the file is likely a text file."""
    if filepath.suffix.lower() in BINARY_EXTENSIONS:
        return False
    try:
        with open(filepath, "rb") as fh:
            chunk = fh.read(1024)
        # If the chunk contains a null byte it is almost certainly binary
        return b"\x00" not in chunk
    except OSError:
        return False


def scan_path(path: str, verbose: bool = False) -> List[Dict[str, Any]]:
    """
    Recursively scan *path* for secrets.

    Parameters
    ----------
    path : str
        Directory or single file to scan.
    verbose : bool
        When True, print the name of each file as it is processed.

    Returns
    -------
    list of dict
        Each dict contains:
            type     – pattern name (str)
            severity – "HIGH" | "MEDIUM" | "LOW"
            file     – relative (or absolute) path to the file (str)
            line     – 1-based line number (int)
            content  – masked line content (str)
    """
    findings: List[Dict[str, Any]] = []
    root = Path(path).resolve()

    # Build the list of files to inspect
    if root.is_file():
        files_to_scan = [root]
    else:
        files_to_scan = _walk_directory(root)

    for filepath in files_to_scan:
        if not _is_text_file(filepath):
            continue

        if verbose:
            print(f"  [scanning] {filepath}")

        _scan_file(filepath, findings)

    return findings


def _walk_directory(root: Path) -> List[Path]:
    """Walk *root* skipping ignored directories and return all file paths."""
    result: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in-place so os.walk won't descend into them
        dirnames[:] = [
            d for d in dirnames if d not in IGNORED_DIRS
        ]
        for filename in filenames:
            result.append(Path(dirpath) / filename)
    return result


def _scan_file(filepath: Path, findings: List[Dict[str, Any]]) -> None:
    """Read *filepath* line-by-line and append any matches to *findings*."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                for pat in PATTERNS:
                    if pat["pattern"].search(line):
                        findings.append(
                            {
                                "type": pat["name"],
                                "severity": pat["severity"],
                                "file": str(filepath),
                                "line": lineno,
                                "content": _mask_secret(line.rstrip()),
                            }
                        )
    except OSError:
        # Skip files we cannot open (permission errors, etc.)
        pass
