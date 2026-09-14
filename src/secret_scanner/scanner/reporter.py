"""
reporter.py – Export scan findings to JSON or CSV files.
"""

import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List

OUTPUT_DIR = "output"


def _ensure_output_dir(output_path: str) -> None:
    """Create the parent directory for *output_path* if it does not exist."""
    parent = Path(output_path).parent
    parent.mkdir(parents=True, exist_ok=True)


def export_json(findings: List[Dict[str, Any]], output_path: str) -> None:
    """
    Serialize *findings* to a JSON file at *output_path*.

    The output directory is created automatically when it does not exist.

    Parameters
    ----------
    findings : list[dict]
        List of finding dicts as returned by ``scan_path``.
    output_path : str
        Destination file path (e.g. ``"output/report.json"``).
    """
    _ensure_output_dir(output_path)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)


def export_csv(findings: List[Dict[str, Any]], output_path: str) -> None:
    """
    Write *findings* to a CSV file at *output_path*.

    The output directory is created automatically when it does not exist.

    Parameters
    ----------
    findings : list[dict]
        List of finding dicts as returned by ``scan_path``.
    output_path : str
        Destination file path (e.g. ``"output/report.csv"``).
    """
    _ensure_output_dir(output_path)

    fieldnames = ["type", "severity", "file", "line", "content"]

    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(findings)
