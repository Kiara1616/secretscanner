"""Read and write privacy-preserving SecretScanner baselines."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

BASELINE_VERSION = 1


class BaselineError(ValueError):
    """Raised when a baseline cannot be parsed or validated."""


def load_baseline(path: Path) -> frozenset[str]:
    """Return fingerprints stored in a baseline file."""
    if not path.exists():
        return frozenset()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BaselineError(f"Cannot read baseline {path}: {exc}") from exc

    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise BaselineError(f"Unsupported baseline format in {path}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise BaselineError(f"Baseline findings in {path} must be an array")

    fingerprints: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or not isinstance(finding.get("fingerprint"), str):
            raise BaselineError(f"Invalid finding in baseline {path}")
        fingerprints.add(finding["fingerprint"])
    return frozenset(fingerprints)


def filter_baseline(
    findings: list[dict[str, Any]], fingerprints: frozenset[str]
) -> list[dict[str, Any]]:
    """Remove findings already represented by the supplied fingerprints."""
    return [finding for finding in findings if finding["fingerprint"] not in fingerprints]


def write_baseline(path: Path, findings: list[dict[str, Any]]) -> None:
    """Write only non-sensitive finding metadata to a deterministic baseline."""
    records = [
        {
            "fingerprint": finding["fingerprint"],
            "type": finding["type"],
            "file": finding["file"],
        }
        for finding in sorted(findings, key=lambda item: item["fingerprint"])
    ]
    payload = {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "findings": records,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
