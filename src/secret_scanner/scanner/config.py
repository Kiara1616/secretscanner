"""Project configuration for SecretScanner."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 only
    import tomli as tomllib  # type: ignore[no-redef]


CONFIG_FILENAME = ".secretscanner.toml"
DEFAULT_BASELINE_FILENAME = ".secretscanner-baseline.json"


class ConfigError(ValueError):
    """Raised when a SecretScanner configuration is invalid."""


@dataclass(frozen=True)
class ScannerConfig:
    """Validated settings used by the scanner."""

    source: Path | None = None
    exclude_paths: tuple[str, ...] = ()
    allowlist_paths: tuple[str, ...] = ()
    allowlist_patterns: tuple[str, ...] = ()
    allowlist_fingerprints: frozenset[str] = field(default_factory=frozenset)
    baseline_path: str = DEFAULT_BASELINE_FILENAME

    def compiled_allowlist_patterns(self) -> tuple[re.Pattern[str], ...]:
        """Compile allowlist expressions after configuration validation."""
        return tuple(re.compile(pattern) for pattern in self.allowlist_patterns)


def discover_config(target: Path) -> Path | None:
    """Find the closest project configuration at or above the scan target."""
    current = target.resolve().parent if target.is_file() else target.resolve()
    for directory in (current, *current.parents):
        candidate = directory / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None) -> ScannerConfig:
    """Load and validate a TOML configuration, or return defaults."""
    if path is None:
        return ScannerConfig()
    if not path.is_file():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"Invalid TOML in {path}: {exc}") from exc

    scan = _table(data, "scan", path)
    allowlist = _table(data, "allowlist", path)
    baseline = _table(data, "baseline", path)

    patterns = _string_list(allowlist, "patterns", path)
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ConfigError(f"Invalid allowlist regex {pattern!r}: {exc}") from exc

    baseline_path = baseline.get("path", DEFAULT_BASELINE_FILENAME)
    if not isinstance(baseline_path, str) or not baseline_path.strip():
        raise ConfigError(f"baseline.path in {path} must be a non-empty string")

    return ScannerConfig(
        source=path.resolve(),
        exclude_paths=tuple(_string_list(scan, "exclude_paths", path)),
        allowlist_paths=tuple(_string_list(allowlist, "paths", path)),
        allowlist_patterns=tuple(patterns),
        allowlist_fingerprints=frozenset(_string_list(allowlist, "fingerprints", path)),
        baseline_path=baseline_path,
    )


def load_config_for_target(target: Path, explicit_path: str | None = None) -> ScannerConfig:
    """Load an explicit configuration or discover one from the target path."""
    path = Path(explicit_path).resolve() if explicit_path else discover_config(target)
    return load_config(path)


def resolve_project_path(value: str, config: ScannerConfig, target: Path) -> Path:
    """Resolve a config-relative path, falling back to the scan project root."""
    if config.source:
        return (config.source.parent / value).resolve()
    base = target.resolve().parent if target.is_file() else target.resolve()
    return (base / value).resolve()


def _table(data: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    value = data.get(key, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{key}] in {path} must be a TOML table")
    return value


def _string_list(table: dict[str, Any], key: str, path: Path) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{key} in {path} must be an array of strings")
    return value
