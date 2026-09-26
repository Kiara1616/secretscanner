"""Tests for project configuration discovery and validation."""

from pathlib import Path

import pytest

from secret_scanner.scanner.config import (
    ConfigError,
    discover_config,
    load_config,
    load_config_for_target,
    resolve_project_path,
)


def test_discovers_config_from_nested_directory(tmp_path: Path):
    config_path = tmp_path / ".secretscanner.toml"
    config_path.write_text("[scan]\nexclude_paths = []\n", encoding="utf-8")
    nested = tmp_path / "src" / "package"
    nested.mkdir(parents=True)
    assert discover_config(nested) == config_path


def test_loads_complete_config(tmp_path: Path):
    config_path = tmp_path / ".secretscanner.toml"
    config_path.write_text(
        """
[scan]
exclude_paths = ["vendor/**"]

[allowlist]
paths = ["tests/fixtures/**"]
patterns = ["example-[0-9]+"]
fingerprints = ["v1:abc"]

[baseline]
path = "security/baseline.json"
""".strip(),
        encoding="utf-8",
    )
    config = load_config(config_path)
    assert config.exclude_paths == ("vendor/**",)
    assert config.allowlist_paths == ("tests/fixtures/**",)
    assert config.allowlist_fingerprints == frozenset({"v1:abc"})
    assert config.baseline_path == "security/baseline.json"
    assert resolve_project_path(config.baseline_path, config, tmp_path) == (
        tmp_path / "security" / "baseline.json"
    )


def test_explicit_config_takes_precedence(tmp_path: Path):
    explicit = tmp_path / "custom.toml"
    explicit.write_text('[baseline]\npath = "custom.json"\n', encoding="utf-8")
    config = load_config_for_target(tmp_path, str(explicit))
    assert config.source == explicit.resolve()
    assert config.baseline_path == "custom.json"


@pytest.mark.parametrize(
    "content",
    [
        "[scan]\nexclude_paths = 'not-a-list'\n",
        "[allowlist]\npatterns = ['[invalid']\n",
        "[baseline]\npath = ''\n",
    ],
)
def test_rejects_invalid_config(tmp_path: Path, content: str):
    path = tmp_path / ".secretscanner.toml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path)


def test_missing_explicit_config_is_an_error(tmp_path: Path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "missing.toml")
