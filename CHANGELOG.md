# Changelog

All notable changes to SecretScanner are documented here. The project follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-09-26

### Added

- Project configuration through `.secretscanner.toml`.
- Path, regex and fingerprint allowlists.
- Stable privacy-preserving fingerprints for every finding.
- Baseline creation and filtering with `--update-baseline` and `--baseline`.
- Automatic policy and baseline discovery for the CLI and MCP server.

## [1.0.2] - 2026-09-26

### Added

- Contributor, security and support documentation.
- CI validation for Python 3.10–3.13, the VS Code extension and Python distributions.
- Build provenance attestations for published Python packages.
- MCP server entry point and server card.
- VS Code extension package.
- Automated PyPI publishing workflow.

### Changed

- Unified project and VS Code extension metadata under the SecretScanner name.
- Improved package metadata for PyPI discovery.
- Prepared the project as an independent open-source repository.
- Updated documentation, package links and branding.

### Removed

- Generated `node_modules` content and obsolete VSIX packages from version control.

[Unreleased]: https://github.com/Kiara1616/secretscanner/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Kiara1616/secretscanner/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Kiara1616/secretscanner/releases/tag/v1.0.2
