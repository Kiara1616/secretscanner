# Contributing to SecretScanner

Thank you for helping improve SecretScanner. Bug reports, documentation corrections and focused pull requests are welcome.

## Development setup

```bash
git clone https://github.com/Kiara1616/secretscanner.git
cd secretscanner
python -m venv .venv
```

Activate the environment, then install the development dependencies:

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
pytest
ruff check .
```

To validate the VS Code extension:

```bash
cd vscode-extension
npm ci
npm test
```

## Pull requests

1. Open an issue before making a large behavioral change.
2. Keep each pull request focused on one concern.
3. Add or update tests for behavior changes.
4. Update `CHANGELOG.md` when the change is visible to users.
5. Never use real credentials in fixtures, examples, issues or commits.

All checks must pass, and scanner coverage must remain at or above 80 percent.

## Adding detectors

Use an unmistakably fake value in tests. Include positive, negative and false-positive cases, document the expected severity, and avoid patterns broad enough to flag ordinary identifiers.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
