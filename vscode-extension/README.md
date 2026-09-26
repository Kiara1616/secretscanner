# SecretScanner for Visual Studio Code

SecretScanner detects API keys, tokens and credentials while you work, using the open-source `secret-scanner-cl` engine locally on your computer.

[Install from Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=kiara.secret-scanner-pr)

## Features
- **Real-time scanning:** Automatically detects hardcoded secrets (API keys, tokens, credentials) on file save.
- **Visual Feedback:** Highlights exposed secrets directly in your editor with warning/error squiggles.
- **Cross-platform support:** Works seamlessly on Windows, Linux, and macOS.
- **Command Palette Integration:** Easily trigger manual scans across your current file.

## Commands
Use the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):
- `SecretScanner: Scan Current File`

## Requirements and setup
This extension acts as an intelligent bridge to the `secret-scanner-cl` Python CLI.

### Prerequisites
You must have Python installed on your system.

Install the scanner CLI and ensure `secret-scanner` is available on your `PATH`:

```bash
pip install secret-scanner-cl
```

Once installed, the extension will automatically detect the `secret-scanner` command and highlight any vulnerabilities in your workspace.

## How it Works
1. When you save a file (`Ctrl+S`), the extension runs the Python CLI in the background.
2. The CLI returns a detailed JSON report.
3. The extension parses the report and maps the vulnerabilities to precise line numbers in your editor.

## Privacy

Scanning is performed locally. The extension does not upload source code or findings.

## Support

Report bugs and request features in the [GitHub repository](https://github.com/Kiara1616/secretscanner/issues). See the project's [security policy](https://github.com/Kiara1616/secretscanner/security/policy) for vulnerabilities.
