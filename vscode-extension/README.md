# SecretScan PR

**SecretScan PR** is a powerful VS Code extension that detects API keys, tokens, and other secrets in your codebase to prevent accidental leaks.

## Features
- **Real-time scanning:** Automatically detects hardcoded secrets (API keys, tokens, credentials) on file save.
- **Visual Feedback:** Highlights exposed secrets directly in your editor with warning/error squiggles.
- **Cross-platform support:** Works seamlessly on Windows, Linux, and macOS.
- **Command Palette Integration:** Easily trigger manual scans across your current file.

## Configuration
Customize the extension from VS Code settings (coming soon):
- `secret-scanner.autoScanOnSave`: Automatically scan when a file is saved (Default: `true`)

## Commands
Use the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`):
- `SecretScanner: Scan Current File`

## 📦 Requirements & Setup
This extension acts as an intelligent bridge to the `secret-scanner-cl` Python CLI.

### Prerequisites
You must have Python installed on your system.

### Automatic Global Installation
For the extension to work, simply install the core scanner globally via pip:

```bash
pip install secret-scanner-cl
```

Once installed, the extension will automatically detect the `secret-scanner` command and highlight any vulnerabilities in your workspace.

## How it Works
1. When you save a file (`Ctrl+S`), the extension runs the Python CLI in the background.
2. The CLI returns a detailed JSON report.
3. The extension parses the report and maps the vulnerabilities to precise line numbers in your editor.

## 🤝 Connect with Us
[GitHub Repository](https://github.com/Kiara1616/secret-scanner)
