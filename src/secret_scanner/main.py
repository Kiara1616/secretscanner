"""
main.py – SecretScanner CLI entry-point.

Usage examples
--------------
    python main.py --path .
    python main.py --path ./myproject --output json --verbose
    python main.py --path ./myproject --output csv
"""

import argparse
import os
import sys
from pathlib import Path

# Force UTF-8 output on Windows to avoid cp1252 UnicodeEncodeError
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except AttributeError:
        pass

from colorama import Fore, Style, init as colorama_init

from secret_scanner.scanner.file_scanner import scan_path
from secret_scanner.scanner.reporter import export_json, export_csv

# ── Colour helpers ─────────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "HIGH": Fore.RED + Style.BRIGHT,
    "MEDIUM": Fore.YELLOW + Style.BRIGHT,
    "LOW": Fore.CYAN,
}


def _colored(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def _banner() -> None:
    print(
        _colored(
            r"""
  ____  ___   ____ ____  _____ _____ ____   ____    _    _   _ _   _ _____ ____
 / ___||__ \ / ___| __ )| ____|_   _/ ___| / ___|  / \  | \ | | \ | | ____|  _ \
 \___ \  / // |   |  _ \|  _|   | | \___ \| |     / _ \ |  \| |  \| |  _| | |_) |
  ___) |/ /_| |___| |_) | |___  | |  ___) | |___ / ___ \| |\  | |\  | |___|  _ <
 |____//_____\____|____/|_____| |_| |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_\
""",
            Fore.CYAN + Style.BRIGHT,
        )
    )
    print(_colored("  SecretScanner v1.0.0 - Hardcoded Secret Detector\n", Fore.WHITE))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Detect hardcoded secrets and credentials in source code.",
    )
    parser.add_argument(
        "--path",
        required=True,
        metavar="PATH",
        help="Directory or file to scan.",
    )
    parser.add_argument(
        "--output",
        choices=["json", "csv"],
        default=None,
        metavar="FORMAT",
        help="Export format: 'json' or 'csv'. Saves to output/ directory.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each file as it is processed.",
    )
    return parser


def _print_findings(findings: list) -> None:
    if not findings:
        return

    print(_colored("\n" + "-" * 70, Fore.WHITE))
    print(_colored("  FINDINGS", Fore.RED + Style.BRIGHT))
    print(_colored("-" * 70 + "\n", Fore.WHITE))

    for f in findings:
        severity = f.get("severity", "MEDIUM")
        color = SEVERITY_COLOR.get(severity, Fore.WHITE)
        badge = _colored(f"[{severity}]", color)
        type_label = _colored(f.get("type", "Unknown"), Fore.WHITE + Style.BRIGHT)
        file_info = _colored(f"{f['file']}:{f['line']}", Fore.BLUE)
        content = f.get("content", "")

        print(f"  {badge} {type_label}")
        print(f"    {_colored('File:', Fore.WHITE)} {file_info}")
        print(f"    {_colored('Content:', Fore.WHITE)} {content}")
        print()


def _print_summary(
    total_files: int,
    findings: list,
    report_path: str | None,
) -> None:
    count = len(findings)
    separator = "-" * 70

    print(_colored(separator, Fore.GREEN))

    if count == 0:
        print(_colored("  [OK] No secrets found. Your project looks clean!", Fore.GREEN + Style.BRIGHT))
    else:
        print(
            _colored(
                f"  [!] {count} secret(s) found - review them before committing!",
                Fore.RED + Style.BRIGHT,
            )
        )

    print(_colored(f"  Files analysed : {total_files}", Fore.GREEN))
    print(_colored(f"  Secrets found  : {count}", Fore.GREEN))

    if report_path:
        print(_colored(f"  Report saved   : {report_path}", Fore.GREEN))

    print(_colored(separator, Fore.GREEN))


def _count_files(path: str) -> int:
    """Count scannable files under *path* (mirrors the scanner logic)."""
    root = Path(path).resolve()
    if root.is_file():
        return 1
    total = 0
    ignored_dirs = {".git", "__pycache__", "node_modules", "output",
                    ".venv", "venv", ".tox", "dist", "build", ".mypy_cache"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignored_dirs]
        total += len(filenames)
    return total


def main() -> int:
    colorama_init(autoreset=True)
    _banner()

    parser = _build_parser()
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(_colored(f"  ERROR: Path not found: {args.path}", Fore.RED + Style.BRIGHT))
        return 1

    print(_colored(f"  Scanning: {target.resolve()}", Fore.CYAN))
    if args.verbose:
        print()

    findings = scan_path(str(target), verbose=args.verbose)

    total_files = _count_files(str(target))

    _print_findings(findings)

    report_path: str | None = None
    if args.output and findings:
        os.makedirs("output", exist_ok=True)
        if args.output == "json":
            report_path = os.path.join("output", "report.json")
            export_json(findings, report_path)
        elif args.output == "csv":
            report_path = os.path.join("output", "report.csv")
            export_csv(findings, report_path)

    _print_summary(total_files, findings, report_path)

    # Exit code 1 when secrets found (useful for CI pipelines)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
