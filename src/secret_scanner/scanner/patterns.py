"""
patterns.py – Compiled regex patterns for detecting secrets and credentials.

Each entry in PATTERNS is a dict with:
    name     – human-readable label for the finding type
    pattern  – compiled re.Pattern object
    severity – "HIGH" | "MEDIUM" | "LOW"
"""

import re

PATTERNS = [
    {
        "name": "GitHub Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"(ghp_|gho_|ghu_|ghs_)[A-Za-z0-9_]{36,}"
        ),
    },
    {
        "name": "AWS Access Key",
        "severity": "HIGH",
        "pattern": re.compile(
            r"AKIA[0-9A-Z]{16}"
        ),
    },
    {
        "name": "Generic API Key",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'api[_-]?key\s*=\s*["\']([A-Za-z0-9\-_]{8,})["\']',
            re.IGNORECASE,
        ),
    },
    {
        "name": "Hardcoded Password",
        "severity": "HIGH",
        "pattern": re.compile(
            r'password\s*=\s*["\']([^"\']{4,})["\']',
            re.IGNORECASE,
        ),
    },
    {
        "name": "JWT Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"
        ),
    },
    {
        "name": "Slack Token",
        "severity": "HIGH",
        "pattern": re.compile(
            r"xox[baprs]-[0-9A-Za-z\-]{10,}"
        ),
    },
    {
        "name": "RSA Private Key",
        "severity": "HIGH",
        "pattern": re.compile(
            r"-----BEGIN RSA PRIVATE KEY-----"
        ),
    },
    {
        "name": "URL with Credentials",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r"\w[\w+\-.]*://[^:@\s]+:[^:@\s]+@[^\s]+"
        ),
    },
]
