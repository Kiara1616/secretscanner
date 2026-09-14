"""
tests/test_patterns.py – Unit tests for scanner/patterns.py

Each pattern is tested with:
  - At least one string that SHOULD match (true positive)
  - At least one string that should NOT match (no false positive)
"""

import pytest
from secret_scanner.scanner.patterns import PATTERNS

# Build a convenience dict: name → compiled pattern
_PAT = {p["name"]: p["pattern"] for p in PATTERNS}


# ── GitHub Token ───────────────────────────────────────────────────────────
class TestGitHubToken:
    def test_detects_ghp_prefix(self):
        token = "ghp_" + "A" * 36
        assert _PAT["GitHub Token"].search(token)

    def test_detects_gho_prefix(self):
        token = "gho_" + "B" * 36
        assert _PAT["GitHub Token"].search(token)

    def test_detects_ghu_prefix(self):
        token = "ghu_" + "C" * 36
        assert _PAT["GitHub Token"].search(token)

    def test_detects_ghs_prefix(self):
        token = "ghs_" + "D" * 36
        assert _PAT["GitHub Token"].search(token)

    def test_no_false_positive_plain_text(self):
        assert not _PAT["GitHub Token"].search("hello world")

    def test_no_false_positive_short_token(self):
        # Too short after prefix (only 4 chars)
        assert not _PAT["GitHub Token"].search("ghp_abcd")


# ── AWS Access Key ─────────────────────────────────────────────────────────
class TestAWSAccessKey:
    def test_detects_valid_key(self):
        key = "AKIAIOSFODNN7EXAMPLE"  # 20 chars total, classic example
        assert _PAT["AWS Access Key"].search(key)

    def test_detects_key_in_context(self):
        line = 'aws_access_key_id = "AKIAI44QH8DHBEXAMPLE"'
        assert _PAT["AWS Access Key"].search(line)

    def test_no_false_positive_plain_akia(self):
        # AKIA followed by fewer than 16 uppercase-alphanumeric chars
        assert not _PAT["AWS Access Key"].search("AKIA123")

    def test_no_false_positive_random_string(self):
        assert not _PAT["AWS Access Key"].search("this is just text")


# ── Generic API Key ────────────────────────────────────────────────────────
class TestGenericAPIKey:
    def test_detects_double_quotes(self):
        line = 'api_key = "sk-abcdef123456"'
        assert _PAT["Generic API Key"].search(line)

    def test_detects_single_quotes(self):
        line = "api_key = 'sk-abcdef123456'"
        assert _PAT["Generic API Key"].search(line)

    def test_detects_case_insensitive(self):
        line = 'API_KEY = "my_secret_key_value"'
        assert _PAT["Generic API Key"].search(line)

    def test_no_false_positive_no_quotes(self):
        line = "api_key = some_variable"
        assert not _PAT["Generic API Key"].search(line)

    def test_no_false_positive_empty_string(self):
        line = 'api_key = ""'
        assert not _PAT["Generic API Key"].search(line)


# ── Hardcoded Password ─────────────────────────────────────────────────────
class TestHardcodedPassword:
    def test_detects_double_quotes(self):
        line = 'password = "hunter2"'
        assert _PAT["Hardcoded Password"].search(line)

    def test_detects_single_quotes(self):
        line = "password = 's3cr3t!'"
        assert _PAT["Hardcoded Password"].search(line)

    def test_detects_case_insensitive(self):
        line = 'PASSWORD = "Admin@123"'
        assert _PAT["Hardcoded Password"].search(line)

    def test_no_false_positive_no_quotes(self):
        line = "password = my_password_var"
        assert not _PAT["Hardcoded Password"].search(line)

    def test_no_false_positive_too_short(self):
        # Value length < 4
        line = 'password = "ab"'
        assert not _PAT["Hardcoded Password"].search(line)


# ── JWT Token ──────────────────────────────────────────────────────────────
class TestJWTToken:
    VALID_JWT = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )

    def test_detects_valid_jwt(self):
        assert _PAT["JWT Token"].search(self.VALID_JWT)

    def test_detects_jwt_in_line(self):
        line = f'Authorization: Bearer {self.VALID_JWT}'
        assert _PAT["JWT Token"].search(line)

    def test_no_false_positive_plain_eyj(self):
        # Missing second and third segments
        assert not _PAT["JWT Token"].search("eyJhello world")

    def test_no_false_positive_random_text(self):
        assert not _PAT["JWT Token"].search("just some text without a token")


# ── Slack Token ────────────────────────────────────────────────────────────
# NOTE: tokens are built at runtime to avoid triggering GitHub secret scanning.
_SLACK_SUFFIX = "-" + "1" * 11 + "-" + "1" * 11 + "-" + "a" * 16


class TestSlackToken:
    def test_detects_xoxb(self):
        token = "xox" + "b" + _SLACK_SUFFIX
        assert _PAT["Slack Token"].search(token)

    def test_detects_xoxp(self):
        token = "xox" + "p" + _SLACK_SUFFIX
        assert _PAT["Slack Token"].search(token)

    def test_detects_xoxs(self):
        token = "xox" + "s" + _SLACK_SUFFIX
        assert _PAT["Slack Token"].search(token)

    def test_no_false_positive_plain_xox(self):
        assert not _PAT["Slack Token"].search("xox")

    def test_no_false_positive_random_text(self):
        assert not _PAT["Slack Token"].search("slack token here")


# ── RSA Private Key ────────────────────────────────────────────────────────
class TestRSAPrivateKey:
    def test_detects_pem_header(self):
        line = "-----BEGIN RSA PRIVATE KEY-----"
        assert _PAT["RSA Private Key"].search(line)

    def test_detects_in_multiline_context(self):
        text = "some\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK"
        assert _PAT["RSA Private Key"].search(text)

    def test_no_false_positive_ec_key(self):
        line = "-----BEGIN EC PRIVATE KEY-----"
        assert not _PAT["RSA Private Key"].search(line)

    def test_no_false_positive_public_key(self):
        line = "-----BEGIN PUBLIC KEY-----"
        assert not _PAT["RSA Private Key"].search(line)


# ── URL with Credentials ───────────────────────────────────────────────────
class TestURLWithCredentials:
    def test_detects_http_url(self):
        url = "http://user:password@example.com/db"
        assert _PAT["URL with Credentials"].search(url)

    def test_detects_https_url(self):
        url = "https://admin:s3cr3t@myserver.internal:5432/mydb"
        assert _PAT["URL with Credentials"].search(url)

    def test_detects_url_in_config_line(self):
        line = 'DATABASE_URL = "postgresql://myuser:mypass@localhost/mydb"'
        assert _PAT["URL with Credentials"].search(line)

    def test_no_false_positive_url_without_creds(self):
        url = "https://example.com/path?query=1"
        assert not _PAT["URL with Credentials"].search(url)

    def test_no_false_positive_plain_text(self):
        assert not _PAT["URL with Credentials"].search("no url here")
