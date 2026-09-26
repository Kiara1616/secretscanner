# Security policy

## Supported versions

Security fixes are provided for the latest published version of SecretScanner.

## Reporting a vulnerability

Please do not disclose vulnerabilities, bypasses or real credentials in public issues.

Use [GitHub private vulnerability reporting](https://github.com/Kiara1616/secretscanner/security/advisories/new) to send:

- the affected version;
- a clear description and potential impact;
- reproduction steps or a minimal proof of concept;
- any proposed mitigation, if available.

You should receive an initial response within seven days. Reports will be investigated privately, and a coordinated disclosure date will be agreed upon when a fix is required.

## Handling detected secrets

SecretScanner reports are sensitive. Do not commit reports containing real credentials. Revoke and rotate any exposed credential; deleting it from the current file alone does not remove it from Git history.
