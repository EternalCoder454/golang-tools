# secscan

A dependency-free **pre-push secret scanner**. Walks a directory and flags files
that contain private keys, credentials, API tokens, or secret-looking
assignments — the things you never want to push to a public repo. Exits non-zero
on any HIGH finding, so it drops straight into a git hook or CI step.

## Build

```sh
go build -o secscan .
```

## Usage

```sh
secscan [-q] [-no-entropy] [path ...]      # default path: .
```

- `-q` — only print findings, no summary line.
- `-no-entropy` — disable the high-entropy heuristic (fewer false positives).
- Suppress a known-safe line with a trailing `secscan:ignore` comment.

Exit code is `1` if any **HIGH** finding exists (keys, recognised tokens, secret
assignments), `0` otherwise. WARN findings (key-looking files, high-entropy
strings) are advisory and don't fail.

## What it catches

| Rule | Sev |
|---|---|
| PEM private-key blocks (RSA/EC/OpenSSH/…) | HIGH |
| AWS / GitHub / Slack / Google API keys, JWTs | HIGH |
| `CLUSTER_TOKEN=…`, service-account `private_key_id` | HIGH |
| `password`/`secret`/`token`/`api_key` = long value | HIGH |
| Files named `id_rsa`, `*.key`, `*.pem`, `ca.key`, `*.p12` | WARN |
| High-entropy strings with surrounding context | WARN |

Reported values are **redacted** so the report itself isn't a leak. Findings
inside PEM blocks past the header (public cert bodies) are not re-flagged, and
`.git`, `node_modules`, `vendor`, `dist`, `build` and files > 5 MiB are skipped.

## Git hook

```sh
# .git/hooks/pre-commit
#!/bin/sh
exec secscan -q .
```
