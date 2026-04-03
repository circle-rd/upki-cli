# Contributing to uPKI CLI

Thank you for your interest in contributing to uPKI CLI. This document provides guidelines and best practices for contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Architecture](#architecture)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Reporting Issues](#reporting-issues)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We are committed to providing a welcoming and safe experience for everyone.

- Be respectful and inclusive in your communications
- Accept constructive criticism positively
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

1. **Fork the repository** — Click the "Fork" button on GitHub to create your own copy
2. **Clone your fork** — `git clone https://github.com/YOUR_USERNAME/upki-cli.git`
3. **Add upstream remote** — `git remote add upstream https://github.com/circle-rd/upki-cli.git`
4. **Create a branch** — `git checkout -b feature/your-feature-name`

## Development Environment

### Prerequisites

- Python 3.11 or higher
- Git
- A running uPKI RA instance (for integration testing)

### Setup

```bash
# Clone the repository
git clone https://github.com/circle-rd/upki-cli.git
cd upki-cli

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Architecture

uPKI CLI is structured as a thin command-line wrapper around an ACME v2 client:

```
client/
  acme_client.py   — ACME v2 client (RFC 8555): account key, JWS signing,
                     certificate enrollment, renewal, revocation, CRL fetch.
                     Uses httpx + cryptography; no subprocess openssl.
  bot.py           — High-level coordinator: CA cert management, browser
                     integration (certutil/pk12util), delegation to AcmeClient.
  collection.py    — Local node registry (cli.nodes.json).
  upkiLogger.py    — Logging helper.
```

### Key design decisions

- **No josepy dependency** — JWS flattened JSON format is implemented directly using `cryptography`.
- **No subprocess openssl** — CSR and PKCS#12 generation use `cryptography` builders.
- **EC P-256 account key** — Stored at `<data_dir>/acme_account.key`, loaded on subsequent runs.
- **RFC 7638 thumbprint** — Computed over `{"crv","kty","x","y"}` in lexicographic order.
- **Flattened JSON JWS** — `{"protected","payload","signature"}` as required by RFC 8555.
- **P1363 EC signatures** — `r || s` byte format used in JWS (not DER).

## Coding Standards

### Style

- Follow [PEP 8](https://peps.python.org/pep-0008/) with a line length of 100.
- Use f-strings for string formatting (no `.format()` or `%`).
- Use type annotations for all public function signatures.
- Use `from __future__ import annotations` for Python 3.11+ forward-reference support.

### Dead code policy

- **No deprecated code** — Remove it entirely.
- **No backward-compatibility shims** — Break cleanly and document in release notes.
- **No commented-out code** in commits.

### Error handling

- Use `raise ... from err` when re-raising exceptions to preserve the chain.
- Only validate at system boundaries (user input, HTTP responses, file I/O).
- Do not add defensive guards for conditions the caller guarantees.

### Security

- Never log private key material.
- Store key files with mode `0o400` (owner read-only).
- Store account config files with mode `0o600`.
- CA certificate is write-protected at `0o444` after installation.

## Testing

Currently the CLI does not have unit tests (ACME integration is tested in upki-ra). When adding tests:

- Unit test pure logic (e.g. `_b64url`, `_thumbprint`) without network access.
- Mock `httpx.Client` for ACME endpoint tests.
- Do not write tests that shell out to `openssl`.

## Submitting Changes

### Pull Request Process

1. **Write clear commit messages** following [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` — new feature
   - `fix:` — bug fix
   - `refactor:` — code change that neither fixes a bug nor adds a feature
   - `docs:` — documentation only
   - `chore:` — maintenance (deps, CI, etc.)

2. **Keep PRs focused** — one logical change per PR.

3. **Update documentation** if you change behavior visible to users.

4. **Pass CI** — ensure `pip install -r requirements.txt` completes and there are no import errors.

### Branch Naming

- `feature/short-description`
- `fix/short-description`
- `refactor/short-description`

## Reporting Issues

When filing a bug report, please include:

- Python version (`python --version`)
- OS name and version
- Steps to reproduce
- Expected vs actual behaviour
- Relevant log output (redact any private key or password material)

For security vulnerabilities, please **do not open a public issue**. Contact the maintainers directly.
