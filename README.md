# 🔐 Secret Scanner CI

[![CI](https://github.com/txltedxgod/secret-scanner-ci/actions/workflows/ci.yml/badge.svg)](https://github.com/txltedxgod/secret-scanner-ci/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![DevSecOps](https://img.shields.io/badge/Security-DevSecOps%20Pipeline-red.svg)](#architecture)
[![Pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit)](https://pre-commit.com/)

High-speed DevSecOps pre-commit and CI/CD secret scanner. Detects leaked API keys, tokens, cryptographic private keys, and high-entropy credentials in source code and Git diffs using Shannon entropy analysis and regex signatures.

---

## 🎬 Feature Demo

<p align="center">
  <img src="assets/demo.gif" alt="Secret Scanner CI Feature Demo — Pre-Commit & CI/CD Secret Scanner with Shannon Entropy" width="840" />
</p>
<p align="center">
  <sub><a href="assets/demo.mp4">Watch / Download 1080p60 MP4</a></sub>
</p>

---
---

## 🏛️ Detection Pipeline & Architecture

```mermaid
flowchart TD
    Input[Code Base / Git Diff / API Payload] --> Router{Input Type}
    
    Router -->|Unified Git Diff| DiffParser[Hunk Parser: extract added lines only]
    Router -->|Raw Text / Config| Lexer[Token Stream]
    
    DiffParser --> Lexer
    
    Lexer --> SigMatch[Rule Signature Matcher]
    Lexer --> EntropyEngine[Shannon Entropy Analyzer]
    
    SigMatch -->|Known Pattern: AWS, GitHub, Stripe, etc.| FPCheck{False Positive Check}
    EntropyEngine -->|Entropy >= 4.5 + Proximity Keywords| FPCheck
    
    FPCheck -->|Contains PLACEHOLDER, CHANGEME, etc.| Ignore[Suppress Finding]
    FPCheck -->|True Credential| Classifier[Severity & Location Mapper]
    
    Classifier --> Redact[Mask Secret: AKIAIO...PLE]
    Redact --> Output[JSON Finding: file, line, col, severity]
    
    Output --> CIExit[CI/CD Gate: Fail PR if CRITICAL / HIGH]
    Output --> RESTAPI[FastAPI Endpoint /api/v1/scan]
```

---

## ✨ Key Features

- **Multi-Cloud & SaaS Signature Library**: Pre-configured high-precision regex signatures for AWS Access Keys, AWS Secret Keys, GitHub PATs (`ghp_`, `gho_`), GitLab Tokens (`glpat-`), Stripe Live Keys (`sk_live_`), Slack Tokens (`xoxb-`), OpenAI (`sk-`), Anthropic (`sk-ant-`), JWTs, and PEM Private Keys.
- **Shannon Entropy Analysis**: Mathematical entropy calculation ($-\sum p \log_2 p$) detects unformatted high-randomness passwords and secret strings when correlated with credential keywords.
- **Git Diff Scanner**: Efficiently parses unified Git diffs (e.g. `git diff HEAD~1`) to scan only newly added lines (`+`), completely ignoring removed lines (`-`).
- **Contextual Line & Column Mapping**: Pinpoints exact 1-based line and column coordinates of every leak.
- **False-Positive Suppression**: Automatically ignores documentation placeholders (`YOUR_KEY`, `CHANGEME`, `PLACEHOLDER`).
- **Safe Masked Output**: Never leaks cleartext secrets in logs or CI output (e.g. `AKIAIO...`).

---

## 🚀 Quickstart

### Local Installation

```bash
git clone https://github.com/txltedxgod/secret-scanner-ci.git
cd secret-scanner-ci

python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Run Tests

```bash
pytest -v tests/
```

### Start REST API Server

```bash
uvicorn scanner.api:app --host 0.0.0.0 --port 8000 --reload
```

---

## 📡 REST API Reference

### 1. Scan Raw Content
`POST /api/v1/scan`

**Request Payload:**
```json
{
  "content": "export GITHUB_TOKEN='ghp_REDACTED_EXAMPLE_TOKEN_FOR_DOCS_XYZ'"
}
```

**Response (200 OK):**
```json
{
  "has_secrets": true,
  "total_findings": 1,
  "findings": [
    {
      "rule": "GitHub Token",
      "rule_id": "SEC003",
      "severity": "CRITICAL",
      "matched": "ghp_AB...",
      "start": 21,
      "end": 63,
      "line": 1,
      "column": 22,
      "entropy": 4.86
    }
  ]
}
```

### 2. Scan Staged Git Diff
`POST /api/v1/scan/diff`

Inspects additions across pull requests or pre-commit hooks, mapping findings back to their respective filenames and line numbers.

---

## 🛡️ License

MIT License. See [LICENSE](LICENSE) for details.
