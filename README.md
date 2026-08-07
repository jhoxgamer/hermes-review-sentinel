# hermes-review-sentinel — Security Pair Programmer (SPP)

A deterministic + AI security scanner with **auto-fix** and **contextual learning** for Python/TypeScript projects. Runs 100% locally, zero cloud dependencies.

## Quick Start

```bash
# Install
pip install hermes-review-sentinel

# Or run via Docker
docker run --rm -v $(pwd):/workspace jhoxgamer/hermes-review-sentinel:latest . --auto-fix --auto-improve

# Scan + auto-fix secrets + apply contextual improvements
hermes-sentinel . --auto-fix --auto-improve

# Just scan (report only)
hermes-sentinel .
```

## What It Does

| Feature | Description |
|---------|-------------|
| **Auto-Fix Secrets** | Detects hardcoded secrets (Stripe, GitHub, OpenAI, Slack, generic) and replaces with `os.getenv()` / `process.env`, updates `.env.example` |
| **Security Pair Programmer (SPP)** | Learns your project's patterns (auth decorators, CSRF handling, env var style) and suggests/applies improvements |
| **Zero Loss Mutation** | AST-based edits preserve indentation, comments, quotes, formatting |
| **Line Drift Prevention** | Reverse-order editing prevents index corruption on multi-edit files |
| **100% Local / Offline** | Zero cloud calls, runs fully offline with Ollama/local models |
| **Contextual Detection** | Next.js/TS detection restricted to `app/api/`, `pages/api/`, `actions/`, `"use server"` |
| **Performance Filters** | Skips `node_modules`, `venv`, `.git`, files >1MB |

## CLI Usage

```bash
# Scan only (report mode)
hermes-sentinel .

# Auto-fix hardcoded secrets
hermes-sentinel . --auto-fix

# Apply contextual improvements (SPP)
hermes-sentinel . --auto-improve

# Both together
hermes-sentinel . --auto-fix --auto-improve

# Target specific file
hermes-sentinel src/auth.py --auto-fix
```

## Example Output

```
🔍 [Hermes Sentinel] Escaneando 35 arquivo(s)...
✅ [AUTO-FIX] src/auth.py: 2 segredo(s) removido(s) → os.getenv() aplicado.
   └─ Variáveis adicionadas ao .env.example: STRIPE_SECRET_KEY, JWT_SECRET
💡 [SPP] src/routes/admin.py:12
   💡 Rota sem autenticação detectada. Padrão do projeto: `@depends(get_current_user)`.
✨ [SPP] Melhorias aplicadas com sucesso em src/routes/admin.py

📊 [Resumo]
   Arquivos com issues: 2
   Secrets corrigidos: 2
   Melhorias SPP aplicadas: 1
```

## Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│   Source Code   │────▶│  AST Parser      │────▶│  Security       │
│   (Python/TS)   │     │  (ast.parse)     │     │  Pair Programmer│
└─────────────────┘     └──────────────────┘     └────────┬────────┘
                                                          │
                                               ┌──────────▼──────────┐
                                               │  Auto-Fix Engine  │
                                               │  (Zero Loss)      │
                                               └─────────────────────┘
```

## Rules & Patterns

| Category | Patterns |
|----------|----------|
| **Stripe** | `sk_live_*`, `sk_test_*` |
| **GitHub** | `ghp_*`, `gho_*` |
| **OpenAI** | `sk-*` (51 chars) |
| **Slack** | `xoxb-*`, `xoxp-*` |
| **Generic** | `secret_key`, `api_key`, `password`, `token`, `jwt_secret` |

## Configuration

- `rules/python-security.yaml` — P0/P1 security rules for Python/FastAPI
- `rules/typescript-security.yaml` — P0/P1 security rules for TypeScript/Next.js
- `rules/python-quality.yaml` — Clean code / best practices for Python
- `rules/typescript-quality.yaml` — Clean code / best practices for TypeScript

## Installation

```bash
# From PyPI (when published)
pip install hermes-review-sentinel

# From source
git clone https://github.com/jhoxgamer/hermes-review-sentinel.git
cd hermes-review-sentinel
pip install -e .

# Docker
docker build -t hermes-review-sentinel .
docker run --rm -v $(pwd):/workspace hermes-review-sentinel . --auto-fix --auto-improve
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run CLI directly
python -m src.sentinel_server . --auto-fix --auto-improve

# Validate rules
semgrep scan --config=rules/ --test
```

## Security

- **100% Local Execution** — No code leaves your machine
- **No Telemetry** — Zero tracking, zero cloud calls
- **Fail-Safe** — Invalid edits are rolled back automatically

## License

MIT — Free for personal and commercial use.