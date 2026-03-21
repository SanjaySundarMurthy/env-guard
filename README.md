# env-guard

[![CI](https://github.com/SanjaySundarMurthy/env-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/SanjaySundarMurthy/env-guard/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/env-guard-cli)](https://pypi.org/project/env-guard-cli/)
[![PyPI](https://img.shields.io/pypi/v/env-guard-cli)](https://pypi.org/project/env-guard-cli/)

**Environment variable validation, secret detection, and .env file management CLI.**

[![PyPI version](https://badge.fury.io/py/env-guard-cli.svg)](https://pypi.org/project/env-guard-cli/)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Features

- **Validate .env files** — detect missing, empty, or malformed variables
- **Secret scanning** — find hardcoded secrets in source code and .env files
- **Schema validation** — validate against `.env.schema.json` rules (types, formats, required fields)
- **File diffing** — compare `.env` vs `.env.example` or any two env files
- **Auto-sync** — add missing keys from `.env.example` to `.env`
- **Generate templates** — create `.env.example` or `.env.schema.json` from existing `.env`
- **Health scoring** — A+ to F grade for your environment configuration
- **Weak secret detection** — flag common/default passwords

## Installation

```bash
pip install env-guard-cli
```

## Quick Start

```bash
# Scan current directory
env-guard scan

# Validate against a schema
env-guard check --schema .env.schema.json

# Compare .env with .env.example
env-guard diff .env .env.example

# Sync missing keys from .env.example
env-guard sync

# Scan for hardcoded secrets in source files
env-guard secrets

# Generate .env.example from .env
env-guard init

# View .env contents (secrets masked)
env-guard show .env
```

## Commands

### `env-guard scan`

Full environment scan — validates variables, detects secrets, and generates a health score.

```bash
env-guard scan [PATH]
env-guard scan --env-file .env.production
env-guard scan --schema .env.schema.json
env-guard scan --no-secrets          # Skip source file scanning
env-guard scan --strict              # Exit 1 on any issue
```

**Output includes:**
- Health grade (A+ to F) and score (0-100)
- Missing required variables
- Empty values, weak secrets
- Naming convention violations
- Hardcoded secrets in source files

### `env-guard check`

Validate `.env` against a schema file with type checking and format rules.

```bash
env-guard check --schema .env.schema.json
env-guard check --schema schema.json --env-file .env.production
env-guard check --schema schema.json --strict
```

**Schema format** (`.env.schema.json`):

```json
{
  "variables": [
    {
      "key": "DATABASE_URL",
      "required": true,
      "type": "url",
      "description": "PostgreSQL connection string"
    },
    {
      "key": "PORT",
      "required": true,
      "type": "port"
    },
    {
      "key": "LOG_LEVEL",
      "type": "enum",
      "allowed_values": ["debug", "info", "warn", "error"]
    },
    {
      "key": "API_KEY",
      "required": true,
      "type": "string",
      "min_length": 20,
      "secret": true
    }
  ]
}
```

**Supported types:** `string`, `integer`, `float`, `boolean`, `url`, `email`, `port`, `path`, `json`, `enum`

### `env-guard diff`

Compare two environment files side by side.

```bash
env-guard diff .env .env.example
env-guard diff .env.staging .env.production
```

Shows:
- Variables missing in each file
- Variables with different values (secrets masked)
- Summary statistics

### `env-guard sync`

Sync `.env` with `.env.example` — adds missing keys with placeholder values.

```bash
env-guard sync                      # Auto-detect files
env-guard sync --dry-run            # Preview without writing
env-guard sync --env-file .env.local --example-file .env.example
```

### `env-guard secrets`

Scan source files for hardcoded secrets.

```bash
env-guard secrets                   # Scan current directory
env-guard secrets src/              # Scan specific directory
env-guard secrets --include-env     # Also scan .env file values
```

**Detects:**
- AWS access keys and secrets
- GitHub/GitLab/Slack tokens
- JWT tokens
- Private keys
- Connection strings with credentials
- Hardcoded passwords and API keys

### `env-guard show`

Display `.env` file contents with secret values masked.

```bash
env-guard show .env
env-guard show .env.production
```

### `env-guard init`

Generate `.env.example` or `.env.schema.json` from an existing `.env` file.

```bash
env-guard init                              # Generate .env.example
env-guard init --output schema              # Generate .env.schema.json
env-guard init --env-file .env.production   # From specific file
env-guard init --force                      # Overwrite existing
```

## Health Scoring

| Grade | Score   | Description                    |
|-------|---------|--------------------------------|
| A+    | 100     | Perfect — no issues            |
| A     | 90-99   | Excellent — minor issues only  |
| B     | 80-89   | Good — some warnings           |
| C     | 70-79   | Fair — needs attention         |
| D     | 60-69   | Poor — significant issues      |
| F     | < 60    | Critical — immediate action    |

## CI/CD Integration

```yaml
# GitHub Actions
- name: Validate environment
  run: |
    pip install env-guard-cli
    env-guard scan --strict
    env-guard check --schema .env.schema.json --strict
```

```yaml
# GitLab CI
validate-env:
  script:
    - pip install env-guard-cli
    - env-guard scan --strict
```

## License

MIT License — see [LICENSE](LICENSE) for details.

## Author

**Sanjay Sundar Murthy** — [GitHub](https://github.com/SanjaySundarMurthy)


## 🐳 Docker

Run without installing Python:

```bash
# Build the image
docker build -t env-guard .

# Run
docker run --rm env-guard --help

# Example with volume mount
docker run --rm -v ${PWD}:/workspace env-guard [command] /workspace
```

Or pull from the container registry:

```bash
docker pull ghcr.io/SanjaySundarMurthy/env-guard:latest
docker run --rm ghcr.io/SanjaySundarMurthy/env-guard:latest --help
```

## 🤝 Contributing

Contributions are welcome! Here's how:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please ensure tests pass before submitting:

```bash
pip install env-guard-cli
pytest -v
ruff check .
```

## 🔗 Links

- **PyPI**: [https://pypi.org/project/env-guard-cli/](https://pypi.org/project/env-guard-cli/)
- **GitHub**: [https://github.com/SanjaySundarMurthy/env-guard](https://github.com/SanjaySundarMurthy/env-guard)
- **Issues**: [https://github.com/SanjaySundarMurthy/env-guard/issues](https://github.com/SanjaySundarMurthy/env-guard/issues)