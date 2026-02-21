# Contributing to Secure Model Context Protocol

Thank you for your interest in contributing to SMCP. This project has three contribution tracks:

1. [RFC Protocol Changes](#rfc-protocol-changes) — changes to the wire format or protocol semantics
2. [Python SDK](#python-sdk)
3. [TypeScript SDK](#typescript-sdk)

Read the relevant section below before opening a PR. All contributions are subject to the [Code of Conduct](CODE_OF_CONDUCT.md).

---

## General Guidelines

- Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) for all commit messages:
  - `feat:` — new capability
  - `fix:` — bug fix
  - `docs:` — documentation only
  - `refactor:` — code restructure without behavior change
  - `test:` — adding or updating tests
  - `chore:` — build/tooling changes

- Open an issue before starting significant work so we can discuss the approach.
- Keep PRs focused. One logical change per PR.
- All PRs require at least one review from a maintainer.

---

## RFC Protocol Changes

The `RFC/smcp-v1-specification.md` document is the canonical definition of the SMCP wire format. SDKs conform to it.

**Important naming note:** The wire format field is `security_token` (RFC-authoritative). The AEGIS orchestrator's internal Rust implementation uses `context_token` as a struct field name — this is an internal implementation detail and does not affect the wire format or SDK implementations.

### Process

1. **Open an issue** describing the protocol change, the problem it solves, and any backward-compatibility implications.
2. Wait for maintainer acknowledgment before drafting RFC text.
3. Submit a PR to `RFC/smcp-v1-specification.md` with your changes clearly marked with the section being modified.
4. RFC changes require consensus from at least two maintainers before merge, given the protocol stability implications.
5. Protocol changes that break backward compatibility must include a migration path and bump the protocol version.

---

## Python SDK

### Prerequisites (Python)

- Python 3.11 or higher
- [`hatchling`](https://hatch.pypa.io/) (installed via `pip`)

### Setup (Python)

```bash
# Clone the repo
git clone https://github.com/100monkeys-ai/secure-model-context-protocol.git
cd secure-model-context-protocol

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install the Python SDK in editable mode with dev deps
pip install -e "sdk/python[dev]"
```

### Running Tests (Python)

```bash
pytest sdk/python/tests/
```

### Coding Standards (Python)

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- All public functions and classes must have docstrings.
- Use type hints throughout.
- Security-sensitive values (tokens, private key bytes) must never appear in log output or exception messages.
- `Ed25519Key.erase()` must be called when a key is no longer needed. Ensure it is called in `__del__` as a safety net.

### Adding a Test (Python)

Tests live in `sdk/python/tests/`. Add a file named `test_<module>.py`. Use `pytest` conventions.

---

## TypeScript SDK

### Prerequisites (TypeScript)

- Node.js 20 or higher
- npm 10 or higher

### Setup (TypeScript)

```bash
cd sdk/typescript
npm install
```

### Building (TypeScript)

```bash
npm run build
```

### Running Tests (TypeScript)

```bash
npm test
```

> **Known issue:** One test (`envelope creation`) currently fails due to a `sha512Sync` configuration requirement in `@noble/ed25519` v2. See [sdk/typescript/README.md](sdk/typescript/README.md) for details and a workaround. The canonical message test passes.

### Coding Standards (TypeScript)

- Strict TypeScript (`strict: true` in `tsconfig.json`). No `any` without a comment explaining why.
- All public API surface must have JSDoc comments.
- Security-sensitive values (tokens, private key bytes) must never appear in thrown error messages or console output.
- Call `key.erase()` / `client.dispose()` when keys are no longer needed. Use `try/finally` in tests.
- `async/await` over raw Promises.

### Adding a Test (TypeScript)

Tests live in `sdk/typescript/__tests__/`. Use `jest` conventions with `ts-jest`.

---

## Docs

Documentation lives in `docs/`. Docs changes can be submitted as standalone PRs without a code change. Ensure all internal links (`docs/`, SDK READMEs, RFC section anchors) remain valid.

---

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. Email `security@100monkeys.ai` instead. See [SECURITY.md](SECURITY.md) for details.
