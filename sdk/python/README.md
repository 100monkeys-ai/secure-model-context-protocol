# SMCP Python SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-green)](pyproject.toml)

Python client SDK for the [Secure Model Context Protocol (SMCP)](../../README.md). Wraps MCP tool calls in cryptographically signed `SmcpEnvelope`s and handles the attestation handshake.

---

## Prerequisites

- Python 3.11 or higher
- Dependencies installed automatically: `cryptography>=41.0.0`, `requests>=2.30.0`, `pydantic>=2.4.0`

---

## Installation

**From PyPI (once published):**

```bash
pip install smcp
```

**Editable install from source:**

```bash
git clone https://github.com/100monkeys-ai/secure-model-context-protocol.git
cd secure-model-context-protocol
pip install -e "sdk/python[dev]"
```

---

## Usage

### Step 1 — Instantiate the client

```python
from smcp import SMCPClient

client = SMCPClient(
    gateway_url="https://your-gateway.example.com",
    workload_id="exec-abc123",          # Unique ID for this execution session
    security_scope="research-safe",     # Named SecurityContext on the Gateway
)
```

### Step 2 — Attest

Attestation is a one-time handshake that generates an ephemeral Ed25519 keypair and exchanges the public key + `workload_id` for a signed `security_token` (JWT).

```python
token = client.attest()
print(f"Token received: {token[:20]}...")
```

The token is stored internally. You do not need to pass it to subsequent calls.

### Step 3 — Call a tool

Each call to `call_tool()` automatically wraps the MCP payload in a signed `SmcpEnvelope` and sends it to the Gateway.

```python
result = client.call_tool(
    "web_search",
    {"query": "SMCP specification"},
)
print(result)
```

### Full example

```python
from smcp import SMCPClient

client = SMCPClient(
    gateway_url="https://gateway.example.com",
    workload_id="exec-abc123",
    security_scope="research-safe",
)

client.attest()

result = client.call_tool("filesystem.read", {"path": "/workspace/data.json"})
print(result)
```

The `__del__` method calls `Ed25519Key.erase()` automatically. For explicit cleanup:

```python
del client  # or let it go out of scope
```

---

## API Reference

### `SMCPClient`

```python
SMCPClient(gateway_url: str, workload_id: str, security_scope: str)
```

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `gateway_url` | `str` | Base URL of the SMCP Gateway (no trailing slash) |
| `workload_id` | `str` | Unique identifier for the current execution session |
| `security_scope` | `str` | Name of the `SecurityContext` to request at attestation |

#### `attest() -> str`

Generates an ephemeral Ed25519 keypair and performs the attestation handshake against `POST {gateway_url}/smcp/v1/attest`. Stores the returned `security_token` internally. Returns the raw JWT string.

Raises `requests.HTTPError` if the Gateway rejects the request.

#### `call_tool(tool_name: str, arguments: dict) -> dict`

Builds an MCP JSON-RPC payload for `tools/call`, wraps it in a signed `SmcpEnvelope`, sends it to `POST {gateway_url}/smcp/v1/tool-call`, and returns `response["payload"]["result"]`.

Must be called after `attest()`.

---

### `Ed25519Key`

```python
from smcp import Ed25519Key

key = Ed25519Key.generate()
```

| Method | Return | Description |
| -------- | -------- | ------------- |
| `Ed25519Key.generate()` | `Ed25519Key` | Generates a new ephemeral Ed25519 keypair |
| `sign(data: bytes) -> bytes` | `bytes` | Signs `data` with the private key; returns raw 64-byte signature |
| `sign_base64(data: bytes) -> str` | `str` | Signs and returns the signature as a Base64-encoded string |
| `get_public_key_bytes() -> bytes` | `bytes` | Returns the raw 32-byte Ed25519 public key |
| `get_public_key_base64() -> str` | `str` | Returns the public key as a Base64-encoded string |
| `erase()` | `None` | Clears private key references from memory (best-effort in Python) |

---

### `create_smcp_envelope`

```python
from smcp import create_smcp_envelope

envelope = create_smcp_envelope(
    security_token="eyJ...",    # JWT from attest()
    mcp_payload={"jsonrpc": "2.0", ...},
    private_key=key,
)
```

Returns a `dict` with the fields:

```json
{
  "protocol": "smcp/v1",
  "security_token": "<JWT>",
  "signature": "<Base64-Ed25519>",
  "payload": { "<MCP JSON-RPC>" },
  "timestamp": "<ISO 8601>"
}
```

### `create_canonical_message`

```python
from smcp import create_canonical_message

message_bytes = create_canonical_message(
    security_token="eyJ...",
    payload={"jsonrpc": "2.0", ...},
    timestamp_unix=1740000000,
)
```

Returns the UTF-8 encoded bytes of the deterministic canonical JSON (sorted keys, no whitespace) over which the signature is computed.

---

### `verify_smcp_envelope`

```python
from smcp.server import verify_smcp_envelope

payload = verify_smcp_envelope(
    envelope={"protocol": "smcp/v1", ...},
    public_key_bytes=key.get_public_key_bytes(),
    max_age_seconds=30
)
```

Server-side primitive to verify an incoming `SmcpEnvelope`. Reconstructs the canonical message, cryptographically verifies the Ed25519 signature, and checks the timestamp against the allowed replay window to securely unwrap the inner MCP payload.

---

## Error Handling

```python
import requests
from smcp import SMCPClient

client = SMCPClient("https://gateway.example.com", "exec-1", "research-safe")

try:
    client.attest()
except requests.HTTPError as e:
    # 401 → attestation rejected (invalid workload_id or unknown scope)
    # 403 → security scope not found
    print(f"Attestation failed: {e.response.status_code}")

try:
    result = client.call_tool("filesystem.write", {"path": "/etc/passwd"})
except requests.HTTPError as e:
    # 403 → PolicyViolation (path not in capability allowlist)
    print(f"Tool call blocked: {e.response.status_code}")
```

SMCP error codes returned in the response body follow the RFC §8 classification:

| Range | Category |
| ------- | ---------- |
| `1xxx` | Envelope / token errors (malformed, expired, bad signature) |
| `2xxx` | Policy violations (tool not allowed, path out of bounds, rate limit) |
| `3xxx` | Attestation failures (unknown workload, rejected scope) |

---

## Running Tests

```bash
pytest sdk/python/tests/ -v
```

---

## License

[MIT](../../LICENSE) © 2026 100monkeys.ai  
[Full SDK reference](../../docs/sdk-reference.md) | [Concepts](../../docs/concepts.md) | [Integration guide](../../docs/integration-guide.md)
