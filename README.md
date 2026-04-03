# Signed Envelope Attestation Layer (SEAL)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-seal%2Fv1-blue)](RFC/seal-v1-specification.md)
[![Python SDK](https://img.shields.io/badge/python_sdk-0.1.0-green)](sdk/python)
[![TypeScript SDK](https://img.shields.io/badge/typescript_sdk-0.14.0--pre--alpha-green)](sdk/typescript)

SEAL is a cryptographic transport protocol that wraps any JSON
payload in a signed, attested envelope — providing cryptographic
identity, bounded authorization, integrity, non-repudiation,
and replay prevention. It is transport-agnostic (HTTP, gRPC,
WebSocket, VSOCK) and payload-agnostic (MCP, REST, custom RPC).
SEAL operates on a zero-trust model: callers are untrusted by
default, and a gateway serves as the root of trust for every
message.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                        Caller                           │
│                                                         │
│  1. Generate ephemeral Ed25519 keypair (never stored)   │
│  2. Attest to Gateway → receive signed security_token   │
│  3. Wrap each request in SealEnvelope                   │
│     { protocol, security_token, signature, payload,     │
│       timestamp }                                       │
└──────────────────────────┬──────────────────────────────┘
                           │  SealEnvelope (over TLS)
                           ▼
┌─────────────────────────────────────────────────────────┐
│              SealMiddleware / Gateway                    │
│                                                         │
│  1. Verify Ed25519 signature (binding: token+payload+ts)│
│  2. Validate security_token JWT (expiry, issuer)        │
│  3. Check timestamp within ±30s replay window           │
│  4. Evaluate SecurityContext via PolicyEngine:           │
│       deny_list → capabilities → default deny           │
│  5. Forward unwrapped payload to downstream service     │
└──────────────────────────┬──────────────────────────────┘
                           │  Unwrapped JSON payload
                           ▼
┌─────────────────────────────────────────────────────────┐
│                  Downstream Service                     │
│     (no SEAL awareness required — receives plain JSON)  │
└─────────────────────────────────────────────────────────┘
```

---

## Core Concepts

| Concept | Description |
| --- | --- |
| **SealEnvelope** | Signed wrapper: version, token, sig, payload, ts. |
| **Attestation** | Proves Ed25519 pubkey + workload ID; returns JWT. |
| **SecurityToken** | JWT binding caller to a SecurityContext. |
| **SecurityContext** | Permission boundary: capabilities + deny list. |
| **Capability** | Tool pattern + allowlists + optional rate limit. |
| **PolicyEngine** | Deny list, then capabilities, then default deny. |

See [docs/concepts.md](docs/concepts.md) for full definitions.

---

## Quickstart

### Python

```python
from seal import SEALClient

client = SEALClient(
    gateway_url="https://your-gateway.example.com",
    workload_id="exec-abc123",
    security_scope="research-safe",
)

# Step 1: Attest — get a signed security_token from the Gateway
token = client.attest()

# Step 2: Call a tool — automatically wrapped in a signed SealEnvelope
result = client.call_tool("web_search", {"query": "SEAL specification"})
print(result)
```

### TypeScript

```typescript
import { SEALClient } from "seal-protocol";

const client = new SEALClient(
  "https://your-gateway.example.com",
  "exec-abc123",
  "research-safe",
);

// Step 1: Attest
await client.attest();

// Step 2: Call a tool
const result = await client.callTool(
  "web_search", { query: "SEAL specification" },
);
console.log(result);

// Clean up ephemeral key
client.dispose();
```

---

## Contents

| Path | Description |
| --- | --- |
| [`RFC/seal-v1-specification.md`](RFC/seal-v1-specification.md) | Full IETF-style protocol specification |
| [`sdk/python/`](sdk/python/) | Python 3.11+ client SDK |
| [`sdk/typescript/`](sdk/typescript/) | TypeScript / Node.js 20+ client SDK |
| [`docs/getting-started.md`](docs/getting-started.md) | Zero-to-first-tool-call walkthrough |
| [`docs/concepts.md`](docs/concepts.md) | Domain terminology and concept definitions |
| [`docs/sdk-reference.md`](docs/sdk-reference.md) | Full Python + TypeScript API reference |
| [`docs/integration-guide.md`](docs/integration-guide.md) | Deploying a Gateway and defining SecurityContexts |
| [`docs/security.md`](docs/security.md) | Threat model, cryptography, compliance |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
Security issues go to `security@100monkeys.ai` —
see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 100monkeys.ai
