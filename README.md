# Secure Model Context Protocol (SMCP)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Protocol](https://img.shields.io/badge/protocol-smcp%2Fv1-blue)](RFC/smcp-v1-specification.md)
[![Python SDK](https://img.shields.io/badge/python_sdk-0.1.0-green)](sdk/python)
[![TypeScript SDK](https://img.shields.io/badge/typescript_sdk-0.1.0-green)](sdk/typescript)

> **Join the official RFC discussion here:** <https://github.com/orgs/modelcontextprotocol/discussions/689>

SMCP is a security extension for the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) that adds **cryptographic agent identity**, **bounded-authorization SecurityContexts**, **Ed25519 envelope signing**, and **PolicyEngine enforcement** to every tool call.

Without SMCP, an MCP gateway cannot verify *which* agent is making a request, *what* that agent is permitted to do, or *prove* that the agent made the call at all. This creates the [Confused Deputy Problem](docs/concepts.md#confused-deputy): a privileged gateway forwards tool calls under its own elevated credentials without verifying the caller's authorization. SMCP closes this gap at the protocol layer.

---

## Architecture

```markdown
┌─────────────────────────────────────────────────────────┐
│                     Agent Container                     │
│                                                         │
│  1. Generate ephemeral Ed25519 keypair (never stored)   │
│  2. Attest to Gateway → receive signed security_token   │
│  3. Wrap each tool call in SmcpEnvelope                 │
│     { protocol, security_token, signature, payload,     │
│       timestamp }                                       │
└──────────────────────────┬──────────────────────────────┘
                           │  SmcpEnvelope (over TLS)
                           ▼
┌─────────────────────────────────────────────────────────┐
│              SmcpMiddleware / Gateway                   │
│                                                         │
│  1. Verify Ed25519 signature (binding: token+payload+ts)│
│  2. Validate security_token JWT (expiry, issuer)        │
│  3. Check timestamp within ±30s replay window           │
│  4. Evaluate SecurityContext via PolicyEngine:          │
│       deny_list → capabilities → default deny           │
│  5. Forward unwrapped MCP payload to Tool Server        │
└──────────────────────────┬──────────────────────────────┘
                           │  Standard MCP JSON-RPC
                           ▼
┌─────────────────────────────────────────────────────────┐
│                     Tool Server                         │
│   (no SMCP awareness required — receives plain MCP)     │
└─────────────────────────────────────────────────────────┘
```

---

## Core Concepts

| Concept | Description |
| --------- | ------------- |
| **SmcpEnvelope** | Signed wrapper around each MCP tool call. Wire field: `security_token`. |
| **Attestation** | One-time handshake where the agent proves its Ed25519 public key + workload ID and receives a signed JWT. |
| **ContextToken / security_token** | JWT issued by the Gateway binding the agent to a named `SecurityContext`. |
| **SecurityContext** | Named permission boundary (e.g., `"research-safe"`) defining `capabilities[]` and `deny_list[]`. |
| **Capability** | Fine-grained permission: tool pattern + optional path/command/domain allowlists + rate limit. |
| **PolicyEngine** | Evaluates each tool call: deny list first → match capabilities → default deny. |

See [docs/concepts.md](docs/concepts.md) for full definitions.

---

## Quickstart

### Python

```python
from smcp import SMCPClient

client = SMCPClient(
    gateway_url="https://your-gateway.example.com",
    workload_id="exec-abc123",
    security_scope="research-safe",
)

# Step 1: Attest — get a signed security_token from the Gateway
token = client.attest()

# Step 2: Call a tool — automatically wrapped in a signed SmcpEnvelope
result = client.call_tool("web_search", {"query": "SMCP specification"})
print(result)
```

### TypeScript

```typescript
import { SMCPClient } from "@100monkeys/smcp";

const client = new SMCPClient(
  "https://your-gateway.example.com",
  "exec-abc123",
  "research-safe",
);

// Step 1: Attest
await client.attest();

// Step 2: Call a tool
const result = await client.callTool("web_search", { query: "SMCP specification" });
console.log(result);

// Clean up ephemeral key
client.dispose();
```

---

## Contents

| Path | Description |
| ------ | ------------- |
| [`RFC/smcp-v1-specification.md`](RFC/smcp-v1-specification.md) | Full IETF-style protocol specification |
| [`sdk/python/`](sdk/python/) | Python 3.11+ client SDK |
| [`sdk/typescript/`](sdk/typescript/) | TypeScript / Node.js 20+ client SDK |
| [`docs/getting-started.md`](docs/getting-started.md) | Zero-to-first-tool-call walkthrough |
| [`docs/concepts.md`](docs/concepts.md) | Domain terminology and concept definitions |
| [`docs/sdk-reference.md`](docs/sdk-reference.md) | Full Python + TypeScript API reference |
| [`docs/integration-guide.md`](docs/integration-guide.md) | Integrating SMCP into AEGIS / deploying a gateway |
| [`docs/security.md`](docs/security.md) | Threat model, cryptography, compliance |

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues go to `security@100monkeys.ai` — see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 100monkeys.ai
