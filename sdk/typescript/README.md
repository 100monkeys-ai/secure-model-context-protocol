# SMCP TypeScript SDK

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../../LICENSE)
[![Node.js](https://img.shields.io/badge/node-20%2B-blue)](https://nodejs.org/)
[![Version](https://img.shields.io/badge/version-0.1.0-green)](package.json)

TypeScript/Node.js client SDK for the [Secure Model Context Protocol (SMCP)](../../README.md). Wraps MCP tool calls in cryptographically signed `SmcpEnvelope`s and handles the attestation handshake.

---

## Prerequisites

- Node.js 20 or higher
- npm 10 or higher

---

## Installation

**From npm (once published):**

```bash
npm install @100monkeys/smcp
```

**From source:**

```bash
git clone https://github.com/100monkeys-ai/secure-model-context-protocol.git
cd secure-model-context-protocol/sdk/typescript
npm install
npm run build
```

---

## Usage

### Step 1 — Instantiate the client

```typescript
import { SMCPClient } from "@100monkeys/smcp";

const client = new SMCPClient(
  "https://your-gateway.example.com", // gateway URL
  "exec-abc123",                       // workload ID for this session
  "research-safe",                     // SecurityContext name
);
```

### Step 2 — Attest

Attestation generates an ephemeral Ed25519 keypair and exchanges the public key + `workload_id` for a signed `security_token` (JWT) from the Gateway.

```typescript
const token = await client.attest();
console.log("Token received:", token.substring(0, 20) + "...");
```

The token is stored internally and used automatically on subsequent calls.

### Step 3 — Call a tool

```typescript
const result = await client.callTool("web_search", {
  query: "SMCP specification",
});
console.log(result);
```

### Full example

```typescript
import { SMCPClient } from "@100monkeys/smcp";

const client = new SMCPClient(
  "https://gateway.example.com",
  "exec-abc123",
  "research-safe",
);

try {
  await client.attest();

  const result = await client.callTool("filesystem.read", {
    path: "/workspace/data.json",
  });
  console.log(result);
} finally {
  client.dispose(); // erases ephemeral private key
}
```

---

## API Reference

### `SMCPClient`

```typescript
new SMCPClient(gatewayUrl: string, workloadId: string, securityScope: string)
```

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `gatewayUrl` | `string` | Base URL of the SMCP Gateway (no trailing slash) |
| `workloadId` | `string` | Unique identifier for the current execution session |
| `securityScope` | `string` | Name of the `SecurityContext` to request at attestation |

#### `attest(): Promise<string>`

Generates an ephemeral Ed25519 keypair and performs the attestation handshake against `POST {gatewayUrl}/v1/smcp/attest`. Returns the `security_token` JWT string. Throws `SMCPError` on failure.

#### `callTool(toolName: string, arguments: Record<string, unknown>): Promise<unknown>`

Builds an MCP JSON-RPC `tools/call` payload, wraps it in a signed `SmcpEnvelope`, and sends it to `POST {gatewayUrl}/v1/smcp/invoke`. Returns the `result` field from the response payload. Throws `SMCPError` on Gateway rejection.

Must be called after `attest()`.

#### `dispose(): void`

Zeroes out the ephemeral private key bytes in memory. Call this when the client is no longer needed, ideally in a `finally` block.

---

### `Ed25519Key`

```typescript
import { Ed25519Key } from "@100monkeys/smcp";

const key = await Ed25519Key.generate();
```

| Method | Return type | Description |
| -------- | ------------- | ------------- |
| `static async generate()` | `Promise<Ed25519Key>` | Generates a new ephemeral Ed25519 keypair |
| `async sign(data: Uint8Array)` | `Promise<Uint8Array>` | Signs `data`; returns raw 64-byte signature |
| `async signBase64(data: Uint8Array)` | `Promise<string>` | Signs and returns signature as a Base64 string |
| `getPublicKeyBytes()` | `Uint8Array` | Returns the raw 32-byte public key |
| `getPublicKeyBase64()` | `string` | Returns the public key as a Base64 string |
| `erase()` | `void` | Zeroes private and public key bytes in memory |

---

### `createSmcpEnvelope`

```typescript
import { createSmcpEnvelope } from "@100monkeys/smcp";

const envelope = await createSmcpEnvelope(
  "eyJ...",                          // security_token JWT
  { jsonrpc: "2.0", method: "..." }, // MCP payload
  key,                               // Ed25519Key
);
```

Returns an `SmcpEnvelope` object:

```typescript
interface SmcpEnvelope {
  protocol: "smcp/v1";
  security_token: string;  // JWT
  signature: string;       // Base64-encoded Ed25519 signature
  payload: McpPayload;     // The original MCP JSON-RPC payload
  timestamp: string;       // ISO 8601 timestamp
}
```

### `createCanonicalMessage`

```typescript
import { createCanonicalMessage } from "@100monkeys/smcp";

const messageBytes = createCanonicalMessage(
  "eyJ...",                         // security_token
  { jsonrpc: "2.0", method: "..." }, // payload
  1740000000,                        // Unix timestamp (integer)
);
```

Returns a `Uint8Array` of the UTF-8 encoded canonical JSON (sorted keys, no whitespace) over which the signature is computed.

---

### `verifySmcpEnvelope`

```typescript
import { verifySmcpEnvelope } from "@100monkeys/smcp/server";

const mcpPayload = await verifySmcpEnvelope(
  envelope,
  publicKeyBytes,
  30 // maxAgeSeconds
);
```

Server-side primitive to verify an incoming `SmcpEnvelope`. Reconstructs the canonical message, cryptographically verifies the Ed25519 signature, and checks the timestamp against the allowed replay window to securely unwrap the inner MCP payload.

---

## Error Handling

```typescript
import { SMCPClient, SMCPError } from "@100monkeys/smcp";

const client = new SMCPClient("https://gateway.example.com", "exec-1", "research-safe");

try {
  await client.attest();
} catch (e) {
  if (e instanceof SMCPError) {
    // e.message contains the Gateway error body
    console.error("Attestation failed:", e.message);
  }
}

try {
  await client.callTool("filesystem.write", { path: "/etc/passwd" });
} catch (e) {
  // SMCPError thrown for 4xx/5xx responses
  // 403 → PolicyViolation (path not in capability allowlist)
  console.error("Tool call blocked:", (e as SMCPError).message);
}
```

SMCP error code ranges (RFC §8):

| Range | Category |
| ------- | ---------- |
| `1xxx` | Envelope / token errors (malformed, expired, bad signature) |
| `2xxx` | Policy violations (tool denied, path out of bounds, rate limit) |
| `3xxx` | Attestation failures (unknown workload, rejected scope) |

---

## Running Tests

```bash
npm test
```

> **Known issue — envelope creation test fails:** The `Ed25519Key` constructor calls `ed.getPublicKey()` synchronously from `@noble/ed25519` v2.x, which requires `sha512Sync` to be configured. Without it, the synchronous call throws `"hashes.sha512Sync not set"`.
>
> **Workaround:** Add the following before constructing any `Ed25519Key`:
>
> ```typescript
> import { sha512 } from "@noble/hashes/sha512";
> import * as ed from "@noble/ed25519";
>
> ed.etc.sha512Sync = (...msgs) => sha512(...msgs);
> ```
>
> The canonical message test passes without this change. Full fix (making construction fully async) is tracked for 0.2.0.

---

## License

[MIT](../../LICENSE) © 2026 100monkeys.ai  
[Full SDK reference](../../docs/sdk-reference.md) | [Concepts](../../docs/concepts.md) | [Integration guide](../../docs/integration-guide.md)
