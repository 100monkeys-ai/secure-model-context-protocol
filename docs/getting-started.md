# Getting Started with SMCP

This guide walks you through making your first cryptographically secured tool call using SMCP, from zero to a signed, authorized request.

---

## What You Need Before Starting

- An SMCP-compatible Gateway URL (e.g., `https://gateway.example.com`)
- A `SecurityContext` name defined on that Gateway (e.g., `research-safe`)
- A `workload_id` that identifies your current execution session (e.g., a UUID or execution ID)

If you are deploying a Gateway, see the [Integration Guide](integration-guide.md) for how to configure `SecurityContext`s and expose the Gateway endpoint.

---

## How SMCP Works in Three Steps

```markdown
1. Generate ephemeral Ed25519 keypair (client side, never stored)
         │
         ▼
2. Attest  ─── POST /v1/smcp/attest ──►  Gateway
         ◄── security_token (JWT) ────────┘
         │
         ▼
3. Call tool with signed SmcpEnvelope
         │
         ├── security_token  (JWT, proves identity + SecurityContext)
         ├── signature       (Ed25519 over canonical message)
         ├── payload         (standard MCP JSON-RPC tools/call)
         └── timestamp       (Unix integer, replay prevention)
         │
         ─── POST /v1/smcp/invoke ──►  Gateway
                                          │  verify sig
                                          │  validate JWT
                                          │  check timestamp ±30s
                                          │  evaluate policy
                                          └─► Tool Server (plain MCP)
```

---

## Step 1: Install

### Python (Install)

```bash
pip install smcp
# or from source:
pip install -e "sdk/python[dev]"
```

### TypeScript (Install)

```bash
npm install @100monkeys/smcp
# or from source:
cd sdk/typescript && npm install && npm run build
```

---

## Step 2: Generate a Keypair

SMCP uses **ephemeral Ed25519 keypairs** — generated fresh for each execution session, never written to disk.

### Python (Generate a Keypair)

```python
from smcp import Ed25519Key

key = Ed25519Key.generate()
print("Public key:", key.get_public_key_base64())
# The private key never leaves this process
```

### TypeScript (Generate a Keypair)

```typescript
import { Ed25519Key } from "@100monkeys/smcp";

const key = await Ed25519Key.generate();
console.log("Public key:", key.getPublicKeyBase64());
```

---

## Step 3: Attest

Send your public key and `workload_id` to the Gateway. The Gateway verifies your workload identity, finds the requested `SecurityContext`, and returns a signed JWT (`security_token`).

### Python (Attest)

```python
from smcp import SMCPClient

client = SMCPClient(
    gateway_url="https://gateway.example.com",
    workload_id="exec-abc123",
    security_scope="research-safe",
)

token = client.attest()
print("Attested. Token:", token[:30] + "...")
```

### TypeScript (Attest)

```typescript
import { SMCPClient } from "@100monkeys/smcp";

const client = new SMCPClient(
  "https://gateway.example.com",
  "exec-abc123",
  "research-safe",
);

const token = await client.attest();
console.log("Attested. Token:", token.substring(0, 30) + "...");
```

The token is stored internally by the client. You do not pass it around manually.

---

## Step 4: Make a Tool Call

Each `call_tool` / `callTool` invocation automatically:

1. Builds the MCP JSON-RPC payload
2. Creates a canonical message (sorted-key JSON, UTF-8 encoded)
3. Signs it with the ephemeral private key
4. Wraps everything in a `SmcpEnvelope`
5. Sends it to the Gateway

### Python

```python
result = client.call_tool(
    "web_search",
    {"query": "Model Context Protocol security"},
)
print(result)
```

### TypeScript

```typescript
const result = await client.callTool("web_search", {
  query: "Model Context Protocol security",
});
console.log(result);
```

---

## Step 5: Clean Up

The ephemeral private key should be erased when the session ends.

### Python (Clean Up)

```python
del client  # __del__ calls key.erase() automatically
```

### TypeScript (Clean Up)

```typescript
client.dispose();  // zeroes key bytes in memory
```

Use `try/finally` in production to ensure cleanup even if a call throws:

```typescript
const client = new SMCPClient(url, workloadId, scope);
try {
  await client.attest();
  const result = await client.callTool("my_tool", { arg: "value" });
  return result;
} finally {
  client.dispose();
}
```

---

## What a `SmcpEnvelope` Looks Like

```json
{
  "protocol": "smcp/v1",
  "security_token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJleGVjLWFiYzEyMyIsImN0eCI6InJlc2VhcmNoLXNhZmUiLCJleHAiOjE3NDAwMDM2MDB9.<sig>",
  "signature": "BASE64_ED25519_SIGNATURE",
  "payload": {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "web_search",
      "arguments": { "query": "Model Context Protocol security" }
    },
    "id": 1
  },
  "timestamp": "2026-02-21T12:00:00Z"
}
```

The **`security_token`** field is the canonical wire format name (per RFC). The Gateway verifies the `signature` covers the canonical message built from `security_token`, `payload`, and `timestamp`.

---

## Next Steps

- [Concepts](concepts.md) — understand `SecurityContext`, `Capability`, `PolicyEngine`, and the full domain model
- [SDK Reference](sdk-reference.md) — complete Python and TypeScript API documentation
- [Integration Guide](integration-guide.md) — deploy a Gateway, define `SecurityContext`s, and integrate SMCP into your orchestration layer
- [Security](security.md) — threat model, cryptographic choices, and compliance details
