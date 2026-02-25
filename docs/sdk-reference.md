# SDK Reference

Complete API reference for the SMCP Python and TypeScript SDKs. For a step-by-step tutorial, see [Getting Started](getting-started.md).

---

## Python SDK (`smcp`)

### `SMCPClient` (Python SDK)

The main entry point for interacting with an SMCP Gateway.

```python
from smcp import SMCPClient

client = SMCPClient(
    gateway_url: str,
    workload_id: str,
    security_scope: str,
)
```

#### Constructor (Python SDK)

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `gateway_url` | `str` | Base URL of the SMCP Gateway, no trailing slash (e.g., `https://gateway.example.com`) |
| `workload_id` | `str` | Unique identifier for the current execution session |
| `security_scope` | `str` | Name of the `SecurityContext` to request at attestation |

On construction, an ephemeral `Ed25519Key` is generated. No network calls are made.

#### `attest() -> str`

Performs the SMCP attestation handshake:

1. Serializes the ephemeral public key as Base64.
2. Sends `POST {gateway_url}/v1/smcp/attest` with body:

   ```json
   {
     "public_key": "<Base64 Ed25519 public key>",
     "workload_id": "<workload_id>",
     "requested_scope": "<security_scope>"
   }
   ```

3. Extracts `response["security_token"]` and stores it internally.
4. Returns the raw JWT string.

**Raises:** `requests.HTTPError` on 4xx/5xx responses.

**Must be called before `call_tool()`.**

#### `call_tool(tool_name: str, arguments: dict) -> dict`

Makes a signed tool call:

1. Builds an MCP JSON-RPC payload: `{ "jsonrpc": "2.0", "method": "tools/call", "params": { "name": tool_name, "arguments": arguments }, "id": 1 }`.
2. Creates a `SmcpEnvelope` (calls `create_smcp_envelope` internally).
3. Sends `POST {gateway_url}/v1/smcp/invoke` with the envelope as the body.
4. Returns `response["payload"]["result"]`.

**Raises:** `requests.HTTPError` on Gateway rejection (see [Error Codes](#error-codes)).

#### `__del__()`

Called automatically during garbage collection. Calls `self.key.erase()`.

---

### `Ed25519Key` (Python SDK)

Manages an ephemeral Ed25519 keypair.

```python
from smcp import Ed25519Key

key = Ed25519Key.generate()
```

#### `Ed25519Key.generate() -> Ed25519Key`

Class method. Generates a new Ed25519 keypair using the `cryptography` library. The private key is held only in memory.

#### `sign(data: bytes) -> bytes`

Signs `data` using Ed25519. Returns the raw 64-byte signature.

#### `sign_base64(data: bytes) -> str`

Signs `data` and returns the signature Base64-encoded.

#### `get_public_key_bytes() -> bytes`

Returns the raw 32-byte Ed25519 public key.

#### `get_public_key_base64() -> str`

Returns the public key as a Base64-encoded string.

#### `erase() -> None`

Clears the internal references to the private and public key objects. Due to Python's memory model, this is best-effort — the `cryptography` library's private key object may not be immediately garbage collected. For high-security environments, prefer running in a subprocess and terminating the process when done.

---

### `create_smcp_envelope`

Creates a signed `SmcpEnvelope` dict.

```python
from smcp import create_smcp_envelope

envelope = create_smcp_envelope(
    security_token: str,
    mcp_payload: dict,
    private_key: Ed25519Key,
) -> dict
```

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `security_token` | `str` | JWT obtained from `attest()` |
| `mcp_payload` | `dict` | Standard MCP JSON-RPC payload |
| `private_key` | `Ed25519Key` | The ephemeral keypair to sign with |

**Returns** a `dict`:

```python
{
    "protocol": "smcp/v1",
    "security_token": "<JWT>",
    "signature": "<Base64 Ed25519 signature>",
    "payload": { ... },  # mcp_payload unchanged
    "timestamp": "2026-02-21T12:00:00.000000Z",  # ISO 8601
}
```

The signature is computed over `create_canonical_message(security_token, mcp_payload, timestamp_unix)`.

---

### `create_canonical_message`

Builds the deterministic byte sequence over which the signature is computed.

```python
from smcp import create_canonical_message

message_bytes = create_canonical_message(
    security_token: str,
    payload: dict,
    timestamp_unix: int,
) -> bytes
```

The canonical message is constructed as:

```json
{"payload":{...},"security_token":"<JWT>","timestamp":1740000000}
```

Rules:

- Keys are sorted alphabetically at all levels.
- No whitespace.
- `timestamp` is an integer (Unix seconds), not the ISO string.
- The result is UTF-8 encoded.

This ensures that any two implementations that agree on the inputs will produce an identical byte sequence to verify against.

---

### `verify_smcp_envelope`

Server-side primitive to verify an incoming `SmcpEnvelope`.

```python
from smcp.server import verify_smcp_envelope

mcp_payload = verify_smcp_envelope(
    envelope: dict,
    public_key_bytes: bytes,
    max_age_seconds: int = 30,
) -> dict
```

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `envelope` | `dict` | The incoming JSON payload containing the `SmcpEnvelope` |
| `public_key_bytes` | `bytes` | The raw 32-byte Ed25519 public key of the agent |
| `max_age_seconds` | `int` | The maximum allowed age of the envelope in seconds (default: 30) |

**Returns** the verified `mcp_payload` if successful.

**Raises** `SMCPError` with the appropriate status code (1000-1005) if the envelope format is invalid, the signature is bad, or the timestamp is outside the allowed replay window.

---

## TypeScript SDK (`@100monkeys/smcp`)

### `SMCPClient` (TypeScript SDK)

The main entry point for interacting with an SMCP Gateway.

```typescript
import { SMCPClient } from "@100monkeys/smcp";

const client = new SMCPClient(
  gatewayUrl: string,
  workloadId: string,
  securityScope: string,
);
```

#### Constructor (TypeScript SDK)

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `gatewayUrl` | `string` | Base URL of the SMCP Gateway, no trailing slash |
| `workloadId` | `string` | Unique identifier for the current execution session |
| `securityScope` | `string` | Name of the `SecurityContext` to request at attestation |

On construction, an ephemeral `Ed25519Key` is generated. No network calls are made.

#### `attest(): Promise<string>`

Performs the SMCP attestation handshake:

1. Serializes the ephemeral public key as Base64.
2. Sends `POST {gatewayUrl}/v1/smcp/attest` with body:

   ```json
   {
     "public_key": "<Base64 Ed25519 public key>",
     "workload_id": "<workloadId>",
     "requested_scope": "<securityScope>"
   }
   ```

3. Extracts `response.security_token` and stores it internally.
4. Returns the raw JWT string.

**Throws:** `SMCPError` on 4xx/5xx responses.

**Must be called before `callTool()`.**

#### `callTool(toolName: string, arguments: Record<string, unknown>): Promise<unknown>`

Makes a signed tool call:

1. Builds an MCP JSON-RPC payload.
2. Creates a `SmcpEnvelope` (calls `createSmcpEnvelope` internally).
3. Sends `POST {gatewayUrl}/v1/smcp/invoke` with the envelope as the body.
4. Returns `response.payload.result`.

**Throws:** `SMCPError` on Gateway rejection.

#### `dispose(): void`

Zeroes the private and public key byte arrays. Call this in a `finally` block for correct cleanup.

---

### `SMCPError`

```typescript
class SMCPError extends Error {
  constructor(message: string);
}
```

Thrown by `SMCPClient` methods on HTTP 4xx/5xx responses. The `message` property contains the response body text.

---

### `Ed25519Key` (TypeScript SDK)

Manages an ephemeral Ed25519 keypair.

```typescript
import { Ed25519Key } from "@100monkeys/smcp";

const key = await Ed25519Key.generate();
```

#### `static async generate(): Promise<Ed25519Key>`

Generates a new Ed25519 keypair using `@noble/ed25519`. The private key is held only in memory as a `Uint8Array`.

> **Known issue:** The `Ed25519Key` constructor synchronously calls `ed.getPublicKey()` from `@noble/ed25519` v2.x, which requires `sha512Sync` to be set. If you are calling `Ed25519Key.generate()` in a context where `@noble/hashes` is not already configured, add:
>
> ```typescript
> import { sha512 } from "@noble/hashes/sha512";
> import * as ed from "@noble/ed25519";
> ed.etc.sha512Sync = (...msgs) => sha512(...msgs);
> ```
>
> Fix tracked for SDK 0.2.0.

#### `async sign(data: Uint8Array): Promise<Uint8Array>`

Signs `data`. Returns a 64-byte Ed25519 signature.

#### `async signBase64(data: Uint8Array): Promise<string>`

Signs `data` and returns the signature as a Base64 string.

#### `getPublicKeyBytes(): Uint8Array`

Returns the raw 32-byte public key.

#### `getPublicKeyBase64(): string`

Returns the public key as a Base64 string.

#### `erase(): void`

Fills the private and public key `Uint8Array`s with zeros.

---

### `createSmcpEnvelope`

```typescript
import { createSmcpEnvelope } from "@100monkeys/smcp";

const envelope = await createSmcpEnvelope(
  securityToken: string,
  mcpPayload: McpPayload,
  privateKey: Ed25519Key,
): Promise<SmcpEnvelope>
```

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `securityToken` | `string` | JWT from `attest()` |
| `mcpPayload` | `McpPayload` | Standard MCP JSON-RPC payload |
| `privateKey` | `Ed25519Key` | The ephemeral keypair to sign with |

**Returns** an `SmcpEnvelope`:

```typescript
interface SmcpEnvelope {
  protocol: "smcp/v1";
  security_token: string;
  signature: string;        // Base64 Ed25519
  payload: McpPayload;
  timestamp: string;        // ISO 8601
}
```

#### `McpPayload` interface

```typescript
interface McpPayload {
  jsonrpc: "2.0";
  method: string;
  params?: Record<string, unknown>;
  id?: number;
}
```

---

### `createCanonicalMessage`

```typescript
import { createCanonicalMessage } from "@100monkeys/smcp";

const messageBytes = createCanonicalMessage(
  securityToken: string,
  payload: McpPayload,
  timestampUnix: number,
): Uint8Array
```

Produces the UTF-8 canonical JSON byte sequence (sorted keys, no whitespace, integer timestamp) over which the signature is computed. Deterministic across Python and TypeScript implementations given the same inputs.

---

### `verifySmcpEnvelope`

Server-side primitive to verify an incoming `SmcpEnvelope`.

```typescript
import { verifySmcpEnvelope } from "@100monkeys/smcp/server";

const mcpPayload = await verifySmcpEnvelope(
  envelope: any,
  publicKeyBytes: Uint8Array,
  maxAgeSeconds: number = 30,
): Promise<McpPayload>
```

| Parameter | Type | Description |
| ----------- | ------ | ------------- |
| `envelope` | `any` | The incoming JSON payload containing the `SmcpEnvelope` |
| `publicKeyBytes` | `Uint8Array` | The raw 32-byte Ed25519 public key of the agent |
| `maxAgeSeconds` | `number` | The maximum allowed age of the envelope in seconds (default: 30) |

**Returns** the verified `mcpPayload` object if successful.

**Throws** `SMCPError` if the envelope format is invalid, the signature is bad, or the timestamp is outside the allowed ±30s replay window.

---

## Error Codes

SMCP error codes are returned in the response body when the Gateway rejects a request. All SDKs throw/raise on these responses.

| Code range | HTTP status | Category | Description |
| ------------ | ------------- | ---------- | ------------- |
| `1000` | 401 | Malformed envelope | Required fields missing or wrong type |
| `1001` | 401 | Invalid signature | Ed25519 verification failed |
| `1002` | 401 | Expired token | `security_token` past `exp` claim |
| `1003` | 401 | Invalid token | JWT signature invalid or unknown issuer |
| `1004` | 401 | Replay detected | Timestamp outside ±30 second window |
| `1005` | 401 | Invalid protocol | `protocol` field not `"smcp/v1"` |
| `2000` | 403 | Tool not allowed | No matching capability for this tool name |
| `2001` | 403 | Tool explicitly denied | Tool matched the `deny_list` |
| `2002` | 403 | Path not in allowlist | File path outside `path_allowlist` |
| `2003` | 403 | Path traversal attempt | Path contained `../` or similar |
| `2004` | 403 | Domain not allowed | Network domain not in `domain_allowlist` |
| `2005` | 403 | Rate limit exceeded | Tool call frequency exceeded `rate_limit` |
| `3000` | 401 | Attestation rejected | Workload identity could not be verified |
| `3001` | 403 | Unknown security scope | Requested `SecurityContext` does not exist |
| `3002` | 401 | Keypair mismatch | Public key does not match container's registered key |
