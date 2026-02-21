# SMCP Concepts

This document defines the core terms and concepts used throughout SMCP. Use the [Ubiquitous Language](../RFC/smcp-v1-specification.md) consistently — the same terms appear in the RFC, SDKs, and AEGIS orchestrator implementation.

---

## SmcpEnvelope

The **SmcpEnvelope** is the signed wrapper sent by an agent on every tool call. It is an immutable value object — it cannot be modified after construction without invalidating the signature.

**Wire format (JSON):**

```json
{
  "protocol": "smcp/v1",
  "security_token": "<JWT>",
  "signature": "<Base64-encoded Ed25519 signature>",
  "payload": { "<standard MCP JSON-RPC tools/call>" },
  "timestamp": "<ISO 8601 datetime>"
}
```

| Field | Description |
| ------- | ------------- |
| `protocol` | Always `"smcp/v1"`. Used for protocol negotiation and version detection. |
| `security_token` | The JWT issued by the Gateway at attestation. Binds the agent to its `SecurityContext`. |
| `signature` | Ed25519 signature over the canonical message (see [Cryptography](security.md#cryptographic-choices)). |
| `payload` | The underlying MCP JSON-RPC payload. The Tool Server sees only this field after the Gateway unwraps the envelope. |
| `timestamp` | ISO 8601 datetime string (also represented as Unix integer in canonical message). Used for replay prevention (±30s window). |

---

## Attestation

**Attestation** is the one-time handshake at the start of an agent execution session. The agent:

1. Generates an ephemeral Ed25519 keypair (never persisted to disk).
2. Sends the public key + `workload_id` + requested `security_scope` to `POST /smcp/v1/attest`.
3. The Gateway verifies the workload identity (in AEGIS: via Docker API / container ID).
4. The Gateway issues a signed JWT (`security_token`) binding the agent public key to a named `SecurityContext`.

Token lifetime: recommended 1 hour, maximum 24 hours. After expiry, re-attest to get a fresh token.

---

## ContextToken / security_token

The **ContextToken** (called `security_token` in the wire format) is a JWT issued by the Gateway at attestation. It proves:

- **Who** the agent is (`sub` claim: `workload_id`)
- **What** it is authorized to do (`ctx`/`scp` claim: `SecurityContext` name)
- **When** it expires (`iat`, `exp`)

**JWT header:**

```json
{ "alg": "EdDSA", "typ": "JWT" }
```

**JWT claims:**

```json
{
  "sub": "exec-abc123",       // workload_id
  "ctx": "research-safe",     // SecurityContext name
  "iat": 1740000000,          // issued at (Unix)
  "exp": 1740003600           // expires at (Unix, 1hr later)
}
```

The token is signed by the Gateway's root key (in AEGIS: via OpenBao Transit Engine). Agents cannot forge or modify it.

---

## SecurityContext

A **SecurityContext** is a named permission boundary — an Aggregate Root in the domain model. It defines what a given class of agents is permitted to do.

```yaml
name: research-safe
capabilities:
  - tool_pattern: "web_search"
    domain_allowlist:
      - "*.wikipedia.org"
      - "*.arxiv.org"
  - tool_pattern: "filesystem.*"
    path_allowlist:
      - "/workspace"
deny_list:
  - tool_pattern: "filesystem.delete"
```

Policy evaluation order (always):

1. **Deny list first** — if the tool matches any deny rule, the call is immediately blocked (regardless of capabilities).
2. **Capabilities** — if the tool matches an allow capability, the call proceeds.
3. **Default deny** — if nothing matches, the call is blocked.

---

## Capability

A **Capability** is a fine-grained permission entry inside a `SecurityContext`. Each capability specifies:

| Field | Description |
| ------- | ------------- |
| `tool_pattern` | Glob pattern matching tool names (e.g., `"filesystem.*"`, `"web_search"`) |
| `path_allowlist` | Optional. Allowed filesystem paths (must be absolute, no traversal). |
| `command_allowlist` | Optional. Allowed shell commands (if tool invokes commands). |
| `domain_allowlist` | Optional. Allowed network domains (e.g., `"*.arxiv.org"`). |
| `rate_limit` | Optional. Max invocations per minute. |

If a constraint list is absent, no constraint of that type is applied for that capability.

---

## SmcpSession

A **SmcpSession** is an Aggregate Root representing the lifecycle of an agent's SMCP participation within one execution session:

```markdown
attestation → authorized tool calls → (expiry or revocation)
```

The session holds:

- The agent's ephemeral public key (registered at attestation)
- The issued `security_token` and its expiry
- The resolved `SecurityContext`
- Session status: `Active | Expired | Revoked`

A new session begins on each `attest()` call. Sessions are not shared across executions.

---

## PolicyEngine

The **PolicyEngine** is the Gateway component that evaluates every tool call against the agent's `SecurityContext`. It implements the evaluation order described above (deny list → capabilities → default deny).

In the AEGIS orchestrator, the `PolicyEngine` is implemented using [Cedar](https://www.cedarpolicy.com/) — a declarative authorization policy language from AWS. Cedar enables fine-grained, auditable policy evaluation with formal verification properties.

---

## Confused Deputy

The **Confused Deputy** is the class of attack SMCP is designed to prevent. In a standard MCP setup:

1. Agent A calls the Orchestrator with a tool request.
2. The Orchestrator, which holds elevated credentials to reach Tool Servers, forwards the request.
3. The Orchestrator acts as a "deputy" — but it has no way to verify *which* agent issued the request or *whether that agent is authorized* for the specific tool.

An attacker who can inject instructions into agent context (prompt injection) can exploit this to invoke tools the agent was never supposed to call.

SMCP prevents this by:

- Binding every tool call to the agent's ephemeral key via Ed25519 signature (non-repudiation)
- Binding the agent key to a `SecurityContext` via the signed JWT (bounded authorization)
- Evaluating policy at the Gateway on every call, regardless of which physical channel the request arrived on

---

## Field Name Note

The SMCP wire format uses **`security_token`** as the envelope field name. This is authoritative per the RFC specification.

The AEGIS orchestrator's internal Rust implementation uses **`context_token`** as the struct field name. This is an internal implementation detail — the Rust code maps to/from `security_token` during serialization. SDK implementations (Python, TypeScript) and all external/wire usage use `security_token`.

If you see `context_token` in AEGIS source code or ADR-035, it refers to the same concept. The wire format is always `security_token`.

---

## Glossary Quick Reference

| Term | Definition |
| ------ | ----------- |
| **SmcpEnvelope** | Signed wrapper around each MCP tool call |
| **Attestation** | One-time handshake; agent proves public key + workload ID, receives JWT |
| **security_token** | JWT (ContextToken) binding agent to SecurityContext; wire format field name |
| **SecurityContext** | Named permission boundary with capabilities + deny list |
| **Capability** | Fine-grained allow rule with optional path/command/domain/rate constraints |
| **SmcpSession** | Aggregate: agent keypair + token + SecurityContext for one execution |
| **PolicyEngine** | Gateway component; evaluates deny list → capabilities → default deny |
| **Confused Deputy** | Attack class SMCP prevents; unauthorized tool call via privileged proxy |
| **Canonical message** | Sorted-key compact JSON over which signature is computed |
| **Ephemeral keypair** | Ed25519 keys generated per-session, never persisted |
| **workload_id** | Caller-supplied identifier for the current execution (e.g., execution UUID) |
| **Non-repudiation** | Cryptographic proof agent signed the message; agent cannot later deny it |
