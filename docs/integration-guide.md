# Integration Guide

This guide explains how SMCP fits into an orchestrator stack, how to deploy a Gateway, and how to define `SecurityContext`s for your agents.

---

## Where SMCP Sits in the Stack

SMCP operates at the **protocol layer**, on top of the physical security boundary already provided by the Orchestrator Proxy pattern.

```markdown
┌─────────────────────────────────────────────────────────────┐
│                         Agent Container                     │
│  SMCP SDK:  generate keypair → attest → sign envelopes      │
└──────────────────────────────┬──────────────────────────────┘
                               │  SmcpEnvelope (over TLS)
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                   Orchestrator — SmcpMiddleware                │
│                                                             │
│  Physical layer:  Orchestrator Proxy Pattern                │
│    - All agent tool calls physically route through here     │
│    - Internal tools executed via Runtime::exec()            │
│    - External tools executed with orchestrator credentials  │
│                                                             │
│  Protocol layer:  SMCP                                      │
│    - AttestationService: verify workload, issue JWT         │
│    - SmcpMiddleware: verify signature, validate JWT         │
│    - PolicyEngine (Cedar): evaluate SecurityContext         │
│    - Unwrap → forward plain MCP to Tool Server              │
└──────────────────────────────┬──────────────────────────────┘
                               │  Standard MCP JSON-RPC
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                        Tool Server                          │
│  (No SMCP awareness — receives ordinary MCP JSON-RPC)       │
└─────────────────────────────────────────────────────────────┘
```

The physical proxy layer ensures requests are routed correctly and credentials are held by the orchestrator, not agents. SMCP adds protocol-level identity and authorization enforcement. Both layers are required; neither alone provides complete security.

---

## Gateway Endpoints

The SMCP Gateway exposes two endpoints:

### `POST /smcp/v1/attest`

**Request body:**

```json
{
  "public_key": "<Base64 Ed25519 public key>",
  "workload_id": "<execution session ID>",
  "requested_scope": "<SecurityContext name>"
}
```

**Success response (200):**

```json
{
  "status": "attested",
  "security_token": "<JWT>",
  "expires_at": "2026-02-21T13:00:00Z",
  "session_id": "<SmcpSession UUID>"
}
```

**Failure responses:**

- `401` — workload identity could not be verified (error code `3000` or `3002`)
- `403` — requested `SecurityContext` not found (error code `3001`)

### `POST /smcp/v1/tool-call`

**Request body:** A complete `SmcpEnvelope` JSON object.

**Success response (200):**

```json
{
  "payload": {
    "jsonrpc": "2.0",
    "result": { ... },
    "id": 1
  }
}
```

**Failure responses:**

- `401` — envelope verification failed (signature, JWT, timestamp; error codes `1xxx`)
- `403` — policy violation (error codes `2xxx`)

---

## Defining SecurityContexts

A `SecurityContext` is a named permission boundary. Agents request a `SecurityContext` by name at attestation.

### Example `SecurityContext`s

These examples are taken from RFC Appendix A:

#### `read-only-research`

Allows web search and read-only filesystem access within `/workspace`:

```yaml
name: read-only-research
capabilities:
  - tool_pattern: "web_search"
    domain_allowlist:
      - "*.wikipedia.org"
      - "*.arxiv.org"
      - "*.scholar.google.com"
  - tool_pattern: "filesystem.read"
    path_allowlist:
      - "/workspace"
  - tool_pattern: "filesystem.list"
    path_allowlist:
      - "/workspace"
deny_list:
  - tool_pattern: "filesystem.write"
  - tool_pattern: "filesystem.delete"
  - tool_pattern: "shell.*"
```

#### `code-assistant`

Allows read/write filesystem access and git operations within a project directory:

```yaml
name: code-assistant
capabilities:
  - tool_pattern: "filesystem.*"
    path_allowlist:
      - "/workspace/project"
  - tool_pattern: "git.*"
    path_allowlist:
      - "/workspace/project"
  - tool_pattern: "shell.run"
    command_allowlist:
      - "npm test"
      - "cargo test"
      - "pytest"
deny_list:
  - tool_pattern: "filesystem.delete"
    # Restrict delete to be explicit
  - tool_pattern: "shell.run"
    # Denies unlisted commands (deny_list evaluated first)
```

> **Note:** The `deny_list` is evaluated before capabilities. A tool matching any deny rule is blocked regardless of whether it also matches a capability.

#### `admin-unrestricted`

Full access — intended for trusted orchestrator-level tooling only:

```yaml
name: admin-unrestricted
capabilities:
  - tool_pattern: "*"
deny_list: []
```

---

## Token Lifetime

| Setting                           | Recommended   | Maximum    |
|-----------------------------------|---------------|------------|
| Token lifetime                    | 1 hour        | 24 hours   |
| Key rotation (Gateway signing key)| Every 90 days | —          |

Short-lived tokens limit the blast radius of a stolen JWT. The signature binding (agent's ephemeral private key → token) provides an additional layer: a stolen token is useless without the corresponding private key.

For long-running agents, implement token renewal by calling `attest()` again before the token expires.

---

## Gateway Key Signing (OpenBao)

In a production deployment, the Gateway should **not** hold its signing key directly. Instead, it should use a **KMS Transit Engine** (Encryption-as-a-Service):

```markdown
AttestationService  →  Transit Engine API (sign)  →  KMS
                                                      │
                                                      └─ Ed25519 key
                                                         managed by KMS
                                                         never distributed
```

This implements the **Keymaster Pattern**: the key material never leaves the HSM/KMS. Compromise of the orchestrator process does not expose the signing key.

The JWT is signed with EdDSA (`alg: EdDSA` in the JWT header). Verification requires the Gateway's public key, which can be fetched from a well-known endpoint or distributed out-of-band for SDK use.

---

## Workload Identity Verification

During attestation, the Gateway must verify that the `workload_id` maps to a real, currently running execution. For example:

- **Container runtime:** The Gateway checks the container runtime API to confirm a container with the matching execution ID is running, and cross-references the submitted public key with what was registered at container start.
- **VM runtime:** Similar verification via the hypervisor management API.

This step prevents attackers from forging attestation requests with arbitrary `workload_id`s.

---

## Multi-tenant Namespace Isolation

In multi-tenant deployments, `SecurityContext`s are scoped to namespaces. For example, using OpenBao namespaces to isolate per-tenant secrets and signing keys:

```markdown
tenant-acme/
  SecurityContexts:
    - research-safe      (Acme-specific domain allowlists)
    - code-assistant     (Acme-specific path boundaries)

tenant-beta/
  SecurityContexts:
    - research-safe      (Beta-specific domain allowlists — different from Acme's)
```

Namespace isolation ensures that two tenants with a `SecurityContext` named `research-safe` cannot cross-access each other's resources even if names collide.

---

## Audit Event Integration

Every SMCP operation should publish domain events to an audit event store. These events power the audit trail and compliance reporting:

| Event | Description |
| ------- | ------------- |
| `AttestationSucceeded` | Agent attested; session created |
| `AttestationFailed` | Attestation rejected; reason logged |
| `ToolCallAuthorized` | Tool call passed PolicyEngine; forwarded to Tool Server |
| `PolicyViolationBlocked` | Tool call rejected; violation type and details logged |
| `SignatureVerificationFailed` | Envelope signature invalid |
| `ContextTokenExpired` | Agent's JWT expired mid-session |
| `SessionRevoked` | Gateway revoked the session (e.g., execution cancelled) |

---

## Phase 2: Firecracker + VSOCK Transport

SMCP is transport-agnostic. In the current Docker-based deployment, the agent communicates with the Gateway over TCP/TLS. In the Phase 2 Firecracker deployment:

- The `SmcpEnvelope` is transmitted over VSOCK (virtual socket between the MicroVM and host).
- No changes to the agent-side SDK are required — the envelope format and endpoints are identical.
- The Gateway-side `SmcpMiddleware` adds a VSOCK listener alongside the existing TCP listener.

This is possible because the `SmcpEnvelope` is transport-agnostic: it contains all the identity and authorization information needed for stateless verification, regardless of how it was delivered.

---

## Further Reading

- [RFC smcp-v1-specification](../RFC/smcp-v1-specification.md) — full protocol specification including test vectors and compliance mapping
- [OpenBao Transit Engine](https://openbao.org/docs/secrets/transit/) — encryption-as-a-service for Gateway key signing
- [Cedar Policy Language](https://www.cedarpolicy.com/) — declarative policy engine for SecurityContext evaluation
