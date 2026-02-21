# Security Policy

## Supported Versions

| Component | Version | Supported |
| ----------- | --------- | ----------- |
| SMCP Protocol | `smcp/v1` | ✅ Yes |
| Python SDK | `0.1.0` | ✅ Yes |
| TypeScript SDK | `0.1.0` | ✅ Yes |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email `security@100monkeys.ai` with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if applicable)
- The affected component(s) and versions

You will receive an acknowledgment within 2 business days. We aim to provide a remediation plan within 14 days for critical issues and 30 days for lower-severity findings.

We ask that you give us reasonable time to address the issue before any public disclosure.

---

## Threat Model

SMCP is designed to defend against the following attack classes. Understanding the threat model helps identify what constitutes a genuine security issue versus a deployment concern.

### Confused Deputy Attack

**What it is:** An attacker tricks a privileged component (the orchestrator) into misusing its authority — e.g., by injecting a tool call that the orchestrator forwards under its own elevated credentials, even though the requesting agent is not authorized for that action.

**How SMCP prevents it:** Every tool call is wrapped in a `SmcpEnvelope` containing a `security_token` (JWT) that cryptographically binds the request to the agent's `SecurityContext`. The `PolicyEngine` evaluates the caller's capabilities on every call — even if the physical channel is the orchestrator itself.

### Prompt Injection

**What it is:** Malicious content in a tool response tricks the agent into issuing subsequent tool calls the user did not intend.

**How SMCP prevents it:** The `SecurityContext` establishes an immutable capability boundary at attestation time. Injected instructions cannot expand the agent's `Capability` set at runtime because the `security_token` is signed by the orchestrator's root key and cannot be forged by the agent.

### Tool Server Impersonation

**What it is:** A compromised or rogue tool server claims to be a different (trusted) tool server.

**How SMCP prevents it:** The protocol enforces identity at the agent level (agent → gateway direction). Tool server authenticity is enforced at the physical layer by the Orchestrator Proxy (routing) and TLS (transport). SMCP does not add server-side certificates but is designed to compose with mutual TLS.

### Replay Attacks

**What it is:** An attacker captures a valid `SmcpEnvelope` and re-submits it to execute a tool call a second time.

**How SMCP prevents it:** Every envelope includes a `timestamp` field (Unix integer). The gateway rejects envelopes whose timestamp falls outside a ±30-second window from the current time. The Ed25519 signature binds the timestamp to the envelope, so an attacker cannot alter it.

---

## Protocol Security Guarantees

| Property | Mechanism |
| ---------- | ----------- |
| **Authentication** | Ed25519 ephemeral keypair; agent attests its public key + workload ID at session start |
| **Authorization** | `SecurityContext` capabilities evaluated on every tool call (deny-list first, then capabilities, default deny) |
| **Integrity** | Ed25519 signature over canonical JSON (sorted keys, UTF-8, Unix timestamp) |
| **Non-repudiation** | Signature binds tool call to agent's ephemeral private key; audit log persisted by gateway |
| **Replay prevention** | 30-second timestamp window enforced by gateway |
| **Confidentiality** | Out of scope for SMCP itself; TLS 1.3+ at the transport layer is required |

## Key Management

- **Client (agent) keys:** Ed25519 keypairs are ephemeral — generated per execution session, never written to disk, erased from memory when the session ends (`Ed25519Key.erase()`).
- **Gateway signing keys:** The orchestrator's root signing key (used to issue `security_token` JWTs) is managed via KMS/HSM (OpenBao Transit Engine in the AEGIS deployment). Gateway keys must be rotated at least every 90 days.

## Out of Scope

The following are deployment concerns, not SMCP protocol vulnerabilities:

- TLS termination and certificate management
- Network segmentation between orchestrator and tool servers
- Host OS security and container isolation (covered by AEGIS runtime policies)
- DoS protection at the network layer

## Compliance

SMCP is designed to support the following compliance frameworks. See [docs/security.md](docs/security.md) for the full compliance mapping:

- SOC 2 Type II (CC6.1, CC6.6, CC6.8)
- GDPR Article 25 (Data Protection by Design)
- NIST AI Risk Management Framework
- ISO 27001
