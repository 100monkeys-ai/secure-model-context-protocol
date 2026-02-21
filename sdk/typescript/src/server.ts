import * as ed from '@noble/ed25519';
import { createCanonicalMessage, McpPayload, SmcpEnvelope } from './envelope';
import { SMCPError } from './client';

/**
 * Server-side primitive to verify an incoming SmcpEnvelope.
 * 
 * 1. Checks if the envelope format is valid.
 * 2. Validates timestamp freshness against current server time.
 * 3. Reconstructs the canonical message.
 * 4. Cryptographically verifies the Ed25519 signature.
 * 
 * @param envelope The incoming JSON payload containing the SmcpEnvelope.
 * @param publicKeyBytes The raw 32-byte Ed25519 public key of the agent.
 * @param maxAgeSeconds The maximum allowed age of the envelope in seconds.
 * @returns The verified MCP JSON-RPC payload.
 * @throws SMCPError If verification fails.
 */
export async function verifySmcpEnvelope(
    envelope: any,
    publicKeyBytes: Uint8Array,
    maxAgeSeconds: number = 30
): Promise<McpPayload> {
    // 1. Validate envelope structure
    if (envelope.protocol !== 'smcp/v1') {
        throw new SMCPError("Missing or invalid 'protocol' field. Expected 'smcp/v1'.");
    }

    const securityToken = envelope.security_token;
    if (!securityToken || typeof securityToken !== 'string') {
        throw new SMCPError("Missing or invalid 'security_token' field.");
    }

    const signatureB64 = envelope.signature;
    if (!signatureB64 || typeof signatureB64 !== 'string') {
        throw new SMCPError("Missing or invalid 'signature' field.");
    }

    const payload = envelope.payload;
    if (!payload || typeof payload !== 'object') {
        throw new SMCPError("Missing or invalid 'payload' field.");
    }

    const timestampIso = envelope.timestamp;
    if (!timestampIso || typeof timestampIso !== 'string') {
        throw new SMCPError("Missing or invalid 'timestamp' field.");
    }

    // 2. Check Timestamp limits
    const timestampMs = Date.parse(timestampIso);
    if (isNaN(timestampMs)) {
        throw new SMCPError("Invalid 'timestamp' format. Expected ISO 8601.");
    }

    const timestampUnix = Math.floor(timestampMs / 1000);
    const currentTimeMs = Date.now();
    const currentTimeUnix = Math.floor(currentTimeMs / 1000);

    if (Math.abs(currentTimeUnix - timestampUnix) > maxAgeSeconds) {
        throw new SMCPError(`Envelope timestamp is outside the allowed ±${maxAgeSeconds}s window.`);
    }

    // 3. Canonicalize message
    let canonicalMsg: Uint8Array;
    try {
        canonicalMsg = createCanonicalMessage(securityToken, payload as McpPayload, timestampUnix);
    } catch (e: any) {
        throw new SMCPError(`Failed to construct canonical message: ${e.message}`);
    }

    // 4. Verify Signature
    let signatureBytes: Uint8Array;
    try {
        signatureBytes = Buffer.from(signatureB64, 'base64');
    } catch (e) {
        throw new SMCPError("Invalid base64 encoding for 'signature'.");
    }

    let isValid = false;
    try {
        isValid = await ed.verifyAsync(signatureBytes, canonicalMsg, publicKeyBytes);
    } catch (e) {
        throw new SMCPError("Ed25519 signature verification failed.");
    }

    if (!isValid) {
        throw new SMCPError("Ed25519 signature verification failed.");
    }

    return payload as McpPayload;
}
