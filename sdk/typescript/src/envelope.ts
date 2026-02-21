import { Ed25519Key } from './crypto';

/**
 * Standard standard json-rpc definition constraints matching MCP payloads.
 */
export interface McpPayload {
    jsonrpc: string;
    id: string | number;
    method: string;
    params?: Record<string, any>;
}

/**
 * High-fidelity wrapping envelope structure capturing security rules.
 */
export interface SmcpEnvelope {
    protocol: string;
    security_token: string;
    signature: string;
    payload: McpPayload;
    timestamp: string;
}

/**
 * Construct democratic, deterministic message byte sequence for signing/verification.
 * Following RFC canonical definitions.
 */
export function createCanonicalMessage(
    securityToken: string,
    payload: McpPayload,
    timestampUnix: number
): Uint8Array {
    const message = {
        security_token: securityToken,
        payload: payload,
        timestamp: timestampUnix,
    };

    // Stringify with sorted keys and no whitespaces
    const canonicalJson = stableStringify(message);

    // Encode into utf-8 arrays for signing boundaries
    return new TextEncoder().encode(canonicalJson);
}

/**
 * Helper to stringify an object with keys sorted alphabetically.
 */
function stableStringify(obj: any): string {
    if (obj === null || typeof obj !== 'object') {
        return JSON.stringify(obj);
    }

    if (Array.isArray(obj)) {
        const len = obj.length;
        let res = '[';
        for (let i = 0; i < len; i++) {
            res += (i ? ',' : '') + stableStringify(obj[i]);
        }
        res += ']';
        return res;
    }

    const keys = Object.keys(obj).sort();
    let res = '{';
    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        if (obj[key] !== undefined) {
            res += (i ? ',' : '') + JSON.stringify(key) + ':' + stableStringify(obj[key]);
        }
    }
    res += '}';
    return res;
}

/**
 * Wrap an MCP JSON-RPC payload in an SMCP Security Envelope v1.
 */
export async function createSmcpEnvelope(
    securityToken: string,
    mcpPayload: McpPayload,
    privateKey: Ed25519Key
): Promise<SmcpEnvelope> {
    const now = new Date();

    // Create precisely formatted timestamps
    const timestampIso = now.toISOString();
    // Math.floor required to resolve unix equivalent properly
    const timestampUnix = Math.floor(now.getTime() / 1000);

    const canonicalBytes = createCanonicalMessage(
        securityToken,
        mcpPayload,
        timestampUnix
    );

    const signatureB64 = await privateKey.signBase64(canonicalBytes);

    return {
        protocol: 'smcp/v1',
        security_token: securityToken,
        signature: signatureB64,
        payload: mcpPayload,
        timestamp: timestampIso,
    };
}
