import { Ed25519Key } from './crypto';
import { createSealEnvelope, McpPayload } from './envelope';
import crypto from 'crypto';

type AttestationResponse = {
    status?: string;
    message?: string;
    security_token?: string;
    error?: {
        message?: string;
    };
};

type InvokeResponse = {
    error?: {
        message?: string;
    };
    status?: string;
    payload?: {
        error?: unknown;
        result?: unknown;
    };
};

export class SEALError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SEALError';
    }
}

/**
 * A TypeScript client wrapper for generating ephemeral keys, interacting
 * with a SEAL Gateway to undergo an attestation handshake, and securely
 * wrapping Model Context Protocol (MCP) message calls leveraging SEAL.
 */
export class SEALClient {
    private gatewayUrl: string;
    private workloadId: string;
    private securityScope: string;

    private key: Ed25519Key | null = null;
    private securityToken: string | null = null;

    constructor(gatewayUrl: string, workloadId: string, securityScope: string) {
        this.gatewayUrl = gatewayUrl.replace(/\/$/, ''); // Remove trailing slash
        this.workloadId = workloadId;
        this.securityScope = securityScope;
    }

    /**
     * Perform the attestation handshake spanning the gateway's REST endpoint.
     */
    public async attest(): Promise<string> {
        this.key = await Ed25519Key.generate();

        const requestBody = {
            public_key: this.key.getPublicKeyBase64(),
            workload_id: this.workloadId,
            requested_scope: this.securityScope,
        };

        const response = await fetch(`${this.gatewayUrl}/v1/seal/attest`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => null);
            if (errorData && errorData.error && errorData.error.message) {
                throw new SEALError(`Attestation failed: ${errorData.error.message}`);
            }
            throw new SEALError(`Attestation failed: HTTP ${response.status}`);
        }

        const data = (await response.json()) as AttestationResponse;

        if (data.status === 'error') {
            throw new SEALError(`Attestation failed: ${data.message || 'Unknown error'}`);
        }

        this.securityToken = data.security_token ?? null;
        return this.securityToken as string;
    }

    /**
     * Make a SEAL-wrapped JSON-RPC method call to a tool passing through the Gateway.
     */
    public async callTool(toolName: string, argumentsObj: Record<string, unknown>): Promise<unknown> {
        if (!this.securityToken || !this.key) {
            throw new SEALError('No security token available. Must call attest() first.');
        }

        const reqId = `req-${crypto.randomBytes(4).toString('hex')}`;

        const mcpPayload: McpPayload = {
            jsonrpc: '2.0',
            id: reqId,
            method: 'tools/call',
            params: {
                name: toolName,
                arguments: argumentsObj,
            },
        };

        const envelope = await createSealEnvelope(
            this.securityToken,
            mcpPayload,
            this.key
        );

        const response = await fetch(`${this.gatewayUrl}/v1/seal/invoke`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(envelope),
        });

        const responseData = (await response.json().catch(() => null)) as InvokeResponse | null;

        if (!response.ok) {
            if (responseData?.error?.message) {
                throw new SEALError(`SEAL Gateway Rejected: ${responseData.error.message}`);
            }
            throw new SEALError(`SEAL Gateway error: HTTP ${response.status}`);
        }

        if (responseData?.status === 'error' && responseData.error?.message) {
            throw new SEALError(`SEAL Gateway Error: ${responseData.error.message}`);
        }

        const payload = (responseData?.payload ?? {}) as NonNullable<InvokeResponse['payload']>;

        if (payload.error) {
            throw new SEALError(`MCP Tool Error: ${JSON.stringify(payload.error)}`);
        }

        return payload.result || {};
    }

    /**
     * Release ephemeral key material explicitly if possible.
     */
    public dispose(): void {
        if (this.key) {
            this.key.erase();
            this.key = null;
        }
    }
}
