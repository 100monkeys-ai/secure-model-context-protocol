import { Ed25519Key } from './crypto';
import { createSmcpEnvelope, McpPayload } from './envelope';
import crypto from 'crypto';

export class SMCPError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'SMCPError';
    }
}

/**
 * A TypeScript client wrapper for generating ephemeral keys, interacting
 * with an SMCP Gateway to undergo an attestation handshake, and securely
 * wrapping Model Context Protocol (MCP) message calls leveraging SMCP.
 */
export class SMCPClient {
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

        const response = await fetch(`${this.gatewayUrl}/v1/smcp/attest`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody),
        });

        if (!response.ok) {
            const errorData = await response.json().catch(() => null);
            if (errorData && errorData.error && errorData.error.message) {
                throw new SMCPError(`Attestation failed: ${errorData.error.message}`);
            }
            throw new SMCPError(`Attestation failed: HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'error') {
            throw new SMCPError(`Attestation failed: ${data.message || 'Unknown error'}`);
        }

        this.securityToken = data.security_token;
        return this.securityToken as string;
    }

    /**
     * Make an SMCP-wrapped JSON-RPC method call to a tool passing through the Gateway.
     */
    public async callTool(toolName: string, argumentsObj: Record<string, any>): Promise<any> {
        if (!this.securityToken || !this.key) {
            throw new SMCPError('No security token available. Must call attest() first.');
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

        const envelope = await createSmcpEnvelope(
            this.securityToken,
            mcpPayload,
            this.key
        );

        const response = await fetch(`${this.gatewayUrl}/v1/smcp/invoke`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(envelope),
        });

        const responseData = await response.json().catch(() => null);

        if (!response.ok) {
            if (responseData && responseData.error && responseData.error.message) {
                throw new SMCPError(`SMCP Gateway Rejected: ${responseData.error.message}`);
            }
            throw new SMCPError(`SMCP Gateway error: HTTP ${response.status}`);
        }

        if (responseData && responseData.status === 'error') {
            throw new SMCPError(`SMCP Gateway Error: ${responseData.error.message}`);
        }

        const payload = responseData?.payload || {};

        if (payload.error) {
            throw new SMCPError(`MCP Tool Error: ${JSON.stringify(payload.error)}`);
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
