import { describe, expect, it } from '@jest/globals';
import { verifySealEnvelope } from '../src/server';
import { createSealEnvelope, McpPayload } from '../src/envelope';
import { Ed25519Key } from '../src/crypto';
import { SEALError } from '../src/client';
import { createCanonicalMessage } from '../src/envelope';

describe('SEAL Server Verification', () => {
    it('verifies a valid envelope', async () => {
        const key = await Ed25519Key.generate();
        const payload: McpPayload = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
        const token = 'test.jwt.token';

        const envelope = await createSealEnvelope(token, payload, key);

        const verifiedPayload = await verifySealEnvelope(envelope, key.getPublicKeyBytes());

        expect(verifiedPayload).toEqual(payload);
    });

    it('rejects tampered payload', async () => {
        const key = await Ed25519Key.generate();
        const payload: McpPayload = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
        const envelope = await createSealEnvelope('token', payload, key);

        // Tamper with the payload
        const tamperedEnvelope = {
            ...envelope,
            payload: { ...envelope.payload, id: 2 }
        };

        await expect(verifySealEnvelope(tamperedEnvelope, key.getPublicKeyBytes()))
            .rejects.toThrow(SEALError);
    });

    it('rejects expired envelope', async () => {
        const key = await Ed25519Key.generate();
        const payload: McpPayload = { jsonrpc: '2.0', id: 1, method: 'tools/call' };
        const oldTimeUnix = Math.floor(Date.now() / 1000) - 40;
        const timestampIso = new Date(oldTimeUnix * 1000).toISOString();

        const canonical = createCanonicalMessage('token', payload, oldTimeUnix);
        const signature = await key.signBase64(canonical);

        const expiredEnvelope = {
            protocol: 'seal/v1',
            security_token: 'token',
            signature: signature,
            payload: payload,
            timestamp: timestampIso
        };

        await expect(verifySealEnvelope(expiredEnvelope, key.getPublicKeyBytes()))
            .rejects.toThrow(/outside the allowed/);
    });

    it('rejects wrong public key', async () => {
        const key1 = await Ed25519Key.generate();
        const key2 = await Ed25519Key.generate();
        const payload: McpPayload = { jsonrpc: '2.0', id: 1, method: 'tools/call' };

        const envelope = await createSealEnvelope('token', payload, key1);

        await expect(verifySealEnvelope(envelope, key2.getPublicKeyBytes()))
            .rejects.toThrow(/verification failed/);
    });
});
