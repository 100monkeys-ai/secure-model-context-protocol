import { describe, expect, it } from '@jest/globals';
import { createCanonicalMessage, createSmcpEnvelope, McpPayload } from '../src/envelope';
import { Ed25519Key } from '../src/crypto';

describe('SMCP Envelope Canonicalization', () => {
    it('should match RFC 8032 test cases exactly', () => {
        const securityToken = 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl';
        const payload: McpPayload = { jsonrpc: '2.0', id: 1, method: 'test' };
        const timestampUnix = 1708261921;

        const expectedCanonicalString =
            '{"payload":{"id":1,"jsonrpc":"2.0","method":"test"},' +
            '"security_token":"eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl",' +
            '"timestamp":1708261921}';

        const expectedCanonicalBytes = new TextEncoder().encode(expectedCanonicalString);

        const canonicalBytes = createCanonicalMessage(
            securityToken,
            payload,
            timestampUnix
        );

        expect(canonicalBytes).toEqual(expectedCanonicalBytes);
    });

    it('structures the envelope correctly', async () => {
        const key = await Ed25519Key.generate();
        const payload: McpPayload = { jsonrpc: '2.0', id: 1, method: 'test' };
        const token = 'test.token.jwt';

        const envelope = await createSmcpEnvelope(token, payload, key);

        expect(envelope.protocol).toBe('smcp/v1');
        expect(envelope.security_token).toBe(token);
        expect(envelope.payload).toEqual(payload);
        expect(typeof envelope.signature).toBe('string');
        expect(typeof envelope.timestamp).toBe('string');
    });
});
