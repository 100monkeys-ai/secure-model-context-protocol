import * as ed from '@noble/ed25519';

/**
 * Manages ephemeral Ed25519 cryptographic keys for the SMCP Protocol.
 * Keys are generated dynamically and stored only in memory per execution
 * for high security according to the SMCP spec.
 */
export class Ed25519Key {
    private privateKey: Uint8Array | null = null;
    private publicKey: Uint8Array | null = null;

    private constructor() { }

    /**
     * Generate a new ephemeral Ed25519 keypair.
     */
    public static async generate(): Promise<Ed25519Key> {
        const key = new Ed25519Key();
        key.privateKey = ed.utils.randomPrivateKey();
        // Asynchronously derive public key to avoid synchronous hash dependency in Node
        key.publicKey = await ed.getPublicKeyAsync(key.privateKey);
        return key;
    }

    /**
     * Produce an Ed25519 signature of the given canonical message bytes.
     */
    public async sign(message: Uint8Array): Promise<Uint8Array> {
        if (!this.privateKey) {
            throw new Error("Private key has been erased or is not initialized");
        }
        return ed.signAsync(message, this.privateKey);
    }

    /**
     * Produce a base64 encoded Ed25519 signature.
     */
    public async signBase64(message: Uint8Array): Promise<string> {
        const signature = await this.sign(message);
        return Buffer.from(signature).toString('base64');
    }

    /**
     * Get the public key in raw binary format.
     */
    public getPublicKeyBytes(): Uint8Array {
        if (!this.publicKey) {
            throw new Error("Public key has been erased or is not initialized");
        }
        return this.publicKey;
    }

    /**
     * Get the public key encoded in base64 format.
     */
    public getPublicKeyBase64(): string {
        return Buffer.from(this.getPublicKeyBytes()).toString('base64');
    }

    /**
     * Erase the memory storing the keys.
     */
    public erase(): void {
        if (this.privateKey) {
            this.privateKey.fill(0);
            this.privateKey = null;
        }
        if (this.publicKey) {
            this.publicKey.fill(0);
            this.publicKey = null;
        }
    }
}
