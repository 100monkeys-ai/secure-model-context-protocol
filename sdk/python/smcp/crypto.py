import base64
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

class Ed25519Key:
    """
    Manages ephemeral Ed25519 cryptographic keys for the SMCP Protocol.
    Keys are generated dynamically and stored only in memory per execution
    for high security according to the SMCP spec.
    """
    
    def __init__(self, private_key: Ed25519PrivateKey = None):
        if private_key is None:
            self._private_key = Ed25519PrivateKey.generate()
        else:
            self._private_key = private_key
            
        self._public_key = self._private_key.public_key()
        
    @classmethod
    def generate(cls) -> "Ed25519Key":
        """Generate a new ephemeral Ed25519 keypair."""
        return cls()
        
    def sign(self, message: bytes) -> bytes:
        """
        Produce an Ed25519 signature of the given canonical message bytes.
        """
        return self._private_key.sign(message)
        
    def sign_base64(self, message: bytes) -> str:
        """
        Produce a base64 encoded Ed25519 signature.
        """
        signature = self.sign(message)
        return base64.b64encode(signature).decode('utf-8')
        
    def get_public_key_bytes(self) -> bytes:
        """Get the public key in raw binary format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
    def get_public_key_base64(self) -> str:
        """Get the public key encoded in base64 format."""
        return base64.b64encode(self.get_public_key_bytes()).decode('utf-8')
        
    def erase(self):
        """
        Erase the memory storing the keys. In pure Python this simply removes
        the reference to the underlying cryptography primitive.
        """
        self._private_key = None
        self._public_key = None
