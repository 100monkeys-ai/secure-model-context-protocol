__version__ = "0.1.0"

from .client import SEALClient
from .crypto import Ed25519Key
from .envelope import create_seal_envelope, create_canonical_message

__all__ = [
    "SEALClient", 
    "Ed25519Key", 
    "create_seal_envelope",
    "create_canonical_message"
]
