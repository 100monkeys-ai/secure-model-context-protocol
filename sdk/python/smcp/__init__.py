__version__ = "0.1.0"

from .client import SMCPClient
from .crypto import Ed25519Key
from .envelope import create_smcp_envelope, create_canonical_message

__all__ = [
    "SMCPClient", 
    "Ed25519Key", 
    "create_smcp_envelope",
    "create_canonical_message"
]
