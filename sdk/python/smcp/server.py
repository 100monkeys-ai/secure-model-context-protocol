import base64
import time
from typing import Dict, Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .client import SMCPError
from .envelope import create_canonical_message

def verify_smcp_envelope(envelope: Dict[str, Any], public_key_bytes: bytes, max_age_seconds: int = 30) -> Dict[str, Any]:
    """
    Server-side primitive to verify an incoming SmcpEnvelope.
    
    1. Checks if the envelope format is valid.
    2. Validates timestamp freshness against current server time.
    3. Reconstructs the canonical message.
    4. Cryptographically verifies the Ed25519 signature.
    
    Args:
        envelope: The incoming JSON payload containing the SmcpEnvelope.
        public_key_bytes: The raw 32-byte Ed25519 public key of the agent (from their Attestation session).
        max_age_seconds: The maximum allowed age of the envelope in seconds.
        
    Returns:
        The verified MCP JSON-RPC payload.
        
    Raises:
        SMCPError: If verification fails (invalid format, expired, bad signature).
    """
    # 1. Validate envelope structure
    if envelope.get("protocol") != "smcp/v1":
        raise SMCPError("Missing or invalid 'protocol' field. Expected 'smcp/v1'.", 1005)
        
    security_token = envelope.get("security_token")
    if not security_token:
        raise SMCPError("Missing 'security_token' field.", 1000)
        
    signature_b64 = envelope.get("signature")
    if not signature_b64:
        raise SMCPError("Missing 'signature' field.", 1000)
        
    payload = envelope.get("payload")
    if not payload:
        raise SMCPError("Missing 'payload' field.", 1000)
        
    timestamp_iso = envelope.get("timestamp")
    if not timestamp_iso:
        raise SMCPError("Missing 'timestamp' field.", 1000)
        
    # 2. Check Timestamp limits
    try:
        from .envelope import parse_iso8601_to_unix
        timestamp_unix = parse_iso8601_to_unix(timestamp_iso)
    except ValueError:
        raise SMCPError("Invalid 'timestamp' format. Expected ISO 8601.", 1000)
        
    current_time = int(time.time())
    if abs(current_time - timestamp_unix) > max_age_seconds:
        raise SMCPError(f"Envelope timestamp is outside the allowed ±{max_age_seconds}s window.", 1004)
        
    # 3. Canonicalize message
    try:
        canonical_msg = create_canonical_message(security_token, payload, timestamp_unix)
    except Exception as e:
        raise SMCPError(f"Failed to construct canonical message: {e}", 1000)
        
    # 4. Verify Signature
    try:
        signature_bytes = base64.b64decode(signature_b64)
    except Exception:
        raise SMCPError("Invalid base64 encoding for 'signature'.", 1000)
        
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    except ValueError:
        raise SMCPError("Invalid Ed25519 public key bytes provided by server configuration.", 3000)
        
    try:
        public_key.verify(signature_bytes, canonical_msg)
    except InvalidSignature:
        raise SMCPError("Ed25519 signature verification failed.", 1001)

    return payload
