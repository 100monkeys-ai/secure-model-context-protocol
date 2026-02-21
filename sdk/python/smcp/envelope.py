import json
from datetime import datetime, timezone
from typing import Dict, Any

from .crypto import Ed25519Key

def parse_iso8601_to_unix(timestamp_iso: str) -> int:
    """
    Parse an ISO 8601 UTC timestamp to Unix seconds.
    Expects format: YYYY-MM-DDTHH:MM:SS.sssZ or similar valid ISO string.
    """
    # Replace Z with +00:00 for strict fromisoformat parsing in standard datetime
    clean_iso = timestamp_iso.replace('Z', '+00:00')
    dt = datetime.fromisoformat(clean_iso)
    return int(dt.timestamp())

def create_canonical_message(security_token: str, payload: Dict[str, Any], timestamp_unix: int) -> bytes:
    """
    Construct democratic, deterministic message byte sequence for signing/verification.
    
    Args:
        security_token: JWT string representation.
        payload: Standard MCP JSON-RPC object dictionary.
        timestamp_unix: Unix integer tracking creation seconds.
        
    Returns:
        bytes: UTF-8 encoded JSON matching RFC requirements.
    """
    message = {
        "security_token": security_token,
        "payload": payload,
        "timestamp": timestamp_unix
    }
    
    # Serialize to JSON with sorted keys, no whitespace, and ensure ASCII is false
    # to support accurate UTF-8 canonical transmission of payload data natively.
    canonical_json = json.dumps(
        message,
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False
    )
    
    return canonical_json.encode('utf-8')

def create_smcp_envelope(security_token: str, mcp_payload: Dict[str, Any], private_key: Ed25519Key) -> Dict[str, Any]:
    """
    Wrap an MCP JSON-RPC payload in an SMCP Security Envelope v1.
    
    Args:
        security_token: The client's JWT allocated from attestation.
        mcp_payload: The raw standard `tools/call` JSON dictionary.
        private_key: The client's ephemeral Ed25519 keypair for signing.
        
    Returns:
        Dict: A comprehensive SMCP Envelope satisfying all RFC constraints.
    """
    utc_now = datetime.now(timezone.utc)
    timestamp_iso = utc_now.isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    timestamp_unix = int(utc_now.timestamp())
    
    canonical_bytes = create_canonical_message(
        security_token=security_token,
        payload=mcp_payload,
        timestamp_unix=timestamp_unix
    )
    
    signature_b64 = private_key.sign_base64(canonical_bytes)
    
    return {
        "protocol": "smcp/v1",
        "security_token": security_token,
        "signature": signature_b64,
        "payload": mcp_payload,
        "timestamp": timestamp_iso
    }
