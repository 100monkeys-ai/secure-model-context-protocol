import json
from datetime import datetime
import pytest

from smcp.crypto import Ed25519Key
from smcp.envelope import create_canonical_message, create_smcp_envelope

def test_canonical_message_construction():
    """Verify JSON canonicalization per RFC 8032 test cases."""
    # Test vector input data
    security_token = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl"
    payload = {"jsonrpc": "2.0", "id": 1, "method": "test"}
    # Unix of 2026-02-17T14:32:01.000Z
    timestamp_unix = 1708261921 
    
    expected_canonical_bytes = (
        b'{"payload":{"id":1,"jsonrpc":"2.0","method":"test"},'
        b'"security_token":"eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ0ZXN0In0.c2lnbmF0dXJl",'
        b'"timestamp":1708261921}'
    )
    
    canonical_bytes = create_canonical_message(
        security_token=security_token,
        payload=payload,
        timestamp_unix=timestamp_unix
    )
    
    assert canonical_bytes == expected_canonical_bytes

def test_envelope_creation():
    """Verify that an SMCP Envelope can structure correctly."""
    key = Ed25519Key.generate()
    payload = {"jsonrpc": "2.0", "id": 1, "method": "test"}
    token = "test.token.jwt"
    
    envelope = create_smcp_envelope(security_token=token, mcp_payload=payload, private_key=key)
    
    assert envelope["protocol"] == "smcp/v1"
    assert envelope["security_token"] == token
    assert envelope["payload"] == payload
    assert "signature" in envelope
    assert "timestamp" in envelope
