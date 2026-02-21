import time
import base64
import pytest
from datetime import datetime, timezone

from smcp.crypto import Ed25519Key
from smcp.envelope import create_smcp_envelope
from smcp.server import verify_smcp_envelope
from smcp.client import SMCPError

def test_verify_valid_envelope():
    key = Ed25519Key.generate()
    payload = {"jsonrpc": "2.0", "method": "tools/call", "id": 1}
    token = "test.jwt.token"
    
    envelope = create_smcp_envelope(token, payload, key)
    
    verified_payload = verify_smcp_envelope(envelope, key.get_public_key_bytes())
    
    assert verified_payload == payload

def test_verify_rejects_modified_payload():
    key = Ed25519Key.generate()
    envelope = create_smcp_envelope("token", {"id": 1}, key)
    
    # Tamper with the payload
    envelope["payload"]["id"] = 2
    
    with pytest.raises(SMCPError) as exc_info:
        verify_smcp_envelope(envelope, key.get_public_key_bytes())
        
    assert exc_info.value.status_code == 1001
    assert "signature verification failed" in str(exc_info.value).lower()

def test_verify_rejects_expired_envelope():
    key = Ed25519Key.generate()
    envelope = create_smcp_envelope("token", {"id": 1}, key)
    
    # Simulate an old envelope by shifting the timestamp back
    old_time = int(time.time()) - 40
    dt = datetime.fromtimestamp(old_time, tz=timezone.utc)
    # create_smcp_envelope uses ISO format with Z
    timestamp_iso = dt.isoformat(timespec='microseconds').replace('+00:00', 'Z')
    
    # We must properly sign the old envelope to just test the expiry rejection
    from smcp.envelope import create_canonical_message
    canonical = create_canonical_message("token", {"id": 1}, old_time)
    signature = key.sign_base64(canonical)
    
    envelope["timestamp"] = timestamp_iso
    envelope["signature"] = signature
    
    with pytest.raises(SMCPError) as exc_info:
        verify_smcp_envelope(envelope, key.get_public_key_bytes())
        
    assert exc_info.value.status_code == 1004
    assert "outside the allowed" in str(exc_info.value).lower()

def test_verify_rejects_wrong_public_key():
    key1 = Ed25519Key.generate()
    key2 = Ed25519Key.generate()
    
    envelope = create_smcp_envelope("token", {"id": 1}, key1)
    
    with pytest.raises(SMCPError) as exc_info:
        # Verify with key2 instead of key1
        verify_smcp_envelope(envelope, key2.get_public_key_bytes())
        
    assert exc_info.value.status_code == 1001
