import os
import requests
from typing import Dict, Any, Optional

from .crypto import Ed25519Key
from .envelope import create_smcp_envelope

class SMCPError(Exception):
    """Base exception for SMCP protocol errors."""
    pass

class SMCPClient:
    """
    A Python client wrapper for generating ephemeral keys, interacting
    with an SMCP Gateway to undergo an attestation handshake, and securely
    wrapping Model Context Protocol (MCP) message calls leveraging SMCP.
    """
    
    def __init__(self, gateway_url: str, workload_id: str, security_scope: str):
        """
        Initialize the SMCP client properties.
        
        Args:
            gateway_url: The HTTP(s) endpoint of the target SMCP Gateway proxying tools.
            workload_id: Process-specific identifier matching Gateway attest algorithms.
            security_scope: Requested operational constraints (e.g. read-only-research).
        """
        self.gateway_url = gateway_url.rstrip('/')
        self.workload_id = workload_id
        self.security_scope = security_scope
        self.key: Optional[Ed25519Key] = None
        self.security_token: Optional[str] = None
        
    def attest(self) -> str:
        """
        Perform the attestation handshake spanning the gateway's REST endpoint.
        """
        self.key = Ed25519Key.generate()
        
        response = requests.post(
            f"{self.gateway_url}/smcp/v1/attest",
            json={
                "public_key": self.key.get_public_key_base64(),
                "workload_id": self.workload_id,
                "requested_scope": self.security_scope
            },
            timeout=10
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get("status") == "error":
            raise SMCPError(f"Attestation failed: {data.get('message', 'Unknown error')}")
            
        self.security_token = data["security_token"]
        return self.security_token
        
    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Make an SMCP-wrapped JSON-RPC method call to a tool passing through the Gateway.
        
        Args:
            tool_name: The name parameter matching capabilities, e.g 'fs.read'.
            arguments: The arguments required by the target MCP tool payload.
            
        Returns:
            Dict: The nested 'result' field of the payload structure returned via HTTP.
        """
        if not self.security_token:
            raise SMCPError("No security token available. Must attest() first.")
            
        mcp_payload = {
            "jsonrpc": "2.0",
            "id": f"req-{os.urandom(8).hex()}",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        envelope = create_smcp_envelope(
            security_token=self.security_token,
            mcp_payload=mcp_payload,
            private_key=self.key
        )
        
        response = requests.post(
            f"{self.gateway_url}/smcp/v1/tool-call",
            json=envelope,
            timeout=30
        )
        
        # If the gateway responds with an HTTP status error 
        # (e.g. 403 Forbidden due to policy violation).
        if not response.ok:
            try:
                error_response = response.json()
                if error_response.get("status") == "error":
                    raise SMCPError(f"SMCP Gateway Rejected: {error_response['error']['message']}")
            except ValueError:
                response.raise_for_status()
            
        # Parse standard unwrapped JSON-RPC response from the tool server.
        smcp_response = response.json()
        
        # A response might also be wrapped via error schemas.
        if smcp_response.get("status") == "error":
             raise SMCPError(f"SMCP Gateway Error: {smcp_response['error']['message']}")
             
        # Extract the inner MCP payload return
        payload = smcp_response.get("payload", {})
        if "error" in payload:
            raise SMCPError(f"MCP Tool Error: {payload['error']}")
            
        return payload.get("result", {})
    
    def __del__(self):
        """Zero out ephemeral key memory upon garbage collection."""
        if self.key is not None:
             self.key.erase()
