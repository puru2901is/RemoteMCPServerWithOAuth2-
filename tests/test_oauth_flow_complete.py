#!/usr/bin/env python3
"""
Test script to verify OAuth flow with client authentication method "none"
"""

import httpx
import asyncio
import json
from urllib.parse import parse_qs, urlparse

async def test_oauth_flow():
    """Test the complete OAuth flow like MCP Inspector does it"""
    
    base_url = "http://localhost:8000"
    redirect_uri = "http://localhost:6274/oauth/callback/debug"
    
    async with httpx.AsyncClient() as client:
        print("🔍 Step 1: Register client (like MCP Inspector)")
        
        # Step 1: Register client
        registration_data = {
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "client_name": "Test MCP Inspector",
            "scope": "user:email openid profile email"
        }
        
        reg_response = await client.post(f"{base_url}/register", json=registration_data)
        if reg_response.status_code != 201:
            print(f"❌ Registration failed: {reg_response.status_code}")
            print(reg_response.text)
            return
        
        client_info = reg_response.json()
        client_id = client_info["client_id"]
        print(f"✅ Client registered: {client_id}")
        
        # Step 2: Authorization request
        print("\n🔍 Step 2: Authorization request")
        
        auth_params = {
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": "test_challenge_12345",
            "code_challenge_method": "S256",
            "redirect_uri": redirect_uri,
            "scope": "user:email openid profile email",
            "resource": f"{base_url}/mcp/"
        }
        
        # Build the authorization URL
        auth_url = f"{base_url}/oauth/authorize"
        auth_response = await client.get(auth_url, params=auth_params, follow_redirects=False)
        
        if auth_response.status_code != 307:
            print(f"❌ Authorization failed: {auth_response.status_code}")
            print(auth_response.text)
            return
        
        # Parse the redirect to get the authorization code
        redirect_location = auth_response.headers.get("location")
        parsed_redirect = urlparse(redirect_location)
        query_params = parse_qs(parsed_redirect.query)
        
        if "code" not in query_params:
            print(f"❌ No authorization code in redirect: {redirect_location}")
            return
        
        auth_code = query_params["code"][0]
        state = query_params.get("state", [None])[0]
        print(f"✅ Authorization code received: {auth_code[:10]}...")
        
        # Step 3: Token exchange (without client_id like MCP Inspector does)
        print("\n🔍 Step 3: Token exchange (no client_id)")
        
        token_data = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "code_verifier": "test_verifier_12345",
            "redirect_uri": redirect_uri,
            # Note: no client_id here (auth method "none")
        }
        
        token_response = await client.post(
            f"{base_url}/oauth/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        print(f"Token response status: {token_response.status_code}")
        print(f"Token response: {token_response.text}")
        
        if token_response.status_code == 200:
            token_info = token_response.json()
            access_token = token_info.get("access_token")
            print(f"✅ Token exchange successful!")
            print(f"Access token: {access_token[:20]}...")
            
            # Step 4: Test MCP endpoint with token
            print("\n🔍 Step 4: Test MCP endpoint")
            
            mcp_response = await client.post(
                f"{base_url}/mcp/",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"Authorization": f"Bearer {access_token}"}
            )
            
            print(f"MCP response status: {mcp_response.status_code}")
            print(f"MCP response: {mcp_response.text[:200]}...")
            
        else:
            print(f"❌ Token exchange failed: {token_response.status_code}")
            print(f"Error: {token_response.text}")

if __name__ == "__main__":
    asyncio.run(test_oauth_flow())
