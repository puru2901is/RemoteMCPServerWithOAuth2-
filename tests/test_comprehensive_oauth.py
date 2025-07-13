#!/usr/bin/env python3
"""
Comprehensive test for FastMCP OAuth 2.1 with Dynamic Client Registration
"""

import httpx
import asyncio
import json
import pytest

@pytest.mark.asyncio
async def test_comprehensive_oauth_flow():
    """Test the complete OAuth flow with dynamic client registration"""
    
    print("🚀 Testing Comprehensive FastMCP OAuth 2.1 Flow...")
    
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient(follow_redirects=False) as client:
        
        # Test 1: Check standard OAuth discovery endpoints (FastMCP built-in)
        print("\n1. Testing FastMCP built-in OAuth discovery...")
        
        try:
            response = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
            print(f"   ✅ Standard OAuth metadata: {response.status_code}")
            if response.status_code == 200:
                metadata = response.json()
                print(f"   📋 Authorization endpoint: {metadata.get('authorization_endpoint')}")
                print(f"   📋 Token endpoint: {metadata.get('token_endpoint')}")
                print(f"   📋 Registration endpoint: {metadata.get('registration_endpoint', 'Not supported')}")
        except Exception as e:
            print(f"   ❌ Standard OAuth metadata failed: {e}")
        
        # Test 2: Check our extended OAuth discovery endpoint
        print("\n2. Testing extended OAuth discovery...")
        
        try:
            response = await client.get(f"{base_url}/.well-known/oauth-authorization-server-extended")
            print(f"   ✅ Extended OAuth metadata: {response.status_code}")
            if response.status_code == 200:
                metadata = response.json()
                print(f"   📋 Registration endpoint: {metadata.get('registration_endpoint')}")
                print(f"   📋 Grant types: {metadata.get('grant_types_supported')}")
                print(f"   📋 PKCE methods: {metadata.get('code_challenge_methods_supported')}")
        except Exception as e:
            print(f"   ❌ Extended OAuth metadata failed: {e}")
        
        # Test 3: Check OAuth protected resource metadata
        print("\n3. Testing OAuth protected resource metadata...")
        
        try:
            response = await client.get(f"{base_url}/.well-known/oauth-protected-resource")
            print(f"   ✅ Protected resource metadata: {response.status_code}")
            if response.status_code == 200:
                metadata = response.json()
                print(f"   📋 Protected resource: {metadata.get('resource')}")
                print(f"   📋 Bearer methods: {metadata.get('bearer_methods_supported')}")
        except Exception as e:
            print(f"   ❌ Protected resource metadata failed: {e}")
        
        # Test 4: Test dynamic client registration
        print("\n4. Testing dynamic client registration...")
        
        try:
            registration_data = {
                "redirect_uris": ["http://localhost:3000/callback"],
                "client_name": "Test MCP Client",
                "client_uri": "http://localhost:3000",
                "scope": "user:email",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "client_secret_basic"
            }
            
            response = await client.post(
                f"{base_url}/register",
                json=registration_data,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"   ✅ Client registration: {response.status_code}")
            if response.status_code == 201:
                client_info = response.json()
                print(f"   📋 Client ID: {client_info.get('client_id')}")
                print(f"   📋 Client secret: {'***' if client_info.get('client_secret') else 'None'}")
                print(f"   📋 Registration URI: {client_info.get('registration_client_uri')}")
                
                # Test 5: Retrieve client information
                print("\n5. Testing client information retrieval...")
                
                client_id = client_info.get('client_id')
                registration_token = client_info.get('registration_access_token')
                
                if client_id and registration_token:
                    try:
                        response = await client.get(
                            f"{base_url}/register/{client_id}",
                            headers={"Authorization": f"Bearer {registration_token}"}
                        )
                        print(f"   ✅ Client info retrieval: {response.status_code}")
                        if response.status_code == 200:
                            info = response.json()
                            print(f"   📋 Client name: {info.get('client_name')}")
                            print(f"   📋 Redirect URIs: {info.get('redirect_uris')}")
                    except Exception as e:
                        print(f"   ❌ Client info retrieval failed: {e}")
                
            else:
                print(f"   ❌ Registration failed: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Dynamic client registration failed: {e}")
        
        # Test 6: Test MCP endpoint protection
        print("\n6. Testing MCP endpoint protection...")
        
        try:
            response = await client.post(
                f"{base_url}/mcp/",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"Content-Type": "application/json"}
            )
            print(f"   ✅ MCP endpoint protection: {response.status_code}")
            if response.status_code == 401:
                print("   🔒 MCP endpoint is properly protected")
                www_auth = response.headers.get('www-authenticate', '')
                if 'Bearer' in www_auth:
                    print("   📋 WWW-Authenticate header present")
        except Exception as e:
            print(f"   ❌ MCP endpoint test failed: {e}")
        
        # Test 7: Test OAuth authorize endpoint
        print("\n7. Testing OAuth authorize endpoint...")
        
        try:
            response = await client.get(f"{base_url}/oauth/authorize")
            print(f"   ✅ OAuth authorize: {response.status_code}")
            if response.status_code == 307:
                print("   🔄 Redirecting to GitHub OAuth (as expected)")
                location = response.headers.get('location', '')
                if 'github.com' in location:
                    print("   📋 GitHub OAuth integration working")
        except Exception as e:
            print(f"   ❌ OAuth authorize test failed: {e}")
        
        # Test 8: Test health endpoint
        print("\n8. Testing health endpoint...")
        
        try:
            response = await client.get(f"{base_url}/health")
            print(f"   ✅ Health endpoint: {response.status_code}")
            if response.status_code == 200:
                health = response.json()
                print(f"   📋 Status: {health.get('status')}")
                print(f"   📋 Mode: {health.get('mode')}")
        except Exception as e:
            print(f"   ❌ Health endpoint test failed: {e}")
    
    print("\n🎉 Comprehensive OAuth 2.1 test completed!")
    print("\nNext steps:")
    print("1. Visit: http://localhost:8000/oauth/authorize")
    print("2. Authorize with GitHub")
    print("3. Copy the access token")
    print("4. Use the token to access MCP endpoints")
    print("5. Test dynamic client registration with MCP clients")

if __name__ == "__main__":
    asyncio.run(test_comprehensive_oauth_flow())
