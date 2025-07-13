#!/usr/bin/env python3
"""
Test Dynamic Client Registration for MCP OAuth Server
"""

import httpx
import asyncio
import json

async def test_dynamic_client_registration():
    """Test the dynamic client registration flow"""
    
    print("🔧 Testing Dynamic Client Registration...")
    
    base_url = "http://localhost:8000"
    
    async with httpx.AsyncClient() as client:
        
        # Test 1: Check OAuth discovery endpoints
        print("\n1. Testing OAuth authorization server metadata...")
        
        try:
            response = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
            print(f"   ✅ OAuth authorization server metadata: {response.status_code}")
            if response.status_code == 200:
                metadata = response.json()
                print(f"   📋 Authorization endpoint: {metadata.get('authorization_endpoint')}")
                print(f"   📋 Token endpoint: {metadata.get('token_endpoint')}")
                print(f"   📋 Registration endpoint: {metadata.get('registration_endpoint')}")
                
                if metadata.get('registration_endpoint'):
                    print("   ✅ Dynamic client registration supported!")
                else:
                    print("   ❌ Dynamic client registration NOT supported")
                    return
            else:
                print("   ❌ Failed to get authorization server metadata")
                return
        except Exception as e:
            print(f"   ❌ OAuth authorization server metadata failed: {e}")
            return
        
        # Test 2: Register a new client
        print("\n2. Testing dynamic client registration...")
        
        registration_data = {
            "redirect_uris": ["http://localhost:8080/callback"],
            "client_name": "Test MCP Client",
            "client_uri": "http://localhost:8080",
            "scope": "user:email",
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_basic"
        }
        
        try:
            response = await client.post(
                f"{base_url}/register",
                json=registration_data,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"   ✅ Client registration status: {response.status_code}")
            
            if response.status_code == 201:
                client_info = response.json()
                print(f"   📋 Client ID: {client_info.get('client_id')}")
                print(f"   📋 Client Secret: {client_info.get('client_secret')[:10]}...")
                print(f"   📋 Registration Access Token: {client_info.get('registration_access_token')[:10]}...")
                print(f"   📋 Registration Client URI: {client_info.get('registration_client_uri')}")
                
                # Store for next test
                client_id = client_info.get('client_id')
                registration_access_token = client_info.get('registration_access_token')
                
                # Test 3: Retrieve client registration
                print("\n3. Testing client registration retrieval...")
                
                try:
                    response = await client.get(
                        f"{base_url}/register/{client_id}",
                        headers={"Authorization": f"Bearer {registration_access_token}"}
                    )
                    
                    print(f"   ✅ Client retrieval status: {response.status_code}")
                    
                    if response.status_code == 200:
                        retrieved_client = response.json()
                        print(f"   📋 Retrieved client name: {retrieved_client.get('client_name')}")
                        print(f"   📋 Retrieved redirect URIs: {retrieved_client.get('redirect_uris')}")
                        print("   ✅ Client registration retrieval successful!")
                    else:
                        print(f"   ❌ Failed to retrieve client registration: {response.text}")
                        
                except Exception as e:
                    print(f"   ❌ Client retrieval failed: {e}")
                
            else:
                print(f"   ❌ Client registration failed: {response.text}")
                
        except Exception as e:
            print(f"   ❌ Client registration failed: {e}")
        
        # Test 4: Test invalid registration
        print("\n4. Testing invalid client registration...")
        
        invalid_registration_data = {
            "redirect_uris": ["http://evil.com/callback"],  # Invalid URI
            "client_name": "Evil Client"
        }
        
        try:
            response = await client.post(
                f"{base_url}/register",
                json=invalid_registration_data,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"   ✅ Invalid registration status: {response.status_code}")
            
            if response.status_code == 400:
                error_info = response.json()
                print(f"   📋 Error: {error_info.get('error')}")
                print(f"   📋 Error description: {error_info.get('error_description')}")
                print("   ✅ Invalid registration properly rejected!")
            else:
                print(f"   ⚠️  Unexpected status for invalid registration: {response.status_code}")
                
        except Exception as e:
            print(f"   ❌ Invalid registration test failed: {e}")
        
        # Test 5: Check protected resource metadata
        print("\n5. Testing protected resource metadata...")
        
        try:
            response = await client.get(f"{base_url}/.well-known/oauth-protected-resource")
            print(f"   ✅ Protected resource metadata: {response.status_code}")
            if response.status_code == 200:
                metadata = response.json()
                print(f"   📋 Protected resource: {metadata.get('resource')}")
                print(f"   📋 Authorization servers: {metadata.get('authorization_servers')}")
                print(f"   📋 Resource registration: {metadata.get('resource_registration')}")
        except Exception as e:
            print(f"   ❌ Protected resource metadata failed: {e}")
    
    print("\n🎉 Dynamic Client Registration test completed!")
    print("\nMCP clients can now:")
    print("1. Discover the registration endpoint via /.well-known/oauth-authorization-server")
    print("2. Register automatically without manual client configuration")
    print("3. Obtain client credentials dynamically")
    print("4. Complete the OAuth flow with the registered client")

if __name__ == "__main__":
    asyncio.run(test_dynamic_client_registration())
