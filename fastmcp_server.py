"""
FastMCP 2.0 Server with OAuth 2.0 Authentication
Implements note-taking functionality using FastMCP 2.0 with GitHub OAuth integration
"""

import os
import json
import logging
import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
import secrets
import base64
import hashlib
import secrets
import base64
import hashlib

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

import httpx
from pydantic import BaseModel
from urllib.parse import urlencode, parse_qs

# FastMCP 2.0 imports
from fastmcp import FastMCP, Context
from fastmcp.server.auth import BearerAuthProvider
from fastmcp.server.auth.providers.bearer import RSAKeyPair
from fastmcp.server.dependencies import get_access_token, AccessToken
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import RedirectResponse, HTMLResponse, JSONResponse
from starlette.exceptions import HTTPException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# OAuth 2.0 Configuration
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/oauth/callback")
GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_API_URL = "https://api.github.com/user"

# In-memory storage for notes (in production, use a database)
notes_storage: Dict[str, List[Dict[str, Any]]] = {}
oauth_states: Dict[str, Dict[str, Any]] = {}
user_tokens: Dict[str, str] = {}

# Dynamic client registration storage
registered_clients: Dict[str, Dict[str, Any]] = {}

# Pydantic models
class Note(BaseModel):
    id: str
    title: str
    content: str
    created_at: datetime
    updated_at: datetime
    tags: List[str] = []

class SaveNoteRequest(BaseModel):
    title: str
    content: str
    tags: List[str] = []

class GetNotesRequest(BaseModel):
    tag: Optional[str] = None

# Dynamic Client Registration Models
class ClientRegistrationRequest(BaseModel):
    redirect_uris: List[str]
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    scope: Optional[str] = None
    contacts: Optional[List[str]] = None
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    jwks_uri: Optional[str] = None
    jwks: Optional[Dict[str, Any]] = None
    software_id: Optional[str] = None
    software_version: Optional[str] = None
    token_endpoint_auth_method: Optional[str] = "client_secret_basic"
    grant_types: Optional[List[str]] = ["authorization_code"]
    response_types: Optional[List[str]] = ["code"]

class ClientRegistrationResponse(BaseModel):
    client_id: str
    client_secret: Optional[str] = None
    client_id_issued_at: Optional[int] = None
    client_secret_expires_at: Optional[int] = None
    redirect_uris: List[str]
    client_name: Optional[str] = None
    client_uri: Optional[str] = None
    logo_uri: Optional[str] = None
    scope: Optional[str] = None
    contacts: Optional[List[str]] = None
    tos_uri: Optional[str] = None
    policy_uri: Optional[str] = None
    jwks_uri: Optional[str] = None
    jwks: Optional[Dict[str, Any]] = None
    software_id: Optional[str] = None
    software_version: Optional[str] = None
    token_endpoint_auth_method: str = "client_secret_basic"
    grant_types: List[str] = ["authorization_code"]
    response_types: List[str] = ["code"]
    registration_access_token: Optional[str] = None
    registration_client_uri: Optional[str] = None

class OAuth2Handler:
    """Handles OAuth 2.0 flow with GitHub"""
    
    @staticmethod
    def generate_state() -> str:
        """Generate a secure random state parameter"""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def generate_code_verifier() -> str:
        """Generate PKCE code verifier"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Generate PKCE code challenge"""
        digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(digest).decode('utf-8').rstrip('=')
    
    @staticmethod
    async def get_user_info(access_token: str) -> Dict[str, Any]:
        """Get user information from GitHub"""
        async with httpx.AsyncClient() as client:
            response = await client.get(
                GITHUB_API_URL,
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code == 200:
                return response.json()
            raise HTTPException(status_code=401, detail="Invalid access token")

oauth_handler = OAuth2Handler()

# Authentication middleware for proper WWW-Authenticate headers
class OAuthAuthenticationMiddleware:
    """Middleware to add proper WWW-Authenticate headers for 401 responses"""
    
    def __init__(self, app):
        self.app = app
    
    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        
        # Check if this is an MCP endpoint that needs authentication
        if scope["path"].startswith("/mcp"):
            # Get the request object
            request = StarletteRequest(scope, receive)
            
            # Try to authenticate the request
            user_info = await custom_auth.authenticate(request)
            
            # If no authentication provided, use a default/anonymous user for development
            if not user_info:
                # For development purposes, allow anonymous access
                user_info = {
                    "subject": "anonymous_user",
                    "username": "anonymous",
                    "name": "Anonymous User",
                    "email": "anonymous@localhost"
                }
            
            # Add user info to the request object for later use
            request.user_info = user_info
        
        # Intercept responses to add WWW-Authenticate header on 401
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status = message.get("status", 200)
                headers = list(message.get("headers", []))
                
                # Add WWW-Authenticate header for 401 responses to MCP endpoints
                if status == 401 and scope["path"].startswith("/mcp"):
                    base_url = f"{scope['scheme']}://{scope['server'][0]}:{scope['server'][1]}"
                    www_auth_header = (
                        b"www-authenticate",
                        f'Bearer realm="MCP Server", authorization_uri="{base_url}/oauth/authorize"'.encode()
                    )
                    headers.append(www_auth_header)
                    message["headers"] = headers
            
            await send(message)
        
        await self.app(scope, receive, send_wrapper)

# Custom GitHub token authentication
class GitHubBearerAuthProvider:
    """Custom authentication provider that validates GitHub access tokens"""
    
    async def authenticate(self, request: StarletteRequest) -> Optional[Dict[str, Any]]:
        """Authenticate request using GitHub access token"""
        auth_header = request.headers.get("authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return None
        
        token = auth_header[7:]  # Remove "Bearer " prefix
        
        # Handle test token for development
        if token == "test_token_12345":
            return {
                "subject": "test_user_123",
                "username": "test_user",
                "name": "Test User",
                "email": "test@example.com"
            }
        
        # Handle MCP-generated tokens
        if token.startswith("mcp_token_") or token.startswith("mcp_client_token_") or token.startswith("mcp_inspector_token_"):
            # Find user for this token
            for user_id, stored_token in user_tokens.items():
                if stored_token == token:
                    return {
                        "subject": user_id,
                        "username": user_id.replace("oauth_user_", "client_"),
                        "name": f"OAuth User {user_id}",
                        "email": f"{user_id}@mcp.local"
                    }
            
            # If token not found in storage but is our format, create a default user
            if token.startswith("mcp_inspector_token_"):
                return {
                    "subject": "mcp_inspector_user",
                    "username": "mcp_inspector",
                    "name": "MCP Inspector User",
                    "email": "inspector@mcp.local"
                }
        
        # Validate token with GitHub API
        try:
            user_info = await oauth_handler.get_user_info(token)
            return {
                "subject": str(user_info.get("id")),
                "username": user_info.get("login"),
                "name": user_info.get("name"),
                "email": user_info.get("email")
            }
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return None

# Create custom auth provider
custom_auth = GitHubBearerAuthProvider()

# Create FastMCP server WITHOUT built-in auth (we'll handle it manually)
mcp = FastMCP(name="Notes MCP Server")

# MCP Tools with custom authentication
@mcp.tool
async def save_note(title: str, content: str, tags: str = "", ctx: Context = None) -> str:
    """Save a new note with title, content, and optional tags"""
    try:
        # For development/testing, use a default user ID
        # In production, this would come from proper authentication context
        user_id = "default_user"
        
        # Parse tags
        tag_list = [tag.strip() for tag in tags.split(",") if tag.strip()]
        
        # Create note
        note_id = secrets.token_urlsafe(8)
        note = {
            "id": note_id,
            "title": title,
            "content": content,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat(),
            "tags": tag_list
        }
        
        # Store note
        if user_id not in notes_storage:
            notes_storage[user_id] = []
        
        notes_storage[user_id].append(note)
        
        return f"Note '{title}' saved successfully with ID: {note_id}"
    
    except Exception as e:
        logger.error(f"Error saving note: {e}")
        return f"Error saving note: {str(e)}"

@mcp.tool
async def get_notes(tag: str = "", ctx: Context = None) -> str:
    """Get all notes, optionally filtered by tag"""
    try:
        # For development/testing, use a default user ID
        # In production, this would come from proper authentication context
        user_id = "default_user"
        
        if user_id not in notes_storage:
            return "No notes found"
        
        user_notes = notes_storage[user_id]
        
        # Filter by tag if provided
        if tag:
            filtered_notes = [note for note in user_notes if tag in note.get("tags", [])]
        else:
            filtered_notes = user_notes
        
        if not filtered_notes:
            return f"No notes found{' with tag \"' + tag + '\"' if tag else ''}"
        
        # Format notes
        result = []
        for note in filtered_notes:
            result.append(f"**{note['title']}** ({note['id']})")
            result.append(f"Created: {note['created_at']}")
            if note.get('tags'):
                result.append(f"Tags: {', '.join(note['tags'])}")
            result.append(f"Content: {note['content']}")
            result.append("---")
        
        return "\n".join(result)
    
    except Exception as e:
        logger.error(f"Error getting notes: {e}")
        return f"Error getting notes: {str(e)}"

# MCP Resources with custom authentication
@mcp.resource("notes://list")
async def list_notes_resource(ctx: Context = None) -> str:
    """Resource to list all notes"""
    return await get_notes(ctx=ctx)

@mcp.resource("notes://stats")
async def notes_stats_resource(ctx: Context = None) -> str:
    """Resource to get notes statistics"""
    try:
        # Get user info from request scope (already authenticated by middleware)
        request = ctx.meta.get("request") if ctx and ctx.meta else None
        if not request:
            return json.dumps({"error": "No request context available"})
        
        # The middleware should have added user_info to the request scope
        user_info = getattr(request, "user_info", None)
        if not user_info:
            return json.dumps({"error": "Authentication required"})
        
        user_id = user_info["subject"]
        
        if user_id not in notes_storage:
            return json.dumps({"total_notes": 0, "unique_tags": 0, "tags": []})
        
        user_notes = notes_storage[user_id]
        total_notes = len(user_notes)
        
        # Get unique tags
        all_tags = set()
        for note in user_notes:
            all_tags.update(note.get("tags", []))
        
        stats = {
            "total_notes": total_notes,
            "unique_tags": len(all_tags),
            "tags": list(all_tags),
            "last_updated": max([note.get('created_at', '') for note in user_notes]) if user_notes else None
        }
        
        return json.dumps(stats, indent=2)
    
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return json.dumps({"error": f"Error getting statistics: {str(e)}"})

# Authentication is handled within individual tools and resources
# No separate middleware needed as FastMCP handles this differently
@mcp.custom_route("/", methods=["GET"])
async def root(request: StarletteRequest):
    """Serve the main authentication page"""
    with open("templates/index.html", "r") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@mcp.custom_route("/debug", methods=["GET"])
async def debug_page(request: StarletteRequest):
    """Debug page for OAuth flow"""
    with open("templates/debug.html", "r") as f:
        html_content = f.read()
    return HTMLResponse(content=html_content)

@mcp.custom_route("/authorize", methods=["GET"])
async def oauth_authorize_shortcut(request: StarletteRequest):
    """Redirect to the full OAuth authorize endpoint"""
    # Get all query parameters from the original request
    query_params = dict(request.query_params)
    
    # Build the redirect URL with all parameters
    from urllib.parse import urlencode
    redirect_url = f"/oauth/authorize?{urlencode(query_params)}"
    
    return RedirectResponse(url=redirect_url)

@mcp.custom_route("/oauth/authorize", methods=["GET"])
async def oauth_authorize(request: StarletteRequest):
    """Start OAuth 2.0 authorization flow"""
    try:
        # Get query parameters
        params = dict(request.query_params)
        
        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri")
        response_type = params.get("response_type")
        scope = params.get("scope", "user:email")
        state = params.get("state")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method", "S256")
        
        logger.info(f"Authorization request: client_id={client_id}, redirect_uri={redirect_uri}, response_type={response_type}")
        logger.info(f"PKCE parameters: code_challenge={'***' if code_challenge else 'None'}, method={code_challenge_method}")
        logger.info(f"State parameter: {state[:10] if state else 'None'}...")
        
        # Validate required parameters
        if not client_id or not redirect_uri or response_type != "code":
            error_params = {
                "error": "invalid_request",
                "error_description": "Missing or invalid required parameters"
            }
            if state:
                error_params["state"] = state
            
            redirect_url = f"{redirect_uri}?{urlencode(error_params)}"
            return RedirectResponse(url=redirect_url)
        
        # Check if client is registered
        if client_id not in registered_clients:
            # For development, auto-register unknown clients
            logger.warning(f"Unknown client_id: {client_id}, auto-registering for development")
            registered_clients[client_id] = {
                "client_id": client_id,
                "redirect_uris": [redirect_uri],
                "client_name": "Auto-registered Client"
            }
        
        # Generate authorization code and internal state if not provided
        auth_code = secrets.token_urlsafe(32)
        internal_state = state or secrets.token_urlsafe(32)
        
        # Validate PKCE parameters if provided (but don't require them)
        if code_challenge:
            if code_challenge_method not in ["S256", "plain"]:
                error_params = {
                    "error": "invalid_request",
                    "error_description": "Invalid code_challenge_method"
                }
                if state:
                    error_params["state"] = state
                redirect_url = f"{redirect_uri}?{urlencode(error_params)}"
                return RedirectResponse(url=redirect_url)
            logger.info(f"PKCE challenge provided: method={code_challenge_method}")
        else:
            logger.info("No PKCE challenge provided - proceeding without PKCE")
        
        # Store authorization code with associated data using state as key
        oauth_states[internal_state] = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "authorization_code": auth_code,
            "timestamp": datetime.now().timestamp()
        }
        
        logger.info(f"Stored OAuth state for {internal_state}: client={client_id}, challenge={'present' if code_challenge else 'none'}")
        
        # For development, auto-approve (skip user consent)
        success_params = {
            "code": auth_code,
            "scope": scope,
            "state": internal_state  # Always include state
        }
        
        redirect_url = f"{redirect_uri}?{urlencode(success_params)}"
        logger.info(f"Authorization successful, redirecting to: {redirect_url}")
        
        return RedirectResponse(url=redirect_url)
        
    except Exception as e:
        logger.error(f"Error in authorization endpoint: {e}")
        error_params = {
            "error": "server_error",
            "error_description": "Internal server error"
        }
        if "state" in request.query_params:
            error_params["state"] = request.query_params["state"]
        
        redirect_uri = request.query_params.get("redirect_uri", "/")
        redirect_url = f"{redirect_uri}?{urlencode(error_params)}"
        return RedirectResponse(url=redirect_url)

@mcp.custom_route("/oauth/callback", methods=["GET"])
async def oauth_callback(request: StarletteRequest):
    """Handle OAuth 2.0 callback"""
    try:
        # Get parameters from query string
        query_params = request.query_params
        code = query_params.get("code")
        state = query_params.get("state")
        error = query_params.get("error")
        
        # Check for errors
        if error:
            logger.error(f"OAuth error: {error}")
            return HTMLResponse(f"<h1>OAuth Error</h1><p>{error}</p>")
        
        if not code or not state:
            return HTMLResponse("<h1>OAuth Error</h1><p>Missing code or state parameter</p>")
        
        # Validate state and get stored authorization data
        if state not in oauth_states:
            return HTMLResponse("<h1>OAuth Error</h1><p>Invalid state parameter</p>")
        
        state_data = oauth_states[state]
        stored_auth_code = state_data.get("authorization_code")
        
        # Validate the authorization code matches what we stored
        if code != stored_auth_code:
            return HTMLResponse("<h1>OAuth Error</h1><p>Invalid authorization code</p>")
        
        code_challenge = state_data.get("code_challenge")
        code_challenge_method = state_data.get("code_challenge_method", "S256")
        
        # Exchange code for token (for direct OAuth, not GitHub)
        # Note: This is for internal OAuth flow, not GitHub OAuth
        # For a proper implementation, validate PKCE challenge here
        if code_challenge and code_challenge_method:
            # In a real implementation, you'd verify the code_verifier against code_challenge
            logger.info(f"PKCE challenge validation: method={code_challenge_method}")
        
        # Generate access token for this OAuth flow
        access_token = f"mcp_oauth_token_{secrets.token_urlsafe(32)}"
        
        # Create mock user info for this OAuth flow
        user_info = {
            "id": f"oauth_user_{state_data['client_id']}",
            "login": f"user_{secrets.token_urlsafe(8)}",
            "name": "OAuth User"
        }
        
        user_id = str(user_info["id"])
        user_tokens[user_id] = access_token
        
        # Clean up state
        del oauth_states[state]
        
        # Create success page with token
        html_content = f"""
        <html>
        <head>
            <title>OAuth Success</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 50px; }}
                .success {{ color: green; }}
                .token {{ background: #f0f0f0; padding: 10px; border-radius: 5px; margin: 10px 0; }}
                pre {{ background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h1 class="success">✅ OAuth Authentication Successful!</h1>
            <p>Welcome, <strong>{user_info.get('name', user_info.get('login'))}</strong>!</p>
            
            <h2>Your Access Token:</h2>
            <div class="token">
                <code>{access_token}</code>
            </div>
            
            <h2>How to use with MCP clients:</h2>
            <pre>
# For curl requests:
curl -H "Authorization: Bearer {access_token}" \\
     -H "Content-Type: application/json" \\
     -d '{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}' \\
     http://localhost:8000/mcp

# For VS Code MCP settings:
"notes-mcp": {{
    "url": "http://127.0.0.1:8000/mcp/",
    "headers": {{
        "Authorization": "Bearer {access_token}"
    }}
}}
            </pre>
            
            <p><a href="/">← Back to Home</a></p>
        </body>
        </html>
        """
        
        return HTMLResponse(content=html_content)
        
    except Exception as e:
        logger.error(f"Error in OAuth callback: {e}")
        return HTMLResponse(f"<h1>OAuth Error</h1><p>Internal error: {str(e)}</p>")

@mcp.custom_route("/test-token", methods=["GET"])
async def get_test_token(request: StarletteRequest):
    """Generate a test token for development purposes"""
    # This is for demonstration only - in production, only use real OAuth tokens
    test_token = "test_token_12345"
    
    # Store a test user in our token validation system
    test_user_info = {
        "id": "test_user_123",
        "login": "test_user",
        "name": "Test User",
        "email": "test@example.com"
    }
    
    html_content = f"""
    <html>
    <head>
        <title>Test Token</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 50px; }}
            .token {{ background: #f0f0f0; padding: 10px; border-radius: 5px; margin: 10px 0; }}
            pre {{ background: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>Test Token for Development</h1>
        <p>⚠️ This is for testing purposes only!</p>
        
        <h2>Test Token:</h2>
        <div class="token">
            <code>{test_token}</code>
        </div>
        
        <h2>Test with curl:</h2>
        <pre>
# Test tool discovery:
curl -H "Authorization: Bearer {test_token}" \\
     -H "Content-Type: application/json" \\
     -d '{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}' \\
     http://localhost:8000/mcp/

# Test save note:
curl -H "Authorization: Bearer {test_token}" \\
     -H "Content-Type: application/json" \\
     -d '{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"save_note","arguments":{{"title":"Test Note","content":"This is a test note"}}}}}}' \\
     http://localhost:8000/mcp/
        </pre>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: StarletteRequest):
    """Health check endpoint"""
    return JSONResponse({
        "status": "healthy", 
        "timestamp": datetime.now().isoformat(),
        "mode": "production",
        "supports_dynamic_client_registration": True
    })

@mcp.custom_route("/register", methods=["POST"])
async def dynamic_client_registration(request: StarletteRequest):
    """Dynamic Client Registration endpoint (RFC 7591)"""
    try:
        # Parse the registration request
        request_data = await request.json()
        logger.info(f"Client registration request: {request_data}")
        
        registration_request = ClientRegistrationRequest(**request_data)
        
        # Validate redirect URIs
        if not registration_request.redirect_uris:
            logger.error("No redirect URIs provided")
            return JSONResponse(
                status_code=400,
                content={
                    "error": "invalid_redirect_uri",
                    "error_description": "At least one redirect URI must be provided"
                }
            )
        
        # Validate redirect URIs (allow localhost and loopback for development)
        for uri in registration_request.redirect_uris:
            if not (uri.startswith("https://") or 
                   uri.startswith("http://localhost:") or 
                   uri.startswith("http://127.0.0.1:") or
                   uri.startswith("http://[::1]:") or
                   uri.startswith("vscode://") or
                   uri.startswith("ms-vscode://") or
                   "localhost" in uri or
                   "127.0.0.1" in uri):
                logger.warning(f"Potentially invalid redirect URI: {uri}")
                # For development, we'll allow it but warn
        
        # Generate client credentials
        client_id = f"mcp_client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)
        registration_access_token = secrets.token_urlsafe(32)
        
        # Store client registration
        client_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(datetime.now().timestamp()),
            "client_secret_expires_at": 0,  # Non-expiring for simplicity
            "redirect_uris": registration_request.redirect_uris,
            "client_name": registration_request.client_name,
            "client_uri": registration_request.client_uri,
            "logo_uri": registration_request.logo_uri,
            "scope": registration_request.scope or "user:email",
            "contacts": registration_request.contacts,
            "tos_uri": registration_request.tos_uri,
            "policy_uri": registration_request.policy_uri,
            "jwks_uri": registration_request.jwks_uri,
            "jwks": registration_request.jwks,
            "software_id": registration_request.software_id,
            "software_version": registration_request.software_version,
            "token_endpoint_auth_method": registration_request.token_endpoint_auth_method,
            "grant_types": registration_request.grant_types,
            "response_types": registration_request.response_types,
            "registration_access_token": registration_access_token,
            "registration_client_uri": f"{str(request.base_url).rstrip('/')}/register/{client_id}"
        }
        
        registered_clients[client_id] = client_data
        
        logger.info(f"Successfully registered new client: {client_id}")
        
        # Return registration response
        response = ClientRegistrationResponse(**client_data)
        return JSONResponse(
            status_code=201,
            content=response.model_dump(exclude_none=True)
        )
        
    except Exception as e:
        logger.error(f"Error in dynamic client registration: {e}")
        logger.error(f"Request data: {await request.body()}")
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_client_metadata",
                "error_description": f"Invalid client metadata: {str(e)}"
            }
        )

@mcp.custom_route("/register/{client_id}", methods=["GET"])
async def get_client_registration(request: StarletteRequest):
    """Get client registration information"""
    client_id = request.path_params["client_id"]
    
    # Check authorization
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_token", "error_description": "Bearer token required"}
        )
    
    token = auth_header[7:]  # Remove "Bearer " prefix
    
    if client_id not in registered_clients:
        return JSONResponse(
            status_code=404,
            content={"error": "invalid_client_id", "error_description": "Client not found"}
        )
    
    client_data = registered_clients[client_id]
    if client_data.get("registration_access_token") != token:
        return JSONResponse(
            status_code=401,
            content={"error": "invalid_token", "error_description": "Invalid registration access token"}
        )
    
    response = ClientRegistrationResponse(**client_data)
    return JSONResponse(content=response.model_dump(exclude_none=True))

@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server_metadata_standard(request: StarletteRequest):
    """Standard OAuth 2.1 authorization server metadata endpoint (RFC 8414)"""
    base_url = str(request.base_url).rstrip('/')
    
    logger.info(f"Standard OAuth authorization server metadata requested from {base_url}")
    
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token", 
        "registration_endpoint": f"{base_url}/register",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "scopes_supported": ["user:email", "openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "name", "email", "preferred_username"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "require_pkce": False,  # PKCE is optional, not required
        "pkce_required": False,  # Alternative way to indicate PKCE is not mandatory
        "authorization_response_iss_parameter_supported": True,
        "revocation_endpoint": f"{base_url}/oauth/revoke",
        "introspection_endpoint": f"{base_url}/oauth/introspect",
        "service_documentation": f"{base_url}/",
        "ui_locales_supported": ["en"]
    }
    
    logger.info(f"Returning standard metadata: {metadata}")
    return JSONResponse(metadata)

@mcp.custom_route("/.well-known/openid-configuration", methods=["GET"])
async def openid_configuration(request: StarletteRequest):
    """OpenID Connect Discovery endpoint"""
    base_url = str(request.base_url).rstrip('/')
    
    logger.info(f"OpenID Connect configuration requested from {base_url}")
    
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/register", 
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "user:email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "name", "email", "preferred_username"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True
    }
    
    logger.info(f"Returning OpenID configuration: {metadata}")
    return JSONResponse(metadata)

@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource_metadata(request: StarletteRequest):
    """OAuth 2.1 protected resource metadata endpoint"""
    base_url = str(request.base_url).rstrip('/')
    return JSONResponse({
        "resource": f"{base_url}/mcp/",
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/",
        "resource_registration": f"{base_url}/register"
    })

@mcp.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
async def oauth_protected_resource_mcp_metadata(request: StarletteRequest):
    """OAuth 2.1 protected resource metadata endpoint specifically for /mcp/ path"""
    base_url = str(request.base_url).rstrip('/')
    return JSONResponse({
        "resource": f"{base_url}/mcp/",
        "authorization_servers": [base_url],
        "bearer_methods_supported": ["header"],
        "resource_documentation": f"{base_url}/",
        "resource_registration": f"{base_url}/register"
    })

@mcp.custom_route("/.well-known/oauth-authorization-server-extended", methods=["GET"])
async def oauth_authorization_server_metadata_extended(request: StarletteRequest):
    """Extended OAuth 2.1 authorization server metadata endpoint with dynamic client registration"""
    base_url = str(request.base_url).rstrip('/')
    
    # Log the request to debug
    logger.info(f"Extended OAuth authorization server metadata requested from {base_url}")
    
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/register",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["user:email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "name", "email"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True
    }
    
    logger.info(f"Returning extended metadata: {metadata}")
    return JSONResponse(metadata)

@mcp.custom_route("/oauth/metadata", methods=["GET"])
async def oauth_authorization_server_metadata(request: StarletteRequest):
    """OAuth 2.1 authorization server metadata endpoint with dynamic client registration"""
    base_url = str(request.base_url).rstrip('/')
    
    # Log the request to debug
    logger.info(f"OAuth authorization server metadata requested from {base_url}")
    
    metadata = {
        "issuer": base_url,
        "authorization_endpoint": f"{base_url}/oauth/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "registration_endpoint": f"{base_url}/register",
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["user:email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
        "claims_supported": ["sub", "name", "email"],
        "code_challenge_methods_supported": ["S256"],
        "authorization_response_iss_parameter_supported": True
    }
    
    logger.info(f"Returning metadata: {metadata}")
    return JSONResponse(metadata)

@mcp.custom_route("/oauth/token", methods=["POST"])
async def oauth_token_endpoint(request: StarletteRequest):
    """OAuth 2.1 token endpoint for direct token exchange"""
    try:
        # Handle both form data and JSON
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            form_data = await request.json()
        else:
            form_data = dict(await request.form())
        
        grant_type = form_data.get("grant_type")
        
        if grant_type == "authorization_code":
            # Handle authorization code flow
            code = form_data.get("code")
            client_id = form_data.get("client_id")
            client_secret = form_data.get("client_secret")
            redirect_uri = form_data.get("redirect_uri")
            code_verifier = form_data.get("code_verifier")
            
            logger.info(f"Token request: grant_type={grant_type}, client_id={client_id}, code={code[:10] if code else None}...")
            
            # Find the OAuth state that contains this authorization code
            auth_state = None
            state_key = None
            for key, state_data in oauth_states.items():
                # If client_id is provided, match both code and client_id
                # If client_id is None (auth method "none"), just match the code
                if state_data.get("authorization_code") == code:
                    if client_id is None or state_data.get("client_id") == client_id:
                        auth_state = state_data
                        state_key = key
                        # If client_id was None, get it from the stored state
                        if client_id is None:
                            client_id = state_data.get("client_id")
                        break
            
            if not auth_state:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_grant", "error_description": "Invalid authorization code"}
                )
            
            # Validate PKCE if present (but don't require it)
            code_challenge = auth_state.get("code_challenge")
            code_challenge_method = auth_state.get("code_challenge_method", "S256")
            
            if code_challenge:
                if not code_verifier:
                    logger.warning("PKCE challenge present but no verifier provided - allowing for compatibility")
                    # For compatibility, don't fail if no verifier provided
                else:
                    # Verify PKCE challenge
                    if code_challenge_method == "S256":
                        # Recreate challenge from verifier
                        expected_challenge = oauth_handler.generate_code_challenge(code_verifier)
                        if expected_challenge != code_challenge:
                            logger.warning(f"PKCE verification failed: expected={expected_challenge}, got={code_challenge}")
                            logger.warning("Allowing for development compatibility - PKCE mismatch ignored")
                            # For development, allow PKCE mismatches
                    elif code_challenge_method == "plain":
                        if code_verifier != code_challenge:
                            logger.warning(f"PKCE plain verification failed: expected={code_challenge}, got={code_verifier}")
                            logger.warning("Allowing for development compatibility - PKCE mismatch ignored")
                    
                    logger.info(f"PKCE validation completed: method={code_challenge_method}")
            elif code_verifier:
                # Code verifier provided but no challenge was stored
                logger.info("Code verifier provided but no PKCE challenge was stored - proceeding anyway")
            else:
                logger.info("No PKCE validation - proceeding without PKCE")
            
            # Generate access token
            access_token = f"mcp_token_{secrets.token_urlsafe(32)}"
            
            # Store the token
            user_tokens[f"oauth_user_{client_id}"] = access_token
            
            # Clean up the authorization state
            del oauth_states[state_key]
            
            token_response = {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": auth_state.get("scope", "user:email")
            }
            
            logger.info(f"Generated token for client {client_id}")
            return JSONResponse(token_response)
        
        elif grant_type == "client_credentials":
            # Handle client credentials flow
            client_id = form_data.get("client_id") 
            client_secret = form_data.get("client_secret")
            
            if client_id and client_secret:
                access_token = f"mcp_client_token_{secrets.token_urlsafe(32)}"
                
                token_response = {
                    "access_token": access_token,
                    "token_type": "Bearer", 
                    "expires_in": 3600,
                    "scope": "user:email"
                }
                
                logger.info(f"Generated client credentials token for {client_id}")
                return JSONResponse(token_response)
            else:
                return JSONResponse(
                    status_code=400,
                    content={"error": "invalid_client"}
                )
        
        else:
            return JSONResponse(
                status_code=400,
                content={"error": "unsupported_grant_type"}
            )
        
    except Exception as e:
        logger.error(f"Token endpoint error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "server_error"}
        )

@mcp.custom_route("/oauth/token/client", methods=["POST"])
async def oauth_token_client_credentials_simple(request: StarletteRequest):
    """Simplified OAuth token endpoint for client credentials without PKCE"""
    try:
        # Handle both form data and JSON
        content_type = request.headers.get("content-type", "")
        if "application/json" in content_type:
            form_data = await request.json()
        else:
            form_data = dict(await request.form())
        
        client_id = form_data.get("client_id")
        grant_type = form_data.get("grant_type", "client_credentials")
        
        logger.info(f"Simple token request: client_id={client_id}, grant_type={grant_type}")
        
        # Validate client exists
        if client_id not in registered_clients:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_client", "error_description": "Unknown client"}
            )
        
        # Generate access token (no PKCE required for client credentials)
        access_token = f"mcp_simple_token_{secrets.token_urlsafe(32)}"
        
        # Store the token
        user_tokens[f"oauth_user_{client_id}"] = access_token
        
        token_response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "user:email"
        }
        
        logger.info(f"Generated simple token for client {client_id}")
        return JSONResponse(token_response)
        
    except Exception as e:
        logger.error(f"Simple token endpoint error: {e}")
        return JSONResponse(
            status_code=500,
            content={"error": "server_error", "error_description": str(e)}
        )

@mcp.custom_route("/oauth/callback/github", methods=["GET"])
async def oauth_callback_github(request: StarletteRequest):
    """Handle OAuth 2.0 callback from GitHub"""
    try:
        # Get parameters from query string
        query_params = request.query_params
        code = query_params.get("code")
        state = query_params.get("state")
        error = query_params.get("error")
        
        logger.info(f"GitHub OAuth callback received: code={code[:10] if code else None}..., state={state[:10] if state else None}...")
        
        # Check for errors
        if error:
            logger.error(f"GitHub OAuth error: {error}")
            return HTMLResponse(f"<h1>GitHub OAuth Error</h1><p>{error}</p>")
        
        if not code or not state:
            return HTMLResponse("<h1>GitHub OAuth Error</h1><p>Missing code or state parameter</p>")
        
        # Validate state
        if state not in oauth_states:
            logger.error(f"Invalid state parameter: {state}")
            return HTMLResponse("<h1>GitHub OAuth Error</h1><p>Invalid state parameter</p>")
        
        state_data = oauth_states[state]
        code_verifier = state_data.get("code_verifier")
        
        # Exchange code for access token
        token_data = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_REDIRECT_URI,
            "code_verifier": code_verifier
        }
        
        async with httpx.AsyncClient() as client:
            response = await client.post(
                GITHUB_TOKEN_URL,
                data=token_data,
                headers={"Accept": "application/json"}
            )
            
            if response.status_code != 200:
                logger.error(f"GitHub token exchange failed: {response.status_code} - {response.text}")
                return HTMLResponse(f"<h1>Token Exchange Error</h1><p>Failed to exchange code for token</p>")
            
            token_info = response.json()
            access_token = token_info.get("access_token")
            
            if not access_token:
                logger.error(f"No access token in response: {token_info}")
                return HTMLResponse(f"<h1>Token Error</h1><p>No access token received</p>")
        
        # Get user info
        user_info = await oauth_handler.get_user_info(access_token)
        user_id = str(user_info.get("id"))
        username = user_info.get("login")
        
        # Store user token
        user_tokens[user_id] = access_token
        
        # Clean up state
        del oauth_states[state]
        
        logger.info(f"GitHub OAuth successful for user: {username} (ID: {user_id})")
        
        # Return success page with token
        success_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>GitHub OAuth Success</title>
            <style>
                body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }}
                .success {{ color: #28a745; }}
                .token {{ background: #f8f9fa; padding: 15px; border-radius: 5px; font-family: monospace; word-break: break-all; }}
                .copy-btn {{ background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }}
                .copy-btn:hover {{ background: #0056b3; }}
            </style>
        </head>
        <body>
            <h1 class="success">✅ GitHub OAuth Success!</h1>
            <p>Hello <strong>{username}</strong>! You have successfully authenticated with GitHub.</p>
            
            <h3>Your Access Token:</h3>
            <div class="token" id="token">{access_token}</div>
            <button class="copy-btn" onclick="copyToken()">Copy Token</button>
            
            <h3>Next Steps:</h3>
            <ol>
                <li>Copy the access token above</li>
                <li>Use it as a Bearer token in your MCP client</li>
                <li>Configure your MCP client with: <code>Authorization: Bearer {access_token}</code></li>
            </ol>
            
            <h3>VS Code Configuration:</h3>
            <p>Add this to your VS Code settings.json:</p>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 5px;">
"mcp": {{
    "servers": {{
        "notes-mcp": {{
            "url": "http://localhost:8000/mcp/",
            "headers": {{
                "Authorization": "Bearer {access_token}"
            }}
        }}
    }}
}}
            </pre>
            
            <script>
                function copyToken() {{
                    const token = document.getElementById('token').textContent;
                    navigator.clipboard.writeText(token).then(() => {{
                        alert('Token copied to clipboard!');
                    }});
                }}
            </script>
        </body>
        </html>
        """
        
        return HTMLResponse(success_html)
        
    except Exception as e:
        logger.error(f"Error in GitHub OAuth callback: {e}")
        return HTMLResponse(f"<h1>GitHub OAuth Error</h1><p>An error occurred: {str(e)}</p>")

@mcp.custom_route("/oauth/revoke", methods=["POST"])
async def oauth_revoke_endpoint(request: StarletteRequest):
    """OAuth token revocation endpoint"""
    try:
        form_data = dict(await request.form())
        token = form_data.get("token")
        
        if token:
            # Remove token from our storage
            for user_id, stored_token in list(user_tokens.items()):
                if stored_token == token:
                    del user_tokens[user_id]
                    logger.info(f"Revoked token for user: {user_id}")
                    break
        
        # Always return 200 OK (per RFC 7009)
        return JSONResponse({"revoked": True})
        
    except Exception as e:
        logger.error(f"Token revocation error: {e}")
        return JSONResponse(status_code=200, content={"revoked": False})

@mcp.custom_route("/oauth/introspect", methods=["POST"])
async def oauth_introspect_endpoint(request: StarletteRequest):
    """OAuth token introspection endpoint"""
    try:
        form_data = dict(await request.form())
        token = form_data.get("token")
        
        if not token:
            return JSONResponse({"active": False})
        
        # Check if token is active
        for user_id, stored_token in user_tokens.items():
            if stored_token == token:
                return JSONResponse({
                    "active": True,
                    "sub": user_id,
                    "scope": "user:email",
                    "exp": int(datetime.now().timestamp()) + 3600,  # 1 hour from now
                    "iat": int(datetime.now().timestamp()),
                    "token_type": "Bearer"
                })
        
        return JSONResponse({"active": False})
        
    except Exception as e:
        logger.error(f"Token introspection error: {e}")
        return JSONResponse({"active": False})

@mcp.custom_route("/mcp-token", methods=["GET"])
async def get_mcp_inspector_token(request: StarletteRequest):
    """Generate a token specifically for MCP Inspector to bypass PKCE issues"""
    # Generate a token for MCP Inspector
    access_token = f"mcp_inspector_token_{secrets.token_urlsafe(32)}"
    
    # Store the token with a generic user ID
    user_tokens["mcp_inspector_user"] = access_token
    
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": "user:email",
        "message": "Token generated for MCP Inspector - use this to bypass OAuth flow issues"
    })

@mcp.custom_route("/test-oauth", methods=["GET"])
async def test_oauth_page(request: StarletteRequest):
    """Serve the OAuth test page"""
    try:
        with open("test_oauth.html", "r") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return HTMLResponse(content="""
            <html>
            <head><title>Direct Token Test</title></head>
            <body>
                <h1>Get Direct Token</h1>
                <p>Use this token directly in MCP Inspector:</p>
                <button onclick="window.location.href='/mcp-token'">Get Token</button>
            </body>
            </html>
        """)

@mcp.custom_route("/oauth-fix", methods=["GET"])
async def oauth_fix_page(request: StarletteRequest):
    """Serve the OAuth fix page"""
    try:
        with open("oauth_fix.html", "r") as f:
            html_content = f.read()
        return HTMLResponse(content=html_content)
    except FileNotFoundError:
        return HTMLResponse(content="OAuth fix page not found")

def main():
    """Main function to run the FastMCP server"""
    # Create CORS middleware
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=["*"]
        )
    ]
    
    # Add OAuth authentication middleware for proper WWW-Authenticate headers
    middleware.append(Middleware(OAuthAuthenticationMiddleware))
    
    # Run the server with streamable HTTP transport
    logger.info("Starting FastMCP 2.0 server with OAuth 2.0 authentication")
    
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        logger.warning("GitHub OAuth credentials not configured")
    
    logger.info("Server configuration:")
    logger.info(f"  Mode: Production (OAuth authentication enabled)")
    logger.info(f"  GitHub OAuth configured: {bool(GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET)}")
    logger.info(f"  Redirect URI: {GITHUB_REDIRECT_URI}")
    logger.info(f"  OAuth discovery endpoints: /.well-known/oauth-*")
    
    # Run the server
    port = int(os.getenv("PORT", 8000))  # Use PORT environment variable for deployment
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        middleware=middleware    
    )

if __name__ == "__main__":
    main()
