# FastMCP 2.0 OAuth 2.1 Server

A production-ready MCP (Model Context Protocol) server built with FastMCP 2.0 framework, featuring complete OAuth 2.1 authentication, dynamic client registration, and GitHub integration.

## 🚀 Features

### Core Capabilities
- **FastMCP 2.0**: Modern MCP server with streamable HTTP transport
- **OAuth 2.1 Authentication**: Complete OAuth implementation with PKCE support
- **Dynamic Client Registration**: RFC 7591 compliant client management
- **GitHub Integration**: OAuth flow with GitHub API integration
- **Bearer Token Authentication**: Standard token-based security
- **Production Ready**: Secure, scalable deployment

### MCP Tools
- `save_note(title, content, tags)` - Save notes with optional tags
- `get_notes(tag)` - Retrieve notes, optionally filtered by tag

### Authentication Methods
- **GitHub OAuth Flow**: Complete OAuth 2.1 authorization
- **Direct Token Access**: Internal tokens for development/testing
- **Bearer Token Auth**: Standard HTTP Authorization header

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│                 MCP Client                  │
│         (VS Code, Claude, Cursor)           │
└─────────────────┬───────────────────────────┘
                  │ HTTP/Bearer Token
                  │
┌─────────────────▼───────────────────────────┐
│              FastMCP 2.0                    │
│        Streamable HTTP Transport            │
│     ┌─────────────────────────────────┐     │
│     │       OAuth 2.1 Layer           │     │
│     │   (GitHub Authentication)       │     │
│     └─────────────────────────────────┘     │
│     ┌─────────────────────────────────┐     │
│     │         MCP Tools               │     │
│     │   • save_note                   │     │
│     │   • get_notes                   │     │
│     └─────────────────────────────────┘     │
└─────────────────────────────────────────────┘
```

## 🔧 Quick Start

### Prerequisites
- Python 3.8+
- GitHub OAuth App (for production)

### Local Development

1. **Clone and setup**:
   ```bash
   git clone <repository>
   cd RemoteMcpServer
   pip install -r requirements.txt
   ```

2. **Run the server**:
   ```bash
   python fastmcp_server.py
   ```

3. **Server starts on**: http://localhost:8000

### VS Code Integration

Your VS Code is already configured! The server should connect automatically with the existing configuration in `mcp.json`:

```json
{
  "servers": {
    "notes-2": {
      "url": "http://127.0.0.1:8000/mcp/"
    }
  }
}
```

For authenticated access, you can update it to:

```json
{
  "servers": {
    "notes-server": {
      "url": "http://127.0.0.1:8000/mcp/"
    }
  }
}
```

Generate tokens at: http://localhost:8000/oauth/token-generator

## 🔐 Authentication

### OAuth 2.1 Flow
1. **Authorization**: `GET /oauth/authorize` - Redirects to GitHub OAuth
2. **Callback**: `GET /oauth/callback/github` - Handles GitHub response
3. **Token Exchange**: `POST /oauth/token` - Exchanges code for token

### Token Generation
- **Development**: Visit http://localhost:8000/oauth/token-generator
- **Production**: Use full OAuth flow with GitHub

### API Endpoints

#### OAuth Discovery
- `GET /.well-known/oauth-authorization-server` - OAuth metadata
- `GET /.well-known/oauth-authorization-server-extended` - Extended metadata
- `GET /.well-known/oauth-protected-resource` - Resource metadata

#### Dynamic Client Registration
- `POST /register` - Register new OAuth client
- `GET /register/{client_id}` - Get client information

#### MCP Protocol
- `POST /mcp/` - MCP endpoint (requires Bearer token)

## 📋 **Deployment Workflow Summary**

### **Phase 1: Quick Deployment (No OAuth setup needed)**
1. ✅ Push code to GitHub
2. ✅ Deploy to Render (no environment variables)
3. ✅ Get your Render URL: `https://your-app-name.onrender.com`
4. ✅ Test with token generator: `https://your-app-name.onrender.com/oauth/token-generator`
5. ✅ Update VS Code with Render URL and generated token

### **Phase 2: Optional GitHub OAuth (After deployment)**
1. 🔧 Create GitHub OAuth app with your actual Render URL
2. 🔧 Add environment variables to Render
3. 🔧 Automatic redeployment with OAuth support

**You can use your MCP server immediately after Phase 1!** Phase 2 is optional for enhanced authentication.

---

## 🔧 Detailed Deployment Guide

### **Deployment Strategy**
You have two deployment options:

1. **Quick Start (Recommended)**: Deploy without OAuth first, then add GitHub integration
2. **Full OAuth Setup**: Set up GitHub app first (requires knowing your future Render URL)

We'll use the **Quick Start** approach since you won't know your Render URL until after deployment.

### **Step-by-Step Deployment**

#### **Step 1: Prepare Repository**
Your repository is already Render-ready! The server automatically:
- Uses `PORT` environment variable (Render requirement)
- Includes `Procfile` for deployment
- Has proper `requirements.txt`

#### **Step 2: Deploy to Render**

1. **Sign up**: Go to https://render.com and sign up (use GitHub for easy connection)

2. **Create Web Service**:
   - Click "New +" → "Web Service"
   - Choose "Build and deploy from a Git repository"
   - Connect to GitHub and select your repository

3. **Configure Service**:
   ```
   Name: fastmcp-oauth-server (or your preferred name)
   Environment: Python 3
   Region: Choose closest to your users
   Branch: main
   Build Command: pip install -r requirements.txt
   Start Command: python fastmcp_server.py
   ```

4. **Set Instance Type**:
   - **Free Tier**: Choose "Starter" (0.1 CPU, 512 MB RAM) - Perfect for testing
   - **Paid**: Choose higher specs for production load

#### **Step 3: Environment Variables (Initial Deployment)**
**Start with NO environment variables** - the server works perfectly with internal tokens:

```bash
# Leave environment variables empty for initial deployment
# The server will work with internal token generation
```

**Why this works:**
- Server has built-in token generation at `/oauth/token-generator`
- No GitHub OAuth needed for basic MCP functionality
- You can add OAuth later once you know your Render URL

#### **Step 4: Deploy**
- Click "Create Web Service"
- Render will build and deploy automatically
- Build time: ~2-3 minutes
- Your app will be live at: `https://YOUR_APP_NAME.onrender.com`

### **Testing Your Deployment**

#### **Immediate Testing (No OAuth needed)**:
```bash
# Test server health
curl https://YOUR-ACTUAL-RENDER-URL.onrender.com/health

# Generate a token
# Visit: https://YOUR-ACTUAL-RENDER-URL.onrender.com/oauth/token-generator
```

#### **Test MCP Tools**:
```bash
curl -X POST https://YOUR-ACTUAL-RENDER-URL.onrender.com/mcp/ \
  -H "Authorization: Bearer mcp_inspector_token_YOUR_GENERATED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

### **Update VS Code Configuration**

After deployment, update your `mcp.json` with your actual Render URL:

```json
{
  "servers": {
    "notes-server-prod": {
      "url": "https://YOUR-ACTUAL-RENDER-URL.onrender.com/mcp/",
      "headers": {
        "Authorization": "Bearer mcp_inspector_token_YOUR_GENERATED_TOKEN"
      }
    }
  }
}
```

**Steps to get your token:**
1. Visit `https://YOUR-ACTUAL-RENDER-URL.onrender.com/oauth/token-generator`
2. Click "Generate Token"
3. Copy the generated token
4. Update your VS Code `mcp.json` with the token

### **Render-Specific Features**

#### **Auto-Deploy**:
- Every git push to main branch triggers automatic deployment
- No manual intervention needed

#### **Free Tier Limitations**:
- Sleeps after 15 minutes of inactivity
- Cold start time: ~30 seconds
- 750 hours/month free

#### **Monitoring**:
- View logs in Render dashboard
- Monitor performance and usage
- Set up alerts for downtime

#### **Custom Domain** (Optional):
- Add your custom domain in Render settings
- Update OAuth redirect URIs accordingly
- SSL certificates provided automatically

---

## 🚀 Deployment

### Environment Variables
```bash
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
GITHUB_REDIRECT_URI=https://your-domain.com/oauth/callback/github
```

### Railway (Recommended)
1. Create Railway account at https://railway.app
2. Connect your GitHub repository
3. Add environment variables
4. Deploy automatically

### Render (Detailed Instructions)

1. **Create Render Account**:
   - Go to https://render.com
   - Sign up with GitHub (recommended for easy repo connection)

2. **Create New Web Service**:
   - Click "New +" → "Web Service"
   - Connect your GitHub repository
   - Select this repository: `RemoteMcpServer`

3. **Configure Build Settings**:
   ```
   Name: fastmcp-oauth-server
   Environment: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: python fastmcp_server.py
   ```

4. **Set Environment Variables**:
   ```bash
   GITHUB_CLIENT_ID=your_github_oauth_app_client_id
   GITHUB_CLIENT_SECRET=your_github_oauth_app_client_secret
   GITHUB_REDIRECT_URI=https://your-app-name.onrender.com/oauth/callback/github
   ```

5. **Advanced Settings**:
   ```
   Instance Type: Starter (Free tier available)
   Region: Choose closest to your location
   Auto-Deploy: Yes (deploys on git push)
   ```

6. **Deploy**:
   - Click "Create Web Service"
   - Render will automatically build and deploy
   - Initial deployment takes 3-5 minutes

7. **Post-Deployment**:
   - Your server will be available at: `https://your-app-name.onrender.com`
   - Test health: `https://your-app-name.onrender.com/health`
   - Token generator: `https://your-app-name.onrender.com/oauth/token-generator`

### **Phase 2: Add GitHub OAuth (After Deployment)**

Once your server is deployed and you have your Render URL, you can optionally add GitHub OAuth:

#### **Step 1: Create GitHub OAuth App**
1. **Go to GitHub Settings**:
   - Settings → Developer settings → OAuth Apps → "New OAuth App"

2. **Configure OAuth App**:
   ```
   Application name: FastMCP Server
   Homepage URL: https://YOUR-ACTUAL-RENDER-URL.onrender.com
   Authorization callback URL: https://YOUR-ACTUAL-RENDER-URL.onrender.com/oauth/callback/github
   ```

3. **Save and note down**:
   - Client ID
   - Client Secret

#### **Step 2: Update Render Environment Variables**
Add these to your Render service:
```bash
GITHUB_CLIENT_ID=your_actual_client_id
GITHUB_CLIENT_SECRET=your_actual_client_secret
GITHUB_REDIRECT_URI=https://YOUR-ACTUAL-RENDER-URL.onrender.com/oauth/callback/github
```

#### **Step 3: Redeploy**
- Environment variable changes trigger automatic redeployment
- Your server now supports both internal tokens AND GitHub OAuth

## ✅ **Quick Deployment Checklist**

Before deploying to Render, ensure:

- [ ] Repository is pushed to GitHub
- [ ] `.gitignore` protects sensitive files ✅ (comprehensive coverage included)
- [ ] `requirements.txt` includes all dependencies
- [ ] Server uses `PORT` environment variable ✅ (already configured)
- [ ] Server binds to `0.0.0.0` ✅ (already configured)
- [ ] OAuth redirect URI will match your Render domain
- [ ] Test locally with `python fastmcp_server.py`
- [ ] No `.env` files or secrets committed ✅ (protected by .gitignore)

**Ready to deploy!** 🚀

## 🧪 Testing

### Running Tests
```bash
# Run all tests
python -m pytest tests/

# Run specific test categories
python tests/test_comprehensive_oauth.py      # OAuth flow testing
python tests/test_dynamic_client_registration.py  # Client registration
python tests/test_oauth_flow_complete.py     # End-to-end testing
```

### Manual Testing

### Health Check
```bash
curl http://localhost:8000/health
```

### OAuth Discovery
```bash
curl http://localhost:8000/.well-known/oauth-authorization-server
```

### MCP Tools (with authentication)
```bash
curl -X POST http://localhost:8000/mcp/ \
  -H "Authorization: Bearer mcp_inspector_token_YOUR_GENERATED_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

## 📁 Project Structure

```
RemoteMcpServer/
├── fastmcp_server.py              # Main server implementation
├── README.md                      # This documentation
├── .gitignore                     # Comprehensive Git ignore rules
├── requirements.txt               # Python dependencies
├── requirements_fastmcp.txt       # FastMCP specific dependencies
├── pyproject.toml                # Project configuration
├── uv.lock                       # Dependency lock file
├── Dockerfile                    # Container deployment
├── Procfile                      # Render deployment config
├── start_fastmcp.sh              # Server startup script
├── oauth_fix.html                # Token generator interface
├── templates/                    # HTML templates
│   └── debug.html               # Debug interface
└── tests/                       # Test suite
    ├── __init__.py              # Test package init
    ├── test_comprehensive_oauth.py      # Complete OAuth flow tests
    ├── test_dynamic_client_registration.py  # Client registration tests
    └── test_oauth_flow_complete.py     # End-to-end OAuth tests
```

### **Git Configuration**
The project includes a comprehensive `.gitignore` that covers:

- **Python artifacts**: `__pycache__/`, `*.pyc`, virtual environments
- **Security files**: `.env`, API keys, SSL certificates, OAuth secrets
- **Development tools**: VS Code, PyCharm, Vim configurations
- **Operating systems**: macOS, Windows, Linux temp files
- **FastMCP specific**: Server logs, token storage, MCP data
- **Deployment**: Render, Railway, Heroku, Docker artifacts
- **Testing**: Coverage reports, pytest cache
- **Package managers**: uv.lock, node_modules, pip logs

This ensures sensitive data and build artifacts never get committed to your repository.

## 🔍 Key Components

### GitHubBearerAuthProvider
Custom authentication provider that handles:
- GitHub OAuth token validation
- Internal token recognition
- User context management

### OAuth2Handler
Complete OAuth 2.1 implementation:
- PKCE code challenge/verifier
- State parameter for CSRF protection
- Dynamic client registration
- Token endpoint management

### MCP Tools Integration
- `save_note`: Persistent note storage with tagging
- `get_notes`: Note retrieval with filtering
- User-scoped data storage

## 🛠️ Development

### Adding New Tools
```python
@mcp.tool
async def your_tool(param: str, ctx: Context = None) -> str:
    """Your tool description"""
    # Implementation
    return result
```

### Adding New Resources
```python
@mcp.resource
async def your_resource(uri: str, ctx: Context = None):
    """Your resource description"""
    # Implementation
    return resource_data
```

## 📚 Standards Compliance

- **RFC 6749**: OAuth 2.0 Authorization Framework
- **RFC 7636**: PKCE for OAuth Public Clients
- **RFC 7591**: Dynamic Client Registration Protocol
- **RFC 8414**: OAuth 2.0 Authorization Server Metadata
- **MCP Protocol**: Model Context Protocol specification

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues and questions:
1. Check the server logs for error details
2. Verify OAuth configuration
3. Test with the token generator interface
4. Review the MCP protocol documentation

---

**Server Status**: ✅ Production Ready  
**Last Updated**: July 13, 2025  
**FastMCP Version**: 2.10.5  
**MCP Protocol**: 1.11.0

### **Render Troubleshooting**

#### **Common Issues**:

1. **Build Fails**:
   ```bash
   # Check requirements.txt has all dependencies
   pip freeze > requirements.txt
   ```

2. **Server Won't Start**:
   - Ensure `python fastmcp_server.py` works locally
   - Check Render logs for specific error messages
   - Verify PORT environment variable usage

3. **OAuth Callback Errors**:
   - Double-check `GITHUB_REDIRECT_URI` matches your Render URL exactly
   - Ensure GitHub OAuth app has correct callback URL

4. **Free Tier Sleep**:
   - Server sleeps after 15 minutes of inactivity
   - First request after sleep takes ~30 seconds
   - Consider upgrading for production use

#### **Debugging Steps**:
1. Check Render service logs
2. Test health endpoint: `/health`
3. Verify environment variables are set
4. Test locally with same environment variables
