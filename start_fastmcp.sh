#!/bin/bash
# FastMCP Notes Server Startup Script

echo "🚀 Starting FastMCP Notes Server..."
echo "📍 Server will be available at: http://localhost:8000"
echo "🔧 MCP endpoint: http://localhost:8000/mcp/"
echo "🏥 Health check: http://localhost:8000/health"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed or not in PATH"
    exit 1
fi

# Check if required packages are installed
if ! python3 -c "import fastmcp" &> /dev/null; then
    echo "❌ FastMCP is not installed. Please install dependencies:"
    echo "   pip install -r requirements_fastmcp.txt"
    exit 1
fi

# Load environment variables if .env exists
if [ -f .env ]; then
    echo "📋 Loading environment variables from .env"
    export $(cat .env | xargs)
fi

# Start the server
echo "🎯 Starting FastMCP server..."
python3 fastmcp_server.py
