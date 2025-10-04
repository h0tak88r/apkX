#!/bin/bash

# Quick start script for apkX with GitLab Storage

set -e

echo "🚀 apkX with GitLab Storage"
echo "============================"
echo ""

# Check if token is set
if [ -z "$GITLAB_TOKEN" ]; then
    if [ -f ~/.gitlab_token ]; then
        echo "📝 Loading GitLab token from ~/.gitlab_token"
        source ~/.gitlab_token
    else
        echo "❌ Error: GITLAB_TOKEN not set"
        echo ""
        echo "Please set your GitLab token:"
        echo "  export GITLAB_TOKEN='your-token-here'"
        echo ""
        echo "Or create ~/.gitlab_token with:"
        echo "  export GITLAB_TOKEN='your-token-here'"
        echo "  export GITLAB_PROJECT='e9101230/apkx'"
        exit 1
    fi
fi

# Set defaults
export GITLAB_PROJECT="${GITLAB_PROJECT:-e9101230/apkx}"
export USE_GITLAB_STORAGE=true

echo "✓ GitLab Project: $GITLAB_PROJECT"
echo "✓ GitLab Token: ${GITLAB_TOKEN:0:20}..."
echo ""

# Check if Docker Compose is available
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif command -v docker compose &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo "❌ Error: Docker Compose not found"
    exit 1
fi

# Build and run
echo "🔨 Building Docker image..."
$COMPOSE_CMD -f docker-compose-gitlab.yml build

echo ""
echo "🚀 Starting apkX with GitLab storage..."
$COMPOSE_CMD -f docker-compose-gitlab.yml up -d

echo ""
echo "✅ apkX is running!"
echo ""
echo "📊 Access the web interface:"
echo "   http://localhost:9090"
echo ""
echo "📁 Files are stored in GitLab:"
echo "   https://gitlab.com/$GITLAB_PROJECT/-/tree/storage/web-data"
echo ""
echo "📋 View logs:"
echo "   $COMPOSE_CMD -f docker-compose-gitlab.yml logs -f"
echo ""
echo "🛑 Stop the server:"
echo "   $COMPOSE_CMD -f docker-compose-gitlab.yml down"
echo ""

