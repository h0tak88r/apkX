#!/bin/bash

# Run apkX with automatic GitLab sync in background
# This keeps the ORIGINAL UI and features, just adds GitLab backup

set -e

echo "🚀 apkX with Automatic GitLab Sync"
echo "===================================="
echo ""

# Load token
if [ -z "$GITLAB_TOKEN" ]; then
    if [ -f ~/.gitlab_token ]; then
        source ~/.gitlab_token
    else
        echo "❌ GITLAB_TOKEN not set"
        echo "Run: source ~/.gitlab_token"
        exit 1
    fi
fi

export GITLAB_PROJECT="${GITLAB_PROJECT:-e9101230/apkx}"

echo "✓ GitLab Project: $GITLAB_PROJECT"
echo "✓ Original UI: Full-featured"
echo "✓ Auto-sync: Enabled (every 5 minutes)"
echo ""

# Check for docker compose
if command -v docker-compose &> /dev/null; then
    COMPOSE_CMD="docker-compose"
elif command -v docker compose &> /dev/null; then
    COMPOSE_CMD="docker compose"
else
    echo "❌ Docker Compose not found"
    exit 1
fi

# Start services
echo "🔨 Building and starting services..."
$COMPOSE_CMD -f docker-compose-with-gitlab-sync.yml up --build -d

echo ""
echo "✅ apkX is running!"
echo ""
echo "📊 Web Interface (Original UI):"
echo "   http://localhost:9090"
echo ""
echo "🔄 GitLab Auto-Sync: Active"
echo "   Files automatically synced every 5 minutes"
echo "   https://gitlab.com/$GITLAB_PROJECT/-/tree/storage/web-data"
echo ""
echo "📋 View logs:"
echo "   $COMPOSE_CMD -f docker-compose-with-gitlab-sync.yml logs -f"
echo ""
echo "🛑 Stop services:"
echo "   $COMPOSE_CMD -f docker-compose-with-gitlab-sync.yml down"
echo ""

