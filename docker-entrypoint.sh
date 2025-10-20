#!/bin/bash
# apkX Docker startup script
# Handles ipatool authentication and starts the web server

set -e

echo "🚀 Starting apkX Web Server..."

# Check if ipatool is available
if ! command -v ipatool &> /dev/null; then
    echo "❌ ipatool not found in PATH"
    exit 1
fi

echo "✅ ipatool found: $(ipatool --version)"

# Check if we have Apple ID credentials for manual authentication
if [ -n "$IPATOOL_EMAIL" ]; then
    echo "📱 Apple ID email provided: $IPATOOL_EMAIL"
    echo "   To authenticate ipatool manually, connect to the container and run:"
    echo "   docker exec -it apkx-web ipatool auth login --email $IPATOOL_EMAIL"
else
    echo "⚠️  No Apple ID email provided (IPATOOL_EMAIL)"
    echo "   iOS downloads will require manual authentication"
fi

# Check R2 storage configuration
if [ "$USE_R2_STORAGE" = "true" ]; then
    echo "☁️  Cloudflare R2 storage enabled"
    if [ -n "$R2_BUCKET_NAME" ]; then
        echo "   Bucket: $R2_BUCKET_NAME"
    else
        echo "   ⚠️  R2_BUCKET_NAME not set"
    fi
else
    echo "📁 Local storage mode"
fi

# Check authentication settings
if [ "$APKX_AUTH_ENABLED" = "true" ]; then
    echo "🔒 Authentication enabled"
    echo "   Username: ${APKX_AUTH_USERNAME:-admin}"
else
    echo "🔓 Authentication disabled - web interface is publicly accessible"
fi

echo ""
echo "🌐 Starting apkX web server on port ${PORT:-9090}..."

# Start the web server with all arguments passed through
exec /usr/local/bin/apkx-web "$@"
