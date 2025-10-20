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

# Check if we have Apple ID credentials for automated authentication
if [ -n "$IPATOOL_EMAIL" ] && [ -n "$IPATOOL_PASSWORD" ]; then
    echo "🔐 Apple ID credentials provided, checking authentication..."
    
    # Set default keychain passphrase if not provided
    if [ -z "$IPATOOL_KEYCHAIN_PASSPHRASE" ]; then
        export IPATOOL_KEYCHAIN_PASSPHRASE="sallam@88"
    fi
    
    # Try to authenticate (this will be handled by the Go application)
    echo "📱 ipatool authentication will be handled automatically by the application"
else
    echo "⚠️  No Apple ID credentials provided (IPATOOL_EMAIL, IPATOOL_PASSWORD)"
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
