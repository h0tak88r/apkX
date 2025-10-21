#!/bin/bash
# apkX iOS Auto-Authentication Setup Script

echo "🍎 apkX iOS Automatic Authentication Setup"
echo "=========================================="
echo ""

# Set your Apple ID credentials
export IPATOOL_EMAIL="msdslm88@gmail.com"
export IPATOOL_PASSWORD="sqcr-fsqg-pimd-wspe"
export IPATOOL_KEYCHAIN_PASSPHRASE="sallam@88"

echo "✅ Environment variables set:"
echo "   IPATOOL_EMAIL: $IPATOOL_EMAIL"
echo "   IPATOOL_PASSWORD: $IPATOOL_PASSWORD"
echo "   IPATOOL_KEYCHAIN_PASSPHRASE: $IPATOOL_KEYCHAIN_PASSPHRASE"
echo ""

echo "🚀 Starting Docker container with automatic authentication..."
echo ""

# Start the Docker container with the environment variables
docker-compose up --build
