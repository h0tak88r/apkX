#!/bin/bash

# apkX Docker Setup Script
# This script helps users set up and run apkX using Docker

set -e

echo "🚀 apkX Docker Setup"
echo "===================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first:"
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first:"
    echo "   https://docs.docker.com/compose/install/"
    exit 1
fi

# Create necessary directories
echo "📁 Creating necessary directories..."
mkdir -p web-data/uploads web-data/reports web-data/downloads
chmod 755 web-data/uploads web-data/reports web-data/downloads
touch web-data/uploads/.gitkeep web-data/reports/.gitkeep web-data/downloads/.gitkeep

# Build the Docker image
echo "🔨 Building Docker image..."
docker-compose build

# Start the services
echo "🚀 Starting apkX web server..."
docker-compose up -d

# Wait for the service to be ready
echo "⏳ Waiting for apkX to start..."
sleep 10

# Check if the service is running
if curl -f http://localhost:9090/ &> /dev/null; then
    echo "✅ apkX is running successfully!"
    echo ""
    echo "🌐 Web Interface: http://localhost:9090"
    echo "📊 Upload APK/IPA files through the web interface"
    echo ""
    echo "📋 Useful commands:"
    echo "   View logs:     docker-compose logs -f"
    echo "   Stop service:  docker-compose down"
    echo "   Restart:       docker-compose restart"
    echo "   Update:        docker-compose pull && docker-compose up -d"
    echo ""
    echo "📁 Data directories:"
    echo "   Uploads:       ./web-data/uploads/"
    echo "   Reports:       ./web-data/reports/"
    echo "   Downloads:     ./web-data/downloads/"
else
    echo "❌ Failed to start apkX. Check the logs:"
    echo "   docker-compose logs"
    exit 1
fi
