#!/bin/bash

# apkX Docker Setup Script
# This script helps users set up and run apkX using Docker
# Works on fresh VPS/Ubuntu/Debian systems

set -e

echo "🚀 apkX Docker Setup"
echo "===================="

# Function to install Docker
install_docker() {
    echo "📦 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    rm get-docker.sh
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    echo "✅ Docker installed successfully!"
    echo "⚠️  You may need to log out and back in for group changes to take effect."
    echo "   Or run: newgrp docker"
}

# Function to install Docker Compose
install_docker_compose() {
    echo "📦 Installing Docker Compose..."
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    echo "✅ Docker Compose installed successfully!"
}

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed."
    read -p "Would you like to install Docker automatically? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_docker
    else
        echo "Please install Docker manually: https://docs.docker.com/get-docker/"
        exit 1
    fi
fi

# Check if Docker Compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed."
    read -p "Would you like to install Docker Compose automatically? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        install_docker_compose
    else
        echo "Please install Docker Compose manually: https://docs.docker.com/compose/install/"
        exit 1
    fi
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
