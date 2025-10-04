#!/bin/bash

# GitLab Deployment Script for apkX
# This script helps deploy apkX using GitLab Container Registry

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
REGISTRY_IMAGE=""
TAG="latest"
PORT="9090"
DATA_DIR="./web-data"
CONFIG_DIR="./config"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -i, --image IMAGE     GitLab Container Registry image (required)"
    echo "  -t, --tag TAG         Image tag (default: latest)"
    echo "  -p, --port PORT       Port to expose (default: 9090)"
    echo "  -d, --data-dir DIR    Data directory (default: ./web-data)"
    echo "  -c, --config-dir DIR  Config directory (default: ./config)"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Example:"
    echo "  $0 -i registry.gitlab.com/yourusername/apkx -t v3.3.0"
    echo "  $0 -i registry.gitlab.com/yourusername/apkx -t latest -p 8080"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--image)
            REGISTRY_IMAGE="$2"
            shift 2
            ;;
        -t|--tag)
            TAG="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -d|--data-dir)
            DATA_DIR="$2"
            shift 2
            ;;
        -c|--config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$REGISTRY_IMAGE" ]; then
    print_error "GitLab Container Registry image is required!"
    show_usage
    exit 1
fi

print_status "Starting apkX deployment with GitLab Container Registry"
print_status "Image: $REGISTRY_IMAGE:$TAG"
print_status "Port: $PORT"
print_status "Data directory: $DATA_DIR"
print_status "Config directory: $CONFIG_DIR"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    print_error "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Create necessary directories
print_status "Creating necessary directories..."
mkdir -p "$DATA_DIR/uploads"
mkdir -p "$DATA_DIR/reports"
mkdir -p "$DATA_DIR/downloads"

# Check if config directory exists
if [ ! -d "$CONFIG_DIR" ]; then
    print_error "Config directory '$CONFIG_DIR' does not exist!"
    print_status "Please ensure you have the config directory with regexes.yaml"
    exit 1
fi

# Pull the latest image
print_status "Pulling image from GitLab Container Registry..."
docker pull "$REGISTRY_IMAGE:$TAG"

# Stop existing container if running
if docker ps -q -f name=apkx-web > /dev/null 2>&1; then
    print_status "Stopping existing apkx-web container..."
    docker stop apkx-web
    docker rm apkx-web
fi

# Run the container
print_status "Starting apkx-web container..."
docker run -d \
    --name apkx-web \
    -p "$PORT:9090" \
    -v "$(pwd)/$DATA_DIR:/web-data" \
    -v "$(pwd)/$CONFIG_DIR:/config" \
    -e APKX_UPLOAD_DIR=/web-data/uploads \
    -e APKX_REPORTS_DIR=/web-data/reports \
    -e APKX_DOWNLOAD_DIR=/web-data/downloads \
    -e APKX_PATTERNS_PATH=/config/regexes.yaml \
    --restart unless-stopped \
    "$REGISTRY_IMAGE:$TAG"

# Wait for container to start
print_status "Waiting for container to start..."
sleep 5

# Check if container is running
if docker ps -q -f name=apkx-web > /dev/null 2>&1; then
    print_success "apkx-web container is running!"
    print_success "Web interface is available at: http://localhost:$PORT"
    print_status "Container logs: docker logs apkx-web"
    print_status "Stop container: docker stop apkx-web"
    print_status "Remove container: docker rm apkx-web"
else
    print_error "Failed to start apkx-web container!"
    print_status "Container logs:"
    docker logs apkx-web
    exit 1
fi

print_success "Deployment completed successfully!"
