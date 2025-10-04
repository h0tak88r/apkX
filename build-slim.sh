#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

echo "🚀 Building and slimming apkX Docker images..."

# Build original image (if not already built)
if ! docker images | grep -q "apkx-web.*original"; then
    print_status "Building apkx-web:original..."
    docker build -t apkx-web:original -f Dockerfile . || { print_error "Failed to build apkx-web:original"; exit 1; }
else
    print_status "apkx-web:original already exists, skipping build"
fi

# Build slim image
print_status "Building apkx-web:slim..."
docker build -t apkx-web:slim -f Dockerfile.slim . || { print_error "Failed to build apkx-web:slim"; exit 1; }

print_status "Slim image sizes:"
docker images --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}" | grep "apkx-web" | grep "slim"

print_status "Running Docker Slim optimization..."

# Optimize apkx-web
print_status "Optimizing apkx-web with Docker Slim..."
if docker-slim build --target apkx-web:slim --tag apkx-web:slim-optimized --continue-after 30 --http-probe=false --exec-probe=false --keep-perms --rt-as-user=true --image-build-engine=internal; then
    print_status "✅ apkx-web:slim-optimized created"
else
    print_warning "Docker Slim optimization failed for apkx-web, using slim version"
    docker tag apkx-web:slim apkx-web:slim-optimized
fi

print_status "Final image sizes:"
docker images --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}" | grep "apkx-web" | grep "slim\\|original" | sort -k1,1 -k2,2r

echo "=== FINAL IMAGE SIZE COMPARISON ==="
docker images --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}" | grep "apkx-web" | grep "original" | sort -k1,1
docker images --format "{{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.CreatedSince}}\t{{.Size}}" | grep "apkx-web" | grep "slim" | sort -k1,1

print_status "✅ Build and optimization complete!"
print_status "You can now use 'docker-compose -f docker-slim.yml up' to run the optimized container."
