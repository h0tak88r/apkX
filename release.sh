#!/bin/bash

# apkX Release Script
# This script helps create a new release

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

# Check if we're in the right directory
if [ ! -f "go.mod" ] || [ ! -f "Dockerfile" ]; then
    print_error "Please run this script from the apkX root directory"
    exit 1
fi

# Check if git is clean
if [ -n "$(git status --porcelain)" ]; then
    print_error "Working directory is not clean. Please commit or stash changes first."
    git status --short
    exit 1
fi

# Get current version
CURRENT_VERSION=$(grep 'version-v' README.md | sed 's/.*version-v\([0-9.]*\).*/\1/')
print_status "Current version: $CURRENT_VERSION"

# Get new version
read -p "Enter new version (current: $CURRENT_VERSION): " NEW_VERSION

if [ -z "$NEW_VERSION" ]; then
    print_error "Version cannot be empty"
    exit 1
fi

# Validate version format
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    print_error "Invalid version format. Use semantic versioning (e.g., 3.3.0)"
    exit 1
fi

print_status "Preparing release v$NEW_VERSION..."

# Update version in README.md
sed -i "s/version-v$CURRENT_VERSION/version-v$NEW_VERSION/g" README.md
print_success "Updated version in README.md"

# Update version in CHANGELOG.md if needed
if ! grep -q "## \[v$NEW_VERSION\]" CHANGELOG.md; then
    print_warning "Please add changelog entry for v$NEW_VERSION in CHANGELOG.md"
fi

# Build and test
print_status "Building and testing..."

# Test Docker build
print_status "Testing Docker build..."
docker build -t apkx-web:test .

# Test Docker Compose
print_status "Testing Docker Compose..."
docker-compose down 2>/dev/null || true
docker-compose up -d
sleep 10

# Test web interface
if curl -f http://localhost:9090/ > /dev/null 2>&1; then
    print_success "Web interface is working"
else
    print_error "Web interface test failed"
    docker-compose down
    exit 1
fi

docker-compose down
print_success "All tests passed"

# Create release commit
print_status "Creating release commit..."
git add README.md CHANGELOG.md
git commit -m "Release v$NEW_VERSION

- Updated version to $NEW_VERSION
- Enhanced Docker support
- Improved UI/UX
- iOS analysis improvements
- Fixed volume mounting issues"

# Create and push tag
print_status "Creating and pushing tag v$NEW_VERSION..."
git tag -a "v$NEW_VERSION" -m "Release v$NEW_VERSION"
git push origin main
git push origin "v$NEW_VERSION"

print_success "Release v$NEW_VERSION created and pushed!"

# Show next steps
echo ""
print_status "Next steps:"
echo "1. GitHub Actions will automatically build and create the release"
echo "2. Monitor the build at: https://github.com/h0tak88r/apkX/actions"
echo "3. Once complete, the release will be available at: https://github.com/h0tak88r/apkX/releases"
echo ""
print_status "Release includes:"
echo "- Binary releases for Linux, Windows, and macOS"
echo "- Docker image for easy deployment"
echo "- Comprehensive release notes"
echo "- Updated documentation"
echo ""
print_success "Release v$NEW_VERSION is ready! 🚀"
