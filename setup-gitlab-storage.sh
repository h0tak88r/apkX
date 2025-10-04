#!/bin/bash

# GitLab Storage Setup Script for apkX
# This script helps you set up GitLab as your file storage backend

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   GitLab Storage Setup for apkX                ║${NC}"
echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo ""

# Check if sync tool exists
if [ ! -f "./sync-to-gitlab" ]; then
    echo -e "${YELLOW}Building sync tool...${NC}"
    go build -o sync-to-gitlab cmd/sync-to-gitlab/main.go
    echo -e "${GREEN}✓ Sync tool built${NC}"
    echo ""
fi

# Get GitLab project ID
echo -e "${BLUE}Step 1: GitLab Project Configuration${NC}"
echo -e "Your GitLab project: ${GREEN}e9101230/apkx${NC}"
read -p "Is this correct? (y/n): " confirm
if [[ $confirm != [yY] ]]; then
    read -p "Enter your GitLab project ID (e.g., username/project): " PROJECT_ID
else
    PROJECT_ID="e9101230/apkx"
fi
echo ""

# Get GitLab token
echo -e "${BLUE}Step 2: GitLab Personal Access Token${NC}"
echo "You need to create a Personal Access Token with 'api' scope"
echo "Go to: https://gitlab.com/-/profile/personal_access_tokens"
echo ""

if [ -n "$GITLAB_TOKEN" ]; then
    echo -e "${GREEN}✓ Found GITLAB_TOKEN environment variable${NC}"
    USE_ENV_TOKEN=true
else
    echo -e "${YELLOW}No GITLAB_TOKEN environment variable found${NC}"
    read -sp "Enter your GitLab token: " TOKEN
    echo ""
    USE_ENV_TOKEN=false
fi
echo ""

# Show current storage
echo -e "${BLUE}Step 3: Current Storage Status${NC}"
if [ -d "web-data" ]; then
    TOTAL_SIZE=$(du -sh web-data 2>/dev/null | cut -f1)
    FILE_COUNT=$(find web-data -type f 2>/dev/null | wc -l)
    echo -e "Local storage: ${YELLOW}$TOTAL_SIZE${NC} ($FILE_COUNT files)"
    
    echo ""
    echo "Breakdown:"
    if [ -d "web-data/uploads" ]; then
        UPLOADS_SIZE=$(du -sh web-data/uploads 2>/dev/null | cut -f1)
        UPLOADS_COUNT=$(find web-data/uploads -type f 2>/dev/null | wc -l)
        echo -e "  Uploads:  ${YELLOW}$UPLOADS_SIZE${NC} ($UPLOADS_COUNT files)"
    fi
    if [ -d "web-data/reports" ]; then
        REPORTS_SIZE=$(du -sh web-data/reports 2>/dev/null | cut -f1)
        REPORTS_COUNT=$(find web-data/reports -type f 2>/dev/null | wc -l)
        echo -e "  Reports:  ${YELLOW}$REPORTS_SIZE${NC} ($REPORTS_COUNT files)"
    fi
    if [ -d "web-data/downloads" ]; then
        DOWNLOADS_SIZE=$(du -sh web-data/downloads 2>/dev/null | cut -f1)
        DOWNLOADS_COUNT=$(find web-data/downloads -type f 2>/dev/null | wc -l)
        echo -e "  Downloads: ${YELLOW}$DOWNLOADS_SIZE${NC} ($DOWNLOADS_COUNT files)"
    fi
else
    echo -e "${YELLOW}No web-data directory found${NC}"
    mkdir -p web-data/{uploads,reports,downloads}
    echo -e "${GREEN}✓ Created web-data directories${NC}"
fi
echo ""

# Ask what to sync
echo -e "${BLUE}Step 4: What would you like to sync?${NC}"
echo "1) Everything (uploads + reports + downloads)"
echo "2) Uploads only"
echo "3) Reports only"
echo "4) Custom selection"
echo "5) Dry run first (recommended)"
read -p "Choose option (1-5): " SYNC_OPTION
echo ""

# Prepare sync command
SYNC_CMD="./sync-to-gitlab -project \"$PROJECT_ID\""
if [ "$USE_ENV_TOKEN" = false ]; then
    SYNC_CMD="$SYNC_CMD -token \"$TOKEN\""
fi

# Execute based on choice
case $SYNC_OPTION in
    1)
        echo -e "${YELLOW}Syncing everything to GitLab...${NC}"
        eval "$SYNC_CMD -dir web-data -remote web-data"
        ;;
    2)
        echo -e "${YELLOW}Syncing uploads to GitLab...${NC}"
        eval "$SYNC_CMD -dir web-data/uploads -remote web-data/uploads"
        ;;
    3)
        echo -e "${YELLOW}Syncing reports to GitLab...${NC}"
        eval "$SYNC_CMD -dir web-data/reports -remote web-data/reports"
        ;;
    4)
        echo "Enter directory to sync (e.g., web-data/uploads):"
        read -p "Local directory: " LOCAL_DIR
        read -p "Remote path: " REMOTE_PATH
        echo -e "${YELLOW}Syncing $LOCAL_DIR to GitLab...${NC}"
        eval "$SYNC_CMD -dir \"$LOCAL_DIR\" -remote \"$REMOTE_PATH\""
        ;;
    5)
        echo -e "${YELLOW}Running dry run...${NC}"
        eval "$SYNC_CMD -dir web-data -remote web-data -dry-run"
        echo ""
        echo -e "${GREEN}Dry run complete!${NC}"
        echo "Run this script again and choose option 1-4 to actually sync files"
        exit 0
        ;;
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}═════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✓ Sync completed successfully!${NC}"
echo -e "${GREEN}═════════════════════════════════════════════════${NC}"
echo ""

echo -e "${BLUE}Next Steps:${NC}"
echo ""
echo "1. View your files in GitLab:"
echo -e "   ${GREEN}https://gitlab.com/$PROJECT_ID/-/tree/storage/web-data${NC}"
echo ""
echo "2. Setup automated backups (optional):"
echo -e "   ${YELLOW}# Add to crontab${NC}"
echo "   crontab -e"
echo "   # Add this line to sync every 6 hours:"
echo "   0 */6 * * * cd $(pwd) && $SYNC_CMD >> /tmp/gitlab-sync.log 2>&1"
echo ""
echo "3. Save your GitLab token (if not already set):"
echo -e "   ${YELLOW}echo 'export GITLAB_TOKEN=\"your-token\"' >> ~/.bashrc${NC}"
echo "   source ~/.bashrc"
echo ""
echo "4. Read the full guide:"
echo -e "   ${YELLOW}cat GITLAB_STORAGE.md${NC}"
echo ""

echo -e "${BLUE}═════════════════════════════════════════════════${NC}"
echo -e "${BLUE}Thank you for using apkX with GitLab Storage!${NC}"
echo -e "${BLUE}═════════════════════════════════════════════════${NC}"

