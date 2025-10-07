#!/bin/bash

# apkX All-in-One Manager
# - Installs dependencies (Docker, Compose)
# - Runs apkX (normal Docker mode)
# - Runs apkX with GitLab storage (via docker-compose override)
# - Installs CLI binary (optional)

set -euo pipefail

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

echo -e "${BLUE}apkX Manager${NC}"
echo "==============="

project_root() {
  cd "$(dirname "$0")" >/dev/null 2>&1
  pwd
}

ensure_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    return 1
  fi
}

install_docker() {
  echo -e "${YELLOW}Installing Docker...${NC}"
  curl -fsSL https://get.docker.com -o get-docker.sh
  sh get-docker.sh
  rm -f get-docker.sh
}

install_compose() {
  echo -e "${YELLOW}Installing Docker Compose...${NC}"
  curl -fsSL "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
}

ensure_dependencies() {
  echo -e "${BLUE}Checking dependencies...${NC}"
  ensure_cmd curl || { echo -e "${YELLOW}Installing curl...${NC}"; apt-get update && apt-get install -y curl >/dev/null 2>&1 || true; }
  if ! ensure_cmd docker; then install_docker; fi
  if ! ensure_cmd docker-compose; then install_compose; fi
  echo -e "${GREEN}Dependencies OK${NC}"
}

prepare_data_dirs() {
  echo -e "${BLUE}Preparing data directories...${NC}"
  mkdir -p web-data/uploads web-data/reports web-data/downloads
  chmod 755 web-data/uploads web-data/reports web-data/downloads || true
}

run_normal() {
  ensure_dependencies
  prepare_data_dirs
  echo -e "${BLUE}Building and starting apkX (normal mode)...${NC}"
  docker-compose build
  docker-compose up -d
  echo -e "${GREEN}apkX running at http://localhost:9090${NC}"
}

run_gitlab() {
  ensure_dependencies
  echo -e "${BLUE}Configuring GitLab storage...${NC}"
  # Require env vars
  : "${GITLAB_BASE_URL:?Set GITLAB_BASE_URL (e.g., https://gitlab.com)}"
  : "${GITLAB_PROJECT_ID:?Set GITLAB_PROJECT_ID (e.g., 12345678)}"
  : "${GITLAB_TOKEN:?Set GITLAB_TOKEN (Personal Access Token with api scope)}"

  # Create override file with GitLab env
  cat > docker-compose.override.yml <<'YAML'
version: "3.8"
services:
  apkx-web:
    environment:
      - APKX_STORAGE=gitlab
      - GITLAB_BASE_URL=${GITLAB_BASE_URL}
      - GITLAB_PROJECT_ID=${GITLAB_PROJECT_ID}
      - GITLAB_TOKEN=${GITLAB_TOKEN}
YAML

  echo -e "${BLUE}Building and starting apkX (GitLab storage mode)...${NC}"
  docker-compose -f docker-compose.yml -f docker-compose.override.yml build
  docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d
  echo -e "${GREEN}apkX (GitLab mode) running at http://localhost:9090${NC}"
}

install_cli() {
  echo -e "${BLUE}Installing apkx CLI binary...${NC}"
  OS=$(uname -s | tr '[:upper:]' '[:lower:]')
  ARCH=$(uname -m)
  case "$ARCH" in x86_64|amd64) ARCH=amd64;; arm64|aarch64) ARCH=arm64;; *) echo -e "${RED}Unsupported arch: $ARCH${NC}"; exit 1;; esac
  case "$OS" in linux) OS=linux;; darwin) OS=darwin;; *) echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1;; esac
  BINARY_NAME="apkx-${OS}-${ARCH}"
  URL="https://github.com/h0tak88r/apkX/releases/latest/download/${BINARY_NAME}"
  echo -e "${BLUE}Downloading ${BINARY_NAME}...${NC}"
  curl -fL "$URL" -o "$BINARY_NAME"
  chmod +x "$BINARY_NAME"
  if [ -w /usr/local/bin ]; then
    cp "$BINARY_NAME" /usr/local/bin/apkx
    echo -e "${GREEN}Installed to /usr/local/bin/apkx${NC}"
  else
    mkdir -p "$HOME/.local/bin"
    cp "$BINARY_NAME" "$HOME/.local/bin/apkx"
    echo -e "${GREEN}Installed to $HOME/.local/bin/apkx${NC}"
    echo -e "${YELLOW}Ensure $HOME/.local/bin is on your PATH${NC}"
  fi
}

usage() {
  cat <<EOF
Usage: $0 [command]

Commands:
  up                Install deps and run apkX (Docker, normal mode)
  up:gitlab         Run apkX with GitLab storage (needs env: GITLAB_BASE_URL, GITLAB_PROJECT_ID, GITLAB_TOKEN)
  deps              Install/verify Docker + Compose
  cli:install       Install apkx CLI binary (from latest GitHub release)
  down              Stop containers
  logs              Tail logs
  restart           Restart service

Examples:
  $0 deps
  $0 up
  GITLAB_BASE_URL=https://gitlab.com GITLAB_PROJECT_ID=123 GITLAB_TOKEN=XXXX $0 up:gitlab
  $0 cli:install
EOF
}

cmd=${1:-}
case "$cmd" in
  up) run_normal;;
  up:gitlab) run_gitlab;;
  deps) ensure_dependencies;;
  cli:install) install_cli;;
  down) docker-compose down;;
  logs) docker-compose logs -f;;
  restart) docker-compose restart;;
  * ) usage;;
esac


