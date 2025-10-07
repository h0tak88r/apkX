# apkX 🔍⏱️

Advanced mobile app analysis tool with intelligent caching, pattern matching, comprehensive security vulnerability detection, and **web portal interface**. Supports Android APK, iOS IPA, and XAPK files.

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![GitHub Actions](https://img.shields.io/badge/github-actions-blue.svg)
![Version](https://img.shields.io/badge/version-v3.3.2-orange.svg)
[![Build and Release](https://github.com/h0tak88r/apkX/actions/workflows/build.yml/badge.svg)](https://github.com/h0tak88r/apkX/actions/workflows/build.yml)

<img width="1262" height="730" alt="image" src="https://github.com/user-attachments/assets/5b5361a4-7c90-44ce-b09e-2fc30409b94d" />


## Features ✨

### 🔍 **Pattern-Based Analysis**
- 🎯 Intelligent pattern matching with context
- 🔍 Deep APK analysis for:
  - URIs and endpoints
  - API keys and secrets
  - Firebase configurations
  - Access tokens
  - Email addresses
  - Database connections
  - Hardcoded credentials
  - And **1652+ patterns** (including new security vulnerability patterns)...

### 🛡️ **Comprehensive Security Vulnerability Detection**
- 🔄 **Task Hijacking**: Activity launch mode vulnerability analysis (singleTask, taskAffinity)
- 🚨 **Janus Vulnerability**: APK signature scheme analysis (V1/V2/V3)
- 🔒 **Insecure Storage**: SharedPreferences and SQLite security analysis
- 🔐 **Certificate Pinning**: SSL/TLS security implementation checks
- 🐛 **Debug Mode**: Production build security validation
- 📱 **Android Manifest Analysis**:
  - **Exported Activities**: Activities accessible by other apps
  - **Exported Services**: Services vulnerable to hijacking
  - **Exported Broadcast Receivers**: Intent-based vulnerabilities
  - **Exported Content Providers**: Data exposure risks
  - **WebViews**: XSS and injection possibilities
  - **Deep Links**: Custom URL scheme vulnerabilities
  - **File Provider Exports**: File access vulnerabilities
  - **Custom URL Schemes**: All custom schemes detection

### 📊 **Reporting & Output**
- 🌐 **Beautiful HTML Reports** with interactive visualization
- 📊 Detailed JSON reports with context
- 🎨 Beautiful terminal output with progress tracking
- 📄 Pagination and context toggling in HTML reports
- 🔍 Clean, readable vulnerability descriptions

### ⚡ **Performance & Efficiency**
- 🚀 Smart caching system for faster repeated analysis
- ⚡ Concurrent file processing (multi-threaded)
- 🔄 Automatic JADX installation
- 💾 Efficient disk usage with SHA256-based caching
- 🤖 Discord webhook integration for automated notifications

## What's New in v3.3.0 🆕

### 🐳 **Docker Support (NEW!)**
- **One-Command Setup**: Run `./docker-setup.sh` and you're ready!
- **All Dependencies Included**: JADX, apkeep, ipatool, apk-mitm pre-installed
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **No Manual Installation**: Everything configured automatically
- **Persistent Data**: Reports and uploads persist between restarts

### 🎨 **Enhanced UI/UX**
- **Modern Sidebar Design**: Clean, responsive navigation
- **Mobile-Friendly**: Responsive design with collapsible sidebar
- **Word Wrapping**: Long code lines wrap properly on all screen sizes
- **Better Navigation**: Smooth scrolling and active state management
- **Upload Success Alerts**: Clear feedback when files are uploaded

### 🔧 **iOS Analysis Improvements**
- **Binary Plist Support**: Automatic conversion of binary plists to readable format
- **Enhanced Pattern Matching**: iOS-specific regex patterns for better detection
- **Plist Download**: Download Info.plist files directly from reports
- **File Filtering**: Skips static iOS directories for faster analysis
- **Objective-C Support**: Analyzes .m, .mm, and .h files

### 🛠️ **Technical Improvements**
- **Fixed Docker Volume Mounting**: Reports directory now works correctly
- **Better Error Handling**: More descriptive error messages
- **File Validation**: Prevents processing of empty or corrupted files
- **Health Checks**: Container health monitoring
- **Optimized Build**: Smaller Docker images with better caching

### 🌐 **Web Portal Interface**
- 🖥️ **Modern Web UI**: Beautiful, responsive web interface
- 🌙 **Dark/Light Mode**: Toggle between themes with persistent preferences
- 📤 **Drag & Drop Upload**: Easy APK/IPA file upload with progress tracking
- ⬇️ **APK Download**: Download APKs by package name from multiple sources
- 🍎 **iOS App Download**: Download iOS apps by bundle ID using ipatool
- 🔔 **Discord Integration**: Per-upload webhook configuration
- 📊 **Report Management**: View and download all analysis reports
- 📱 **Mobile Friendly**: Responsive design works on all devices
- 🔧 **MITM Patching**: Apply HTTPS inspection patches using apk-mitm
- ⚡ **Async Processing**: Non-blocking analysis with real-time job status

## Requirements 🛠️

### Android Analysis
- Go 1.21+
- Java 8+ (for JADX)
- JADX (automatically downloaded if not found)

### iOS Analysis
- macOS (required for ipatool)
- ipatool (for iOS app downloading)
- class-dump-z (for binary analysis)
- otool (comes with Xcode Command Line Tools)
- plutil (comes with macOS)

### System prerequisites
- unzip, zip, tar, curl, git
- Linux, macOS, or Windows (via WSL)

### Optional but recommended tools
- Node.js 16+ and npm (for `apk-mitm` if you enable MITM patching)
- Python 3.8+ and pip (for `apkeep` APK downloader)

### Install external tools
```bash
# apk-mitm (MITM HTTPS patching)
npm install -g apk-mitm

# apkeep (APK download by package name)
pip install --upgrade apkeep

# iOS dependencies (macOS only)
bash scripts/install_ios_deps.sh
```

Notes:
- MITM patching is optional. If `apk-mitm` is not installed or fails, analysis continues on the original APK.
- XAPK files are supported; apkX automatically extracts the embedded APK before analysis.

## Quick Start 🚀

### Option 1: Docker (Recommended) 🐳

The easiest way to run apkX is using Docker. Works on fresh VPS/Ubuntu/Debian systems:

```bash
# One-liner installation (works on fresh VPS)
git clone https://github.com/h0tak88r/apkX.git && cd apkX && chmod +x docker-setup.sh && ./docker-setup.sh
```

**That's it!** The script will automatically:
- ✅ Install Docker and Docker Compose if needed
- ✅ Create necessary directories
- ✅ Build the Docker image
- ✅ Start the web server
- ✅ Verify everything is working

The web interface will be available at `http://localhost:9090`

**What's included in Docker:**
- ✅ All dependencies pre-installed (JADX, apkeep, ipatool, apk-mitm)
- ✅ Java Runtime and Node.js included
- ✅ Cross-platform support (Linux, macOS, Windows)
- ✅ Persistent data storage
- ✅ Health monitoring and auto-restart
- ✅ No manual setup required

**📖 Installation Guide**: See [INSTALL.md](INSTALL.md) for detailed instructions  
**🐳 Docker Guide**: See [DOCKER.md](DOCKER.md) for advanced Docker usage

Note: `web-data/` (uploads, reports, downloads) and local binaries are ignored via `.gitignore` to prevent accidental commits. Do not commit API keys, tokens, or environment files (`.env*`).

## Installation (Full Guide)

### One-liner (Fresh VPS)

```bash
git clone https://github.com/h0tak88r/apkX.git && cd apkX && chmod +x apkx.sh && ./apkx.sh up
```

### Manual Install

1) Install Docker and Docker Compose (Ubuntu/Debian):
```bash
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

2) Setup and run:
```bash
mkdir -p web-data/uploads web-data/reports web-data/downloads
docker-compose build && docker-compose up -d
```

3) Verify:
```bash
curl -f http://localhost:9090/
```

### Configuration

Set environment variables in `docker-compose.yml`:
```yaml
environment:
  - APKX_ROOT=/app
  - APKX_UPLOAD_DIR=/app/web-data/uploads
  - APKX_REPORTS_DIR=/app/web-data/reports
  - APKX_DOWNLOAD_DIR=/app/web-data/downloads
  - APKX_PATTERNS_PATH=/app/config/regexes.yaml
```

### Data Persistence
- `web-data/uploads/` — uploaded APK/IPA
- `web-data/reports/` — generated reports
- `web-data/downloads/` — downloaded apps

### Manage
```bash
./apkx.sh logs
./apkx.sh restart
./apkx.sh down
./apkx.sh deps
```

### Security
- Open port 9090 on firewall if remote
- Don’t commit `.env*`, tokens, or webhooks
- Consider reverse proxy (Nginx) for production

## GitLab Storage Mode (Optional)

You can use GitLab as the backing storage for reports/uploads.

Set the following environment variables and start with the GitLab mode command:

```bash
export GITLAB_BASE_URL=https://gitlab.com
export GITLAB_PROJECT_ID=12345678
export GITLAB_TOKEN=glpat_xxxxxxxxxxxxxxxxx

./apkx.sh up:gitlab
```

This generates a `docker-compose.override.yml` with the necessary environment and launches the service.

### Option 2: Manual Installation

## Installation 📦
```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# Build the CLI binary
go build -o apkx cmd/apkx/main.go

# Build the web server
go build -o apkx-web cmd/server/main.go
```

## Usage 🚀

### **🌐 Web Portal Interface (Recommended)**
```bash
# Start the web server
./apkx-web -addr :9090

# With Discord webhook (optional)
./apkx-web -addr :9090 -webhook "https://discord.com/api/webhooks/XXX/YYY"

# With MITM patching enabled
./apkx-web -addr :9090 -mitm

# Using environment variable
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/XXX/YYY"
./apkx-web -addr :9090
```

### Run with Docker
```bash
# Build image
docker build --no-cache -t apkx-web .

# Option A: Mount project root (simplest)
docker run --rm -p 9090:9090 \
  -v /home/sallam/apkX:/app \
  -e APKX_ROOT=/app \
  apkx-web

# Option B: Mount only required dirs/files
docker run --rm -p 9090:9090 \
  -v /home/sallam/apkX/web-data:/web-data \
  -v /home/sallam/apkX/config:/config \
  -e APKX_UPLOAD_DIR=/web-data/uploads \
  -e APKX_REPORTS_DIR=/web-data/reports \
  -e APKX_DOWNLOAD_DIR=/web-data/downloads \
  -e APKX_PATTERNS_PATH=/config/regexes.yaml \
  apkx-web
```

Notes:
- If you previously built the image, use `--no-cache` to avoid stale binaries with older hardcoded paths.
- The server auto-detects the project root. You can pin it with `APKX_ROOT` or override directories with `APKX_*` envs shown above.

### Run with Docker Compose
```bash
# Start service
docker compose up --build

# Run in background
docker compose up -d --build

# View logs
docker compose logs -f

# Stop and remove
docker compose down
```

Compose defaults:
- Exposes `9090` and runs apkx-web with smart root detection.
- Mounts the repository root into `/app` and sets `APKX_ROOT=/app`.
- To mount only required paths, adjust `volumes` in `docker-compose.yml` and set `APKX_*` envs accordingly.

### Quickstart Cheatsheet

#### Docker Compose (recommended)
```bash
# From repository root
docker compose up -d --build
docker compose logs -f
# Stop
docker compose down
```

#### Docker CLI
```bash
# Build
docker build --no-cache -t apkx-web .

# Run by mounting full repo (smart root detection)
docker run --rm -p 9090:9090 \
  -v $(pwd):/app \
  -e APKX_ROOT=/app \
  apkx-web

# Run by mounting only required dirs
mkdir -p web-data/uploads web-data/reports web-data/downloads
docker run --rm -p 9090:9090 \
  -v $(pwd)/web-data:/web-data \
  -v $(pwd)/config:/config \
  -e APKX_UPLOAD_DIR=/web-data/uploads \
  -e APKX_REPORTS_DIR=/web-data/reports \
  -e APKX_DOWNLOAD_DIR=/web-data/downloads \
  -e APKX_PATTERNS_PATH=/config/regexes.yaml \
  apkx-web
```

#### Bash (build and run locally)
```bash
# Build binaries
go build -o apkx cmd/apkx/main.go
go build -o apkx-web cmd/server/main.go

# Run web server
./apkx-web -addr :9090

# Optional: set env overrides
export APKX_ROOT=$(pwd)
export APKX_UPLOAD_DIR=$(pwd)/web-data/uploads
export APKX_REPORTS_DIR=$(pwd)/web-data/reports
export APKX_DOWNLOAD_DIR=$(pwd)/web-data/downloads
export APKX_PATTERNS_PATH=$(pwd)/config/regexes.yaml
./apkx-web -addr :9090
```

### Troubleshooting
- Compose “no such service”: run commands from the repo root containing `docker-compose.yml`.
- Empty reports directory: confirm startup log line prints `reportsRoot=/web-data/reports` and that `web-data` is mounted.
- Rebuild image if paths look stale: `docker build --no-cache -t apkx-web .` or `docker compose up --build`.

### Smart project root & paths
- The web server automatically detects the project root:
  1. Uses `APKX_ROOT` if set
  2. Walks up from the executable directory
  3. Falls back to the current working directory and walks up
- A directory is considered the root if it contains `config/regexes.yaml`, `web-data/`, `.git/`, or a `go.mod` referencing `github.com/h0tak88r/apkX`.

Derived defaults (overridable via env):
- `APKX_UPLOAD_DIR` default: `<root>/web-data/uploads`
- `APKX_REPORTS_DIR` default: `<root>/web-data/reports`
- `APKX_DOWNLOAD_DIR` default: `<root>/web-data/downloads`
- `APKX_PATTERNS_PATH` default: `<root>/config/regexes.yaml`

Example to pin root explicitly:
```bash
export APKX_ROOT=/home/sallam/apkX
./apkx-web -addr :9090
```

### One-shot installer (Debian/Ubuntu)
```bash
bash scripts/setup.sh
```

Then open `http://localhost:9090` in your browser to:
- Upload APK files via drag & drop
- Download APKs by package name from APKPure, Google Play, F-Droid, Huawei AppGallery
- Apply MITM patches for HTTPS inspection
- Configure Discord webhooks per upload
- View and download analysis reports
- Toggle between dark/light themes
- Real-time job status tracking

### **📱 Command Line Interface**

#### Android Apps
```bash
# Basic usage
./apkx [flags] <apk-file(s)>

# Analyze multiple APKs
./apkx app1.apk app2.apk app3.apk

# Specify output directory
./apkx -o custom-output-dir app.apk

# Use custom patterns file
./apkx -p custom-patterns.yaml app.apk

# Control worker count
./apkx -w 5 app.apk
```

#### iOS Apps
```bash
# Setup iOS authentication (macOS only)
bash scripts/setup_ios_auth.sh

# Download and analyze iOS app by bundle ID
./apkx -bundle-id com.apple.mobilesafari -download-ios -html

# Download specific version
./apkx -bundle-id com.apple.mobilesafari -ios-version 1.0.0 -download-ios -html

# Analyze existing IPA file (works on all platforms)
./apkx -ipa app.ipa -html

# Analyze IPA with custom output
./apkx -ipa app.ipa -o ios-results -html
```

### **Security Analysis Commands**
```bash
# Full comprehensive scan with all security checks (RECOMMENDED)
./apkx -html -apk target.apk

# Generate HTML report with all vulnerability categories
./apkx -html -apk target.apk

# Analyze specific APK with custom output
./apkx -html -o results -apk target.apk
```

### **Advanced Commands**
```bash
# Send both JSON and HTML reports to Discord
./apkx -html -wh "https://discord.com/api/webhooks/your-webhook-url" app.apk

# Full scan with custom output and workers
./apkx -html -o results -w 8 -apk target.apk
```

### **Command Line Flags**

#### General Flags
- `-o`: Output directory (default: "apkx-output")
- `-p`: Path to patterns file (default: "config/regexes.yaml")
- `-w`: Number of concurrent workers (default: 3)
- `-wh`: Discord webhook URL for sending results (optional)
- `-html`: Generate HTML report (default: false)

#### Android Flags
- `-apk`: Path to APK file
- `-janus`: Enable Janus vulnerability scanning
- `-task-hijacking`: Only scan for task hijacking vulnerabilities

#### iOS Flags
- `-ipa`: Path to IPA file
- `-bundle-id`: iOS app bundle ID to download and analyze
- `-ios-version`: iOS app version to download (optional)
- `-download-ios`: Download iOS app using ipatool

### **Web Server Flags**
- `-addr`: HTTP listen address (default: ":9090")
- `-webhook`: Default Discord webhook URL (optional)
- `-mitm`: Enable MITM patching for HTTPS inspection using apk-mitm
- `PORT`: Environment variable for port (e.g., `PORT=8080`)

## Security Vulnerability Detection 🛡️

### **Task Hijacking Analysis**
Detects activities vulnerable to task hijacking attacks:
- Activities with `singleTask` launch mode
- Exported activities with security implications
- Risk assessment based on export status

### **Janus Vulnerability Detection**
Analyzes APK signature schemes for Janus attack vulnerability:
- **V1 Signature**: Legacy signature scheme
- **V2 Signature**: Modern signature scheme (Android 7.0+)
- **V3 Signature**: Latest signature scheme (Android 9.0+)
- **Risk Levels**: None, Medium, High based on signature combinations

### **Insecure Storage Analysis**
Identifies insecure data storage practices:
- SharedPreferences usage without encryption
- Unencrypted SQLite databases
- Plain text data storage

### **Certificate Pinning Analysis**
Checks for SSL/TLS security implementations:
- Missing certificate pinning
- Insecure network communication
- MITM attack vulnerability

### **Debug Mode Detection**
Validates production build security:
- Debug mode enabled in production
- Security implications of debug builds

## HTML Report Features 🌐

The HTML report provides an interactive, beautiful visualization of all findings:

- **📊 Summary Dashboard**: Overview of all vulnerabilities and findings
- **🔍 Interactive Findings**: Click to expand context and details
- **📄 Pagination**: Navigate through large result sets
- **🎨 Clean Formatting**: ANSI code stripping and proper text formatting
- **📱 Responsive Design**: Works on desktop and mobile devices
- **⚡ Fast Loading**: Optimized for large reports

## Discord Integration 🤖
Send analysis results directly to your Discord channel:
1. Create a webhook in your Discord server
2. Use the `-wh` flag with your webhook URL
3. Both JSON and HTML reports will be sent as file attachments with a summary message
4. JSON report for programmatic access and HTML report for human-readable visualization

## Cache Management 💾
APK decompilations are cached in `~/.apkx/cache/` for faster repeated analysis:
```bash
# Clear entire cache
rm -rf ~/.apkx/cache/

# View cache contents
ls -la ~/.apkx/cache/
```

## Output Format 📝

### **JSON Output**
Results are saved in JSON format with:
- File paths relative to APK root
- Match context (surrounding code)
- Pattern categories
- Vulnerability details

### **HTML Output**
Interactive web-based reports with:
- Categorized findings
- Context toggling
- Pagination controls
- Clean, readable formatting

Example JSON output:
```json
{
  "api_keys": [
    "path/to/file.java: API_KEY_123 (Context: ...surrounding code...)"
  ],
  "urls": [
    "path/to/config.xml: https://api.example.com (Context: ...surrounding code...)"
  ],
  "TaskHijacking": [
    "Activity: com.example.VulnerableActivity (Launch Mode: singleTask, Exported: true)"
  ],
  "JanusVulnerability": [
    "V1 Signature: true, V2 Signature: true, V3 Signature: false - Medium Risk"
  ]
}
```

## Changelog 📝

### **v3.2.0** - iOS Support with ipatool Integration
- 🍎 **NEW**: Complete iOS app support with ipatool integration
  - **iOS App Download**: Download iOS apps by bundle ID using ipatool
  - **IPA Analysis**: Comprehensive static analysis of iOS app files
  - **iOS Security Analysis**: Keychain access, URL schemes, file protection analysis
  - **iOS Vulnerability Detection**: Jailbreak detection, transport security checks
  - **Web Interface**: New iOS download tab in web portal
- 🔧 **NEW**: Enhanced CLI with iOS-specific flags
  - `-bundle-id`: Download iOS apps by bundle ID
  - `-ipa`: Analyze existing IPA files
  - `-download-ios`: Enable iOS app downloading
- 📊 **NEW**: iOS-specific analysis patterns and vulnerability detection
- 🛠️ **NEW**: iOS dependency installation script (`scripts/install_ios_deps.sh`)
- 📱 **IMPROVED**: Web interface now supports both Android and iOS apps
- 🔍 **IMPROVED**: Enhanced pattern matching for iOS-specific security issues

### **v3.1.0** - Comprehensive Android Security Analysis
- 🛡️ **NEW**: Complete Android Manifest security analysis
  - **Exported Activities**: Detect activities accessible by other apps
  - **Exported Services**: Identify services vulnerable to hijacking
  - **Exported Broadcast Receivers**: Find intent-based vulnerabilities
  - **Exported Content Providers**: Detect data exposure risks
  - **WebViews**: Identify XSS and injection possibilities
  - **Deep Links**: Find custom URL scheme vulnerabilities
  - **File Provider Exports**: Detect file access vulnerabilities
  - **Custom URL Schemes**: Comprehensive scheme detection
- 🔄 **NEW**: Enhanced Task Hijacking detection with regex-based patterns
  - **taskAffinity**: Detect activities with custom task affinity
  - **SingleTask Launch Mode**: Identify singleTask launch mode vulnerabilities
- 🔒 **NEW**: Security vulnerability patterns integrated into main analyzer
  - **InsecureStorage**: SharedPreferences and SQLite security analysis
  - **CertificatePinning**: SSL/TLS security implementation checks
  - **DebugMode**: Production build security validation
- 📊 **IMPROVED**: Enhanced HTML reports with modern design
  - **Consolidated summary section** - No more redundant information
  - **Icon-based cards** with better visual hierarchy
  - **Improved color scheme** and typography
  - **Better responsive design** for all devices
- ⚡ **IMPROVED**: Performance optimizations
  - **1652+ patterns** loaded for comprehensive scanning
  - **Regex-based detection** for all security vulnerabilities
  - **Simplified output format** for better readability
- 🧹 **CLEANUP**: Removed deprecated analyzers and consolidated codebase

### **v3.0.0** - Advanced Web Portal & MITM Integration
- 🔧 **NEW**: MITM patching integration using apk-mitm for HTTPS inspection
- ⬇️ **NEW**: APK download functionality from multiple sources (APKPure, Google Play, F-Droid, Huawei AppGallery)
- ⚡ **NEW**: Asynchronous job processing with real-time status updates
- 🎯 **NEW**: Smart download system - serves patched APK when MITM enabled, original otherwise
- 📊 **NEW**: Package name and version extraction in HTML reports
- 🔄 **NEW**: Job management system with active job tracking
- 🗑️ **NEW**: Report deletion functionality
- 🎨 **IMPROVED**: Enhanced UI with tabbed interface for upload/download
- 🔧 **IMPROVED**: Better error handling and user feedback
- 🛠️ **IMPROVED**: Analysis now uses original APK while keeping patched version for download

### **v2.1.0** - Web Portal Release
- 🌐 **NEW**: Web portal interface with modern UI
- 🌙 **NEW**: Dark/Light mode toggle with persistent preferences
- 📤 **NEW**: Drag & drop APK upload functionality
- 🔔 **NEW**: Per-upload Discord webhook configuration
- 📊 **NEW**: Web-based report management and viewing
- 📱 **NEW**: Responsive design for mobile devices
- ⚡ **NEW**: Web server with configurable port and webhook defaults
- 🎨 **IMPROVED**: Enhanced UI/UX with smooth animations
- 🔧 **IMPROVED**: Better error handling and user feedback

### **v2.0.0** - Major Update
- ✨ Added HTML report generation with interactive visualization
- 🚨 Implemented Janus vulnerability detection
- 🔒 Added comprehensive security vulnerability checks
- 📄 Added pagination and context toggling in HTML reports
- 🎨 Improved readability with ANSI code stripping
- 🔧 Fixed task hijacking count accuracy
- 🗑️ Removed duplicate hardcoded credentials scanning
- 📊 Enhanced reporting with better categorization

### **v1.x.x** - Previous Versions
- Pattern-based analysis
- JSON output
- Basic caching system
- Task hijacking detection

## Contributing 🤝
We welcome contributions! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License 📄
MIT License - see [LICENSE](LICENSE) for details

---

🔧 Maintained by [h0tak88r](https://github.com/h0tak88r)
🔧 Maintained by [h0tak88r](https://github.com/h0tak88r)
