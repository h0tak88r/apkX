# apkX - Advanced APK & iOS Analysis Tool

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Version](https://img.shields.io/badge/version-v4.0.0-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![R2](https://img.shields.io/badge/cloudflare-r2-orange.svg)

A comprehensive security analysis tool for Android APK and iOS IPA files with advanced pattern matching, vulnerability detection, and cloud storage integration.

## 🚀 What's New in v4.0.0

- **✅ Enhanced Installation Script**: Automatic dependency checking and installation
- **✅ Configurable Docker Setup**: All paths and ports now configurable via environment variables
- **✅ Cross-Platform Support**: Improved installation on Linux, macOS, and Windows
- **✅ Security Improvements**: Environment variable usage instead of hardcoded credentials
- **✅ Better Error Handling**: Enhanced user feedback and error messages
- **✅ Dependency Management**: Automatic installation of required system packages

## ✨ Features

### 🔍 **Advanced Analysis**
- **Pattern Matching**: 1600+ security patterns for sensitive data detection
- **Vulnerability Detection**: Built-in Janus vulnerability detection
- **Static Analysis**: Comprehensive code analysis for both Android and iOS
- **MITM Patching**: Automatic APK patching for network traffic analysis

### 📱 **Multi-Platform Support**
- **Android APK**: Full decompilation and analysis
- **iOS IPA**: Binary plist parsing and Swift/Objective-C analysis
- **XAPK Support**: Extended Android package format

### ☁️ **Storage Options**
- **Local Storage**: Traditional file-based storage
- **Cloudflare R2 Storage**: Cloud-based storage with zero local dependencies
- **Auto-Sync**: Automatic synchronization between storage backends

### 🎨 **Modern UI**
- **Responsive Design**: Works on desktop and mobile
- **Real-time Updates**: Live job status and progress tracking
- **Interactive Reports**: Rich HTML reports with navigation
- **Download Support**: Direct download of patched APKs and manifests

## 🚀 Installation & Quick Start

### Option 1: Docker (Recommended)
The easiest way to run apkX is with Docker, which includes all dependencies:

```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkX.git
cd apkX

# Set your Apple ID credentials (for iOS downloads)
export IPATOOL_EMAIL="your-email@example.com"
export IPATOOL_PASSWORD="your-app-specific-password"
export IPATOOL_KEYCHAIN_PASSPHRASE="your-passphrase"

# Start with Docker Compose
docker-compose up --build
```

**Access the web interface at:** `http://localhost:9090`

### Option 2: Local Installation
For local installation, you need the following tools installed:

#### Required Tools
- **Go 1.21+** - [Install Go](https://golang.org/dl/)
- **Java 17+** - [Install Java](https://openjdk.org/)
- **Node.js 18+** - [Install Node.js](https://nodejs.org/)
- **apkeep** - [Install apkeep](https://github.com/EFForg/apkeep)
- **ipatool** - [Install ipatool](https://github.com/majd/ipatool)
- **apk-mitm** - [Install apk-mitm](https://github.com/shroudedcode/apk-mitm)

#### Build and Run
```bash
# Clone and build
git clone https://github.com/h0tak88r/apkX.git
cd apkX
go mod download
go build -o apkx-web ./cmd/server/main.go

# Set environment variables
export IPATOOL_EMAIL="your-email@example.com"
export IPATOOL_PASSWORD="your-app-specific-password"
export IPATOOL_KEYCHAIN_PASSPHRASE="your-passphrase"

# Run the server
./apkx-web -addr :9090 -mitm
```

## 📖 Usage

### Web Interface
1. Open your browser to `http://localhost:9090`
2. Upload APK/IPA files or download from package managers
3. View analysis reports and download patched APKs
4. Delete reports using the delete button

### API Endpoints
- `POST /upload` - Upload APK/IPA files
- `POST /download` - Download APKs from package managers
- `POST /download-ios` - Download iOS apps from App Store
- `GET /api/install/{reportID}` - Download patched APK
- `DELETE /api/report/delete/{reportID}` - Delete report
- `GET /api/jobs` - List analysis jobs

### iOS App Download
For iOS apps, you can use the `download-ios` endpoint:

```bash
curl -X POST "http://localhost:9090/download-ios" \
  -d "bundle_id=com.example.app&ios_version=1.0.0"
```

**Note**: iOS downloads require Apple ID authentication. Before using iOS downloads, you need to authenticate `ipatool` with your Apple ID:

```bash
# Run this command interactively to authenticate
docker exec -it apkx-web ipatool auth login
```

This is a one-time setup that stores your credentials securely in the container's keychain.

### Command Line
```bash
# Analyze APK
./apkx-web -apk app.apk -output ./reports

# Analyze with MITM patching
./apkx-web -apk app.apk -mitm -output ./reports
```

## 🔧 Configuration

### Environment Variables

#### Required for iOS Downloads
```bash
export IPATOOL_EMAIL="your-apple-id@example.com"
export IPATOOL_PASSWORD="your-app-specific-password"
export IPATOOL_KEYCHAIN_PASSPHRASE="your-keychain-passphrase"
```

#### Optional Configuration
```bash
# Server Configuration
export PORT="9090"                    # Web server port (default: 9090)

# Storage Paths (Docker)
export APKX_UPLOAD_DIR="/app/web-data/uploads"
export APKX_REPORTS_DIR="/app/web-data/reports"
export APKX_DOWNLOAD_DIR="/app/web-data/downloads"
export APKX_PATTERNS_PATH="/app/config/regexes.yaml"

# Cloudflare R2 Storage (Optional)
export USE_R2_STORAGE="true"
export R2_BUCKET_NAME="your-bucket-name"
export R2_ACCOUNT_ID="your-account-id"
export R2_ACCESS_KEY_ID="your-access-key-id"
export R2_SECRET_KEY="your-secret-key"
export R2_PUBLIC_URL="https://your-custom-domain.com"

# Authentication (Optional)
export APKX_AUTH_ENABLED="true"
export APKX_AUTH_USERNAME="your-username"
export APKX_AUTH_PASSWORD="your-secure-password"
export APKX_SESSION_SECRET="your-session-secret"
```

### Cloudflare R2 Setup
1. Create a Cloudflare R2 bucket
2. Generate R2 API tokens with read/write permissions
3. Set environment variables or use the setup script

**Required Environment Variables:**
```bash
export USE_R2_STORAGE=true
export R2_BUCKET_NAME="your-bucket-name"
export R2_ACCOUNT_ID="your-account-id"
export R2_ACCESS_KEY_ID="your-access-key-id"
export R2_SECRET_KEY="your-secret-key"
export R2_PUBLIC_URL="https://your-custom-domain.com"  # Optional
```

### iOS Downloads Setup (Automatic Authentication)
For automatic iOS app downloads, configure Apple ID credentials with an App-Specific Password:

**Required Environment Variables:**
```bash
export IPATOOL_KEYCHAIN_PASSPHRASE="your-keychain-passphrase"
export IPATOOL_EMAIL="your-apple-id@example.com"
export IPATOOL_PASSWORD="your-app-specific-password"
```

**App-Specific Password Setup:**
1. Go to [Apple ID Account Settings](https://appleid.apple.com/)
2. Sign in with your Apple ID
3. In the "Security" section, click "Generate Password" under "App-Specific Passwords"
4. Enter a label (e.g., "apkX iOS Downloads")
5. Copy the generated password and use it as `IPATOOL_PASSWORD`

**Note**: iOS downloads require a valid Apple ID with purchased apps. Authentication is handled automatically using the App-Specific Password.

### Authentication Setup
By default, authentication is **disabled** and the web interface is publicly accessible. To enable authentication:

1. **Enable Authentication**: Set `APKX_AUTH_ENABLED=true`
2. **Set Credentials**: Configure `APKX_AUTH_USERNAME` and `APKX_AUTH_PASSWORD`
3. **Session Security**: Optionally set `APKX_SESSION_SECRET` for session security

**Default Credentials** (when authentication is enabled but credentials not provided):
- Username: `admin`
- Password: `admin123`

⚠️ **Important**: Change the default password in production environments!

## 🐳 Docker Commands

```bash
# Start the application
docker-compose up --build

# Start in background
docker-compose up -d --build

# View logs
docker-compose logs -f

# Stop the application
docker-compose down

# Rebuild and start
docker-compose up --build --force-recreate
```

## 🔧 Troubleshooting

### Common Issues

#### Missing Dependencies
If you get "command not found" errors, install the missing tools:
- **apkeep**: [Installation Guide](https://github.com/EFForg/apkeep#installation)
- **ipatool**: [Installation Guide](https://github.com/majd/ipatool#installation)
- **Java**: [Installation Guide](https://openjdk.org/install/)
- **Node.js**: [Installation Guide](https://nodejs.org/en/download/)

#### iOS Download Authentication
```bash
# Authenticate ipatool manually
ipatool auth login --email your-email@example.com

# Or set environment variables
export IPATOOL_EMAIL="your-email@example.com"
export IPATOOL_PASSWORD="your-app-specific-password"
export IPATOOL_KEYCHAIN_PASSPHRASE="your-passphrase"
```

#### Docker Issues
```bash
# Check if config file is mounted
docker exec -it apkx-web ls -la /app/config/

# Recreate volumes
docker-compose down -v
docker-compose up --build

# Check logs
docker-compose logs -f
```

### Getting Help
- Check the logs: `docker-compose logs -f`
- Verify dependencies: `docker exec -it apkx-web which apkeep ipatool jadx`
- Test iOS auth: `docker exec -it apkx-web ipatool auth login`

## 📊 Analysis Features

### Android APK Analysis
- **Decompilation**: JADX-based APK decompilation
- **Manifest Analysis**: Permission and component analysis
- **Code Analysis**: Java/Kotlin source code scanning
- **Vulnerability Detection**: Security pattern matching
- **MITM Patching**: Network traffic interception setup

### iOS IPA Analysis
- **Binary Plist Parsing**: Automatic conversion of binary plists
- **Swift/Objective-C Analysis**: Source code pattern matching
- **Bundle Analysis**: App metadata and configuration
- **Security Scanning**: iOS-specific vulnerability patterns

### Pattern Categories
- **API Keys**: AWS, Google, Firebase, etc.
- **Authentication**: OAuth, JWT, session tokens
- **Database**: Connection strings, credentials
- **Payment**: Stripe, PayPal, payment tokens
- **Social**: Facebook, Twitter, social media keys
- **Analytics**: Tracking and analytics services

## 🔒 Security Features

- **Sensitive Data Detection**: 1600+ patterns for secrets and keys
- **Vulnerability Scanning**: Built-in security checks
- **MITM Support**: APK patching for network analysis
- **Report Encryption**: Secure report generation
- **Access Control**: Simple HTTP authentication with session management

## 📁 Project Structure

```
apkX/
├── cmd/
│   ├── apkx/          # CLI tool
│   └── server/        # Web server
├── internal/
│   ├── analyzer/      # Analysis engines
│   ├── decompiler/    # APK decompilation
│   ├── downloader/    # Package downloaders
│   ├── reporter/      # Report generation
│   └── storage/       # Storage backends
├── config/
│   └── regexes.yaml   # Security patterns
├── docker-compose.yml # Docker configuration
├── Dockerfile         # Container definition
└── apkx.sh           # Management script
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [JADX](https://github.com/skylot/jadx) - APK decompilation
- [apkeep](https://github.com/EFForg/apkeep) - APK downloading
- [ipatool](https://github.com/majd/ipatool) - iOS app downloading
- [apk-mitm](https://github.com/shroudedcode/apk-mitm) - APK patching

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/h0tak88r/apkX/issues)
- **Discussions**: [GitHub Discussions](https://github.com/h0tak88r/apkX/discussions)
- **Documentation**: [Wiki](https://github.com/h0tak88r/apkX/wiki)

---

**Made with ❤️ for the security community**
