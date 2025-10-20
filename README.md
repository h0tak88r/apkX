# apkX - Advanced APK & iOS Analysis Tool

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Version](https://img.shields.io/badge/version-v3.3.3-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![R2](https://img.shields.io/badge/cloudflare-r2-orange.svg)

A comprehensive security analysis tool for Android APK and iOS IPA files with advanced pattern matching, vulnerability detection, and cloud storage integration.

## 🚀 What's New in v3.3.3

- **✅ Cloudflare R2 Storage Integration**: Zero-local storage mode with full R2 backend
- **✅ Patched APK Support**: MITM-patched APKs are now properly uploaded and downloadable
- **✅ Delete Reports**: Full CRUD operations for reports in both local and R2 storage
- **✅ Enhanced UI**: Modern responsive design with sidebar navigation
- **✅ iOS Analysis**: Comprehensive iOS app analysis with binary plist support
- **✅ Docker Support**: Complete Docker containerization with all dependencies

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

## 🚀 Quick Start

### Option 1: One-Line Installation (Recommended)
```bash
curl -fsSL https://raw.githubusercontent.com/h0tak88r/apkX/main/apkx.sh | bash -s up
```

### Option 2: Cloudflare R2 Storage Mode
```bash
curl -fsSL https://raw.githubusercontent.com/h0tak88r/apkX/main/apkx.sh | bash -s up:r2
```

### Option 3: Manual Docker Setup
```bash
git clone https://github.com/h0tak88r/apkX.git
cd apkX
docker-compose up -d
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
```bash
# R2 Storage (Optional)
export USE_R2_STORAGE=true
export R2_BUCKET_NAME="your-bucket-name"
export R2_ACCOUNT_ID="your-account-id"
export R2_ACCESS_KEY_ID="your-access-key-id"
export R2_SECRET_KEY="your-secret-key"
export R2_PUBLIC_URL="https://your-custom-domain.com"

# Local Storage
export APKX_UPLOAD_DIR="/path/to/uploads"
export APKX_REPORTS_DIR="/path/to/reports"
export APKX_DOWNLOAD_DIR="/path/to/downloads"

# iOS Authentication (Optional - for manual authentication)
export IPATOOL_KEYCHAIN_PASSPHRASE="your-keychain-passphrase"
export IPATOOL_EMAIL="your-apple-id@example.com"

# Authentication (Optional)
export APKX_AUTH_ENABLED=true
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

### iOS Downloads Setup (Optional)
For iOS app downloads, configure Apple ID credentials and authenticate manually:

**Required Environment Variables:**
```bash
export IPATOOL_KEYCHAIN_PASSPHRASE="your-keychain-passphrase"
export IPATOOL_EMAIL="your-apple-id@example.com"
```

**Manual Authentication:**
1. Start the Docker container
2. Connect to the container: `docker exec -it apkx-web bash`
3. Authenticate ipatool: `ipatool auth login --email your-apple-id@example.com`
4. Follow the interactive prompts for password and 2FA

**Note**: iOS downloads require a valid Apple ID with purchased apps. Authentication must be done manually for security reasons.

### Authentication Setup
By default, authentication is **disabled** and the web interface is publicly accessible. To enable authentication:

1. **Enable Authentication**: Set `APKX_AUTH_ENABLED=true`
2. **Set Credentials**: Configure `APKX_AUTH_USERNAME` and `APKX_AUTH_PASSWORD`
3. **Session Security**: Optionally set `APKX_SESSION_SECRET` for session security

**Default Credentials** (when authentication is enabled but credentials not provided):
- Username: `admin`
- Password: `admin123`

⚠️ **Important**: Change the default password in production environments!

## 🐳 Docker Support

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+

### Available Commands
```bash
# Start with local storage
./apkx.sh up

# Start with R2 storage
./apkx.sh up:r2

# Check dependencies
./apkx.sh deps

# View logs
./apkx.sh logs

# Stop services
./apkx.sh down
```

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
