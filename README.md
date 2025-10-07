# apkX - Advanced APK & iOS Analysis Tool

![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![Version](https://img.shields.io/badge/version-v3.3.3-blue.svg)
![Docker](https://img.shields.io/badge/docker-supported-blue.svg)
![GitLab](https://img.shields.io/badge/gitlab-integration-green.svg)

A comprehensive security analysis tool for Android APK and iOS IPA files with advanced pattern matching, vulnerability detection, and cloud storage integration.

## 🚀 What's New in v3.3.3

- **✅ GitLab Storage Integration**: Zero-local storage mode with full GitLab backend
- **✅ Patched APK Support**: MITM-patched APKs are now properly uploaded and downloadable
- **✅ Delete Reports**: Full CRUD operations for reports in both local and GitLab storage
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
- **GitLab Storage**: Cloud-based storage with zero local dependencies
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

### Option 2: GitLab Storage Mode
```bash
curl -fsSL https://raw.githubusercontent.com/h0tak88r/apkX/main/apkx.sh | bash -s up:gitlab
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
- `GET /api/install/{reportID}` - Download patched APK
- `DELETE /api/report/delete/{reportID}` - Delete report
- `GET /api/jobs` - List analysis jobs

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
# GitLab Storage (Optional)
export USE_GITLAB_STORAGE=true
export GITLAB_PROJECT="your-username/your-repo"
export GITLAB_TOKEN="your-access-token"

# Local Storage
export APKX_UPLOAD_DIR="/path/to/uploads"
export APKX_REPORTS_DIR="/path/to/reports"
export APKX_DOWNLOAD_DIR="/path/to/downloads"
```

### GitLab Setup
1. Create a GitLab repository
2. Generate a Project Access Token with `api` and `write_repository` scopes
3. Set environment variables or use the setup script

## 🐳 Docker Support

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+

### Available Commands
```bash
# Start with local storage
./apkx.sh up

# Start with GitLab storage
./apkx.sh up:gitlab

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
- **Access Control**: Token-based authentication

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
