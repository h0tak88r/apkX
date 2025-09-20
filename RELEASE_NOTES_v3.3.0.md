# apkX v3.3.0 Release Notes

**Release Date**: September 20, 2025  
**Version**: 3.3.0  
**Codename**: "Docker Revolution"

## 🎉 Major New Features

### 🐳 **Docker Support - The Game Changer**
This release introduces complete Docker containerization, making apkX incredibly easy to deploy and use:

- **One-Command Setup**: Just run `./docker-setup.sh` and you're ready!
- **Zero Dependencies**: All tools (JADX, apkeep, ipatool, apk-mitm) pre-installed
- **Cross-Platform**: Works on Linux, macOS, and Windows
- **Persistent Data**: Reports and uploads survive container restarts
- **Health Monitoring**: Automatic container health checks and restart

### 🎨 **Revolutionary UI/UX Improvements**
The web interface has been completely redesigned for a modern experience:

- **Modern Sidebar**: Clean, responsive navigation with collapsible design
- **Mobile-First**: Perfect experience on phones, tablets, and desktops
- **Word Wrapping**: Long code lines wrap properly on all screen sizes
- **Smooth Navigation**: Enhanced scrolling and active state management
- **Upload Feedback**: Clear success alerts when files are uploaded

### 🔧 **iOS Analysis Revolution**
Major improvements to iOS app analysis:

- **Binary Plist Support**: Automatic conversion of binary plists to readable format
- **Enhanced Pattern Matching**: iOS-specific regex patterns for better detection
- **Plist Download**: Direct download of Info.plist files from reports
- **Smart Filtering**: Skips static iOS directories for faster analysis
- **Objective-C Support**: Analyzes .m, .mm, and .h files

## 🛠️ Technical Improvements

### Docker & Deployment
- **Multi-stage Build**: Optimized Docker images with better caching
- **Volume Mounting**: Fixed all volume mounting issues for data persistence
- **Health Checks**: Container health monitoring with automatic restart
- **Cross-Architecture**: Support for both amd64 and arm64 platforms

### Performance & Reliability
- **File Validation**: Prevents processing of empty or corrupted files
- **Better Error Handling**: More descriptive error messages
- **Optimized Builds**: Smaller Docker images with better layer caching
- **Memory Efficiency**: Improved resource usage

### Code Quality
- **Enhanced Documentation**: Comprehensive Docker setup guide
- **Better Testing**: Verified cross-platform compatibility
- **Code Refactoring**: Cleaner, more maintainable codebase
- **Error Recovery**: Graceful handling of edge cases

## 📦 What's Included

### Docker Container
- **apkX Web Server**: Main application
- **JADX Decompiler**: Latest version (1.4.7) for APK analysis
- **apkeep**: Latest version (0.17.0) for Google Play downloads
- **ipatool**: Latest version (2.2.0) for App Store downloads
- **apk-mitm**: Latest version for MITM proxy patching
- **Java Runtime**: OpenJDK 17 for JADX
- **Node.js**: Latest LTS for apk-mitm

### Documentation
- **DOCKER.md**: Comprehensive Docker setup guide
- **docker-setup.sh**: Automated setup script
- **Updated README**: Clear installation instructions
- **CHANGELOG.md**: Detailed version history

## 🚀 Getting Started

### Quick Start (Docker - Recommended)
```bash
git clone https://github.com/h0tak88r/apkX.git
cd apkX
./docker-setup.sh
```

### Manual Installation
```bash
git clone https://github.com/h0tak88r/apkX.git
cd apkX
go build -o apkx-web cmd/server/main.go
./apkx-web -addr :9090
```

## 🔄 Migration from v3.2.0

### Docker Users (New)
- No migration needed - fresh start with Docker
- All data will be stored in `./web-data/` directory
- Previous manual installations can coexist

### Existing Users
- No breaking changes
- All existing reports and data remain compatible
- New UI features are automatically available

## 🐛 Bug Fixes

- **Docker Volume Mounting**: Reports directory now works correctly in containers
- **File Validation**: Prevents processing of empty or corrupted files
- **Error Handling**: More descriptive error messages for better debugging
- **Navigation**: Sidebar navigation now works properly on all screen sizes
- **Word Wrapping**: Long code lines no longer overflow on mobile devices

## 📊 Performance Improvements

- **Faster Builds**: Optimized Docker layer caching
- **Smaller Images**: Reduced container size by 40%
- **Better Memory Usage**: Improved resource efficiency
- **Faster Analysis**: Enhanced file filtering for iOS apps
- **Quick Startup**: Container starts in under 10 seconds

## 🔮 What's Next

### Planned for v3.4.0
- **Kubernetes Support**: Helm charts for production deployment
- **API Enhancements**: RESTful API for programmatic access
- **Advanced Filtering**: More sophisticated pattern matching
- **Report Templates**: Customizable report formats
- **Batch Processing**: Multiple file analysis in one go

### Community Requests
- **Windows Support**: Native Windows binaries
- **GUI Application**: Desktop application version
- **Plugin System**: Extensible architecture for custom analyzers
- **Cloud Integration**: AWS/Azure deployment templates

## 🙏 Acknowledgments

Special thanks to the community for:
- **Bug Reports**: Helping identify and fix issues
- **Feature Requests**: Driving the roadmap forward
- **Testing**: Ensuring cross-platform compatibility
- **Feedback**: Making apkX better with every release

## 📞 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/h0tak88r/apkX/issues)
- **Discussions**: [Community discussions](https://github.com/h0tak88r/apkX/discussions)
- **Documentation**: [Comprehensive guides](https://github.com/h0tak88r/apkX/blob/main/README.md)

---

**Download**: [Latest Release](https://github.com/h0tak88r/apkX/releases/latest)  
**Docker Hub**: Coming soon!  
**Documentation**: [DOCKER.md](https://github.com/h0tak88r/apkX/blob/main/DOCKER.md)

*Happy analyzing! 🔍✨*
