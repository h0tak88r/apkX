# Changelog

## [v3.3.0] - 2025-09-20
### Added
- 🐳 **Docker Support**: Complete Docker containerization with one-command setup
- 🎨 **Enhanced UI/UX**: Modern sidebar design with responsive navigation
- 📱 **Mobile-Friendly**: Collapsible sidebar and responsive design
- 🔧 **iOS Analysis Improvements**: Binary plist support and enhanced pattern matching
- 📄 **Plist Download**: Direct download of Info.plist files from iOS reports
- 🛠️ **Health Checks**: Container health monitoring and auto-restart
- 📦 **All Dependencies**: JADX, apkeep, ipatool, apk-mitm pre-installed

### Changed
- 🎯 **Word Wrapping**: Long code lines now wrap properly on all screen sizes
- 🚀 **Upload Feedback**: Clear success alerts when files are uploaded
- 🔍 **Pattern Matching**: iOS-specific regex patterns for better detection
- 📁 **File Filtering**: Skips static iOS directories for faster analysis
- 🐳 **Volume Mounting**: Fixed Docker volume mounting for reports directory

### Fixed
- 🐛 **Docker Volume Issues**: Reports directory now works correctly in containers
- 🐛 **File Validation**: Prevents processing of empty or corrupted files
- 🐛 **Error Handling**: More descriptive error messages
- 🐛 **Navigation**: Sidebar navigation now works properly on all screen sizes

### Technical
- 📦 **Docker Image**: Optimized build with better caching
- 🔧 **Dependencies**: Updated to latest stable versions
- 📋 **Documentation**: Comprehensive Docker setup guide
- 🧪 **Testing**: Verified cross-platform compatibility

## [v2.0.0] - 2025-09-07
## [v3.2.0] - 2025-09-15
### Added
- XAPK auto-conversion for uploads and downloads
- Metadata flag `mitm_failed` when patching fails

### Changed
- MITM patching no longer aborts jobs on failure; analysis proceeds
- HTML report: always show full context; removed redundant toggle
- Sidebar menu toggle behavior fixed on large screens

### Notes
- See RELEASE_NOTES_v3.2.0.md for details

### Added
- 🌐 **HTML Report Generation**: Beautiful interactive web-based reports
- 🚨 **Janus Vulnerability Detection**: APK signature scheme analysis (V1/V2/V3)
- 🔒 **Comprehensive Security Checks**:
  - Insecure storage analysis (SharedPreferences, SQLite)
  - Certificate pinning detection
  - Debug mode validation
- 📄 **Interactive Features**:
  - Pagination for large result sets
  - Context toggling in HTML reports
  - Clean, readable formatting
- 🎨 **Enhanced UI**:
  - ANSI code stripping for clean HTML output
  - Responsive design for mobile and desktop
  - Improved vulnerability categorization

### Changed
- 🔧 **Fixed Task Hijacking Count**: Now correctly shows single finding instead of multiple
- 🗑️ **Removed Duplicate Scanning**: Eliminated hardcoded credentials from InsecureStorage analyzer
- 📊 **Improved Reporting**: Better categorization and context display
- 🎯 **Enhanced Accuracy**: More precise vulnerability detection and counting

### Technical Improvements
- Added `SetAPKPath` method to analyzer interface
- Improved context parsing and formatting
- Enhanced HTML template with JavaScript functionality
- Better error handling and validation

## [v1.4.0] - 2024-03-24
### Added
- New task hijacking vulnerability scanner
- Ability to scan AndroidManifest.xml for singleTask launch mode
- New `-task-hijacking` flag for focused vulnerability scanning
- Enhanced terminal output with better formatting and colors
- Detailed vulnerability reports with severity levels

### Changed
- Improved output formatting with box-drawing characters
- Better error handling for manifest parsing
- Enhanced worker output messages

## [v1.3.0] - Previous version
... 