# APKx (APK Explorer)

APKx is a high-performance tool written in Go for scanning Android APK files to discover sensitive information like URIs, endpoints, and secrets. It's inspired by [APKLeaks](https://github.com/dwisiswant0/apkleaks) but reimplemented in Go with enhanced features and YAML pattern support.

## Features

- 🚀 High-performance scanning using Go's concurrency
- 📝 YAML-based pattern configuration
- 🎨 Colored terminal output for better readability
- 🔄 Automatic jadx download and setup
- 🎯 Multiple regex pattern support
- 📊 JSON output format support
- 🔍 Concurrent file scanning
- 🛠️ Easy to configure and extend

## Installation

### Prerequisites

- Go 1.19 or higher
- Java Runtime Environment (JRE) for jadx

### Installing from source

    go install github.com/h0tak88r/apkx@latest

## Usage

Basic usage:

    apkx -apk path/to/your.apk [options]

### Options

    -apk string       Path to APK file (required)
    -config string    Path to custom regex patterns config file
    -json            Output results in JSON format
    -output string   Write results to a file
    -verbose         Enable verbose output

### Example

    apkx -apk example.apk -output results.txt

## Configuration

APKx uses YAML configuration files for regex patterns. Default patterns are included, but you can provide your own:

    patterns:
      - name: "AWS Access Key"
        regex: "AKIA[0-9A-Z]{16}"
      - name: "Generic API Key"
        regex: "[aA][pP][iI]_?[kK][eE][yY].{0,20}['|\"][0-9a-zA-Z]{32,45}['|\"]"

## Output Example

    [+] Found AWS Access Key: AKIAXXXXXXXXXXXXXXXX in /path/to/file.java
    [+] Found Generic API Key: api_key="abcdef1234567890" in /path/to/config.xml

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (git checkout -b feature/amazing-feature)
3. Commit your changes (git commit -m 'Add some amazing feature')
4. Push to the branch (git push origin feature/amazing-feature)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [APKLeaks](https://github.com/dwisiswant0/apkleaks)
- Uses [jadx](https://github.com/skylot/jadx) for APK decompilation

## Disclaimer

This tool is for security research purposes only. Make sure you have permission to analyze any APK file before using this tool.