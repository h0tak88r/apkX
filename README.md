# APKX - Android APK Analysis Tool

APKX is a powerful static analysis tool for Android APK files that helps identify sensitive information, such as:
- API Keys
- OAuth Tokens
- Firebase URLs
- Email Addresses
- Endpoints and URLs
- And more...

## Features

- Fast APK decompilation using JADX
- Comprehensive pattern matching for sensitive information
- Clean and simple command-line interface
- JSON output for easy integration with other tools
- Customizable regex patterns

## Requirements

- Go 1.19 or later
- JADX (for APK decompilation)

## Installation

```bash
# Clone the repository
git clone https://github.com/h0tak88r/apkx.git
cd apkx

# Build the project
go build -o apkx cmd/apkx/main.go
```

## Usage

```bash
# Basic usage
./apkx -f app.apk

# Specify custom output file
./apkx -f app.apk -o results.json

# Use custom patterns file
./apkx -f app.apk -r patterns.yaml
```

### Command Line Flags

- `-f` : APK file to analyze (required)
- `-o` : JSON output file (default: apkx-results.json)
- `-r` : Regex patterns file (default: config/regexes.yaml)

## Example Output

```
=== APK Analysis Summary ===
Found sensitive information in 6 categories:
  • API Keys: 2 findings
  • OAuth Tokens: 1 findings
  • Firebase URLs: 1 findings
  • Email Addresses: 3 findings
  • Endpoints: 12 findings
  • URLs: 46 findings

Results saved to: /path/to/apkx-results.json
```

## Custom Patterns

You can create your own patterns file in YAML format:

```yaml
patterns:
  - name: "API Keys"
    regex: "api[_-]?key[_-]?([0-9a-zA-Z]{32,})"
  - name: "OAuth Tokens"
    regex: "access_token[_-]?([0-9a-zA-Z]{32,})"
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.