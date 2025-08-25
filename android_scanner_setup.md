# Android Security Scanner - Setup and Usage Guide

## Prerequisites

### Required Tools
1. **ADB (Android Debug Bridge)** - Install Android SDK Platform-Tools
2. **Connected Android Device** - Either physical device or emulator
3. **APK Analysis Tools** (optional for enhanced scanning):
   - `apktool` - For APK decompilation
   - `jadx` - For Java source code decompilation
   - `aapt`/`aapt2` - For APK information extraction

### Device Setup
- Enable Developer Options on your Android device
- Enable USB Debugging
- Connect device via USB or ensure emulator is running
- For enhanced features: Root access (optional but recommended)

## Basic Usage

### 1. Make the script executable
```bash
chmod +x android_app_security_scanner.sh
```

### 2. Basic command structure
```bash
./android_app_security_scanner.sh [options]
```

## Usage Examples

### Analyze a specific APK file
```bash
./android_app_security_scanner.sh --apk /path/to/app.apk
```

### Analyze an installed app by package name
```bash
./android_app_security_scanner.sh --package com.example.app
```

### Scan all user-installed apps
```bash
./android_app_security_scanner.sh --all-user
```

### Deep scan with JSON output
```bash
./android_app_security_scanner.sh --apk app.apk --deep --json --out /path/to/reports/
```

### Skip certain analysis types
```bash
# Skip dynamic analysis (device-side checks)
./android_app_security_scanner.sh --apk app.apk --no-dynamic

# Skip static analysis
./android_app_security_scanner.sh --package com.example.app --no-static

# Skip network monitoring
./android_app_security_scanner.sh --apk app.apk --no-network
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `--apk <path>` | Path to the APK file to analyze |
| `--package <pkg>` | Package name of installed app to analyze |
| `--all-user` | Analyze all installed third-party applications |
| `--out <dir>` | Directory to save reports (default: current directory) |
| `--timeout <sec>` | Timeout for dynamic analysis (default: 60) |
| `--net-timeout <sec>` | Timeout for network monitoring (default: 30) |
| `--deep` | Enable deep scanning (slower but more thorough) |
| `--no-dynamic` | Skip dynamic and device-side checks |
| `--no-static` | Skip static analysis |
| `--no-network` | Skip network traffic monitoring |
| `--json` | Generate machine-readable JSON report |
| `--help` | Show help message |

## What the Scanner Checks

### Security Areas Covered
- **Static Analysis**: Code vulnerabilities, hardcoded secrets, permissions
- **Dynamic Analysis**: Runtime behavior, file system access, services
- **Network Security**: Traffic monitoring, SSL/TLS issues, certificate pinning
- **Privacy Analysis**: Data collection, location access, PII storage
- **OWASP MASVS Compliance**: Mobile Application Security Verification Standard
- **Malware Detection**: Suspicious patterns and behaviors

### Key Findings Include
- Hardcoded API keys, passwords, and encryption keys
- Insecure network communications
- Dangerous permissions
- SQL injection vulnerabilities
- Weak cryptographic implementations
- Debug code in production
- WebView security issues
- Intent security problems
- Third-party library vulnerabilities

## Example Workflow

### Complete Security Assessment
```bash
# 1. Analyze APK file with deep scanning
./android_app_security_scanner.sh \
  --apk /path/to/suspicious_app.apk \
  --deep \
  --json \
  --out ./security_reports/ \
  --timeout 120

# 2. Check installed app with network monitoring
./android_app_security_scanner.sh \
  --package com.company.app \
  --net-timeout 60 \
  --out ./reports/

# 3. Quick scan of all user apps
./android_app_security_scanner.sh \
  --all-user \
  --no-network \
  --out ./bulk_scan/
```

## Output Files

The scanner generates detailed reports:

### Markdown Report
- **File**: `enhanced_security_report_[target]_[timestamp].md`
- **Contains**: Executive summary, detailed findings, recommendations
- **Format**: Human-readable with severity levels and OWASP mappings

### JSON Report (if --json flag used)
- **File**: `enhanced_security_report_[target]_[timestamp].json`
- **Contains**: Machine-readable structured data
- **Use**: For integration with other tools or automated processing

## Security Score and Risk Assessment

The scanner provides:
- **Risk Score**: 0-100 based on findings severity
- **Risk Level**: LOW, MEDIUM, HIGH, CRITICAL
- **Security Grade**: A, B, C, D, F
- **OWASP MASVS Compliance**: Mapping to security standards

## Important Notes

### Legal and Ethical Usage
⚠️ **AUTHORIZED DEFENSIVE TESTING ONLY**
- Only use on applications you own or have explicit permission to test
- This tool is for defensive security assessment purposes
- Respect privacy and legal boundaries

### Root Access Benefits
With root access, the scanner can perform:
- Enhanced file system analysis
- Deeper permission checks
- Advanced network monitoring
- More thorough security assessments

### Troubleshooting

**Device not detected:**
```bash
adb devices  # Check if device is connected
adb kill-server && adb start-server  # Restart ADB
```

**Permission errors:**
- Ensure USB debugging is enabled
- Check device authorization dialog
- Try different USB cable/port

**Missing tools:**
```bash
# Install Android SDK tools
# Download from: https://developer.android.com/studio/releases/platform-tools

# Install optional tools for enhanced scanning:
# apktool: https://ibotpeaches.github.io/Apktool/
# jadx: https://github.com/skylot/jadx
```

## Integration with Security Workflows

This scanner integrates well with:
- CI/CD pipelines for app security testing
- Penetration testing workflows
- Security compliance audits
- Incident response investigations
- Mobile app security assessments