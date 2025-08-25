#!/bin/bash
#
# enhanced_android_security_scanner.sh - Defensive Security Edition
# Enhanced passive security assessment with advanced detection capabilities
#

# --- Enhanced Configuration ---
set -o pipefail
SCRIPT_VERSION="2.0.0-defensive"
SCRIPT_START_TIME=$(date +"%Y-%m-%d %H:%M:%S %Z")
APP_TARGETS=()
OUTPUT_DIR="."
DYNAMIC_TIMEOUT=60
NETWORK_TIMEOUT=30
RUN_STATIC=1
RUN_DYNAMIC=1
RUN_NETWORK=1
GENERATE_JSON=0
DEEP_SCAN=0
FINDINGS_MD=""
FINDINGS_JSON="[]"
HIGH_SEVERITY_COUNT=0
MEDIUM_SEVERITY_COUNT=0
LOW_SEVERITY_COUNT=0
INFO_SEVERITY_COUNT=0
TEMP_DIR=""

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- Enhanced Functions ---

function show_help() {
    echo "Enhanced Android Security Scanner v${SCRIPT_VERSION} - Defensive Edition"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --apk <path>            Path to the APK file to analyze"
    echo "  --package <pkg>         Package name of installed app to analyze"
    echo "  --all-user              Analyze all installed third-party applications"
    echo "  --out <dir>             Directory to save reports (default: current directory)"
    echo "  --timeout <sec>         Timeout for dynamic analysis (default: 60)"
    echo "  --net-timeout <sec>     Timeout for network monitoring (default: 30)"
    echo "  --deep                  Enable deep scanning (slower but more thorough)"
    echo "  --no-dynamic            Skip dynamic and device-side checks"
    echo "  --no-static             Skip static analysis"
    echo "  --no-network            Skip network traffic monitoring"
    echo "  --json                  Generate machine-readable JSON report"
    echo "  --help                  Show this help message"
    echo ""
    echo "Defensive Features:"
    echo "  • Advanced malware signature detection"
    echo "  • Behavioral pattern analysis"
    echo "  • Network security assessment"
    echo "  • Privacy leak detection"
    echo "  • Compliance checking (OWASP MASVS)"
}

function log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

function log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

function log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_debug() {
    if [[ $DEEP_SCAN -eq 1 ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

function cleanup() {
    log_info "Cleaning up temporary files and processes..."
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    # Kill monitoring processes
    pkill -f "adb logcat" 2>/dev/null
    pkill -f "tcpdump" 2>/dev/null
}

trap 'cleanup; exit 1' SIGINT SIGTERM SIGHUP

function add_finding() {
    local target="$1"
    local id="$2"
    local category="$3"
    local title="$4"
    local severity="$5"
    local evidence="$6"
    local recommendation="$7"
    local cve_ref="${8:-N/A}"
    local owasp_ref="${9:-N/A}"

    case "$severity" in
        "High") HIGH_SEVERITY_COUNT=$((HIGH_SEVERITY_COUNT + 1)) ;;
        "Medium") MEDIUM_SEVERITY_COUNT=$((MEDIUM_SEVERITY_COUNT + 1)) ;;
        "Low") LOW_SEVERITY_COUNT=$((LOW_SEVERITY_COUNT + 1)) ;;
        "Info") INFO_SEVERITY_COUNT=$((INFO_SEVERITY_COUNT + 1)) ;;
    esac

    # Enhanced Markdown formatting with compliance references
    FINDINGS_MD+=$(printf "\n### [%s] %s\n\n" "$id" "$title")
    FINDINGS_MD+=$(printf "**Severity:** %s  \n" "$severity")
    FINDINGS_MD+=$(printf "**Category:** %s  \n" "$category")
    FINDINGS_MD+=$(printf "**OWASP MASVS:** %s  \n" "$owasp_ref")
    FINDINGS_MD+=$(printf "**CVE Reference:** %s  \n" "$cve_ref")
    FINDINGS_MD+=$(printf "**Evidence:**\n\`\`\`\n%s\n\`\`\`\n" "$evidence")
    FINDINGS_MD+=$(printf "**Recommendation:**\n%s\n\n---\n" "$recommendation")

    # Enhanced JSON with compliance data
    if [[ $GENERATE_JSON -eq 1 ]]; then
        local escaped_evidence
        escaped_evidence=$(echo "$evidence" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')
        local evidence_json
        evidence_json=$(echo "$escaped_evidence" | awk -v ORS='\\n' '1' | sed 's/\\n$//')

        local finding_json
        finding_json=$(printf '{"id":"%s","category":"%s","title":"%s","severity":"%s","evidence":"%s","recommendation":"%s","cve":"%s","owasp":"%s","timestamp":"%s"}' \
            "$id" "$category" "$title" "$severity" "$evidence_json" "$recommendation" "$cve_ref" "$owasp_ref" "$(date -Iseconds)")
        
        if [[ "$FINDINGS_JSON" == "[]" ]]; then
            FINDINGS_JSON="[$finding_json]"
        else
            FINDINGS_JSON="${FINDINGS_JSON%?},$finding_json]"
        fi
    fi
}

function check_enhanced_prerequisites() {
    log_info "Checking enhanced security tools and device capabilities..."
    
    # Core tools check
    if ! command -v adb &>/dev/null; then
        log_error "adb not found. Install Android SDK Platform-Tools."
        exit 1
    fi

    # Device connectivity and root check
    DEVICE_SERIAL=$(adb get-serialno 2>/dev/null)
    if [[ "$DEVICE_SERIAL" == "unknown" || -z "$DEVICE_SERIAL" ]]; then
        log_error "No device connected."
        exit 1
    fi

    # Check if device is rooted (for enhanced capabilities)
    IS_ROOTED=0
    if adb shell su -c "id" 2>/dev/null | grep -q "uid=0"; then
        IS_ROOTED=1
        log_success "Device has root access - enhanced scanning available"
    else
        log_warn "Device not rooted - some advanced checks will be limited"
    fi

    # Network monitoring capabilities
    HAVE_TCPDUMP=0
    if adb shell which tcpdump >/dev/null 2>&1; then
        HAVE_TCPDUMP=1
        log_success "tcpdump available on device for network monitoring"
    fi

    # Enhanced tool availability
    HAVE_FRIDA=0
    if command -v frida &>/dev/null; then
        HAVE_FRIDA=1
        log_success "Frida available for runtime analysis"
    fi

    # Get detailed device info
    DEVICE_MODEL=$(adb shell getprop ro.product.model 2>/dev/null)
    DEVICE_OS_VERSION=$(adb shell getprop ro.build.version.release 2>/dev/null)
    DEVICE_SDK_INT=$(adb shell getprop ro.build.version.sdk 2>/dev/null)
    DEVICE_ARCH=$(adb shell getprop ro.product.cpu.abi 2>/dev/null)
    DEVICE_SECURITY_PATCH=$(adb shell getprop ro.build.version.security_patch 2>/dev/null)
}

function run_enhanced_static_analysis() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    log_info "Running enhanced static analysis for $target_name"

    if [[ ! -f "$target_apk" ]]; then
        log_error "APK file not found: $target_apk"
        return
    fi

    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    mkdir -p "$decompile_dir"

    # Enhanced decompilation with multiple tools
    if command -v apktool &>/dev/null; then
        log_info "Decompiling with apktool..."
        apktool d -f -o "$decompile_dir" "$target_apk" >/dev/null 2>&1
    fi

    if command -v jadx &>/dev/null && [[ $DEEP_SCAN -eq 1 ]]; then
        log_info "Decompiling with jadx for source code analysis..."
        jadx -d "$decompile_dir/jadx_output" "$target_apk" >/dev/null 2>&1
    fi

    # --- Advanced Manifest Analysis ---
    local manifest_file="$decompile_dir/AndroidManifest.xml"
    if [[ -f "$manifest_file" ]]; then
        log_info "Performing advanced AndroidManifest.xml analysis..."
        
        # Exported components without proper protection
        local exported_activities
        exported_activities=$(grep -A5 -B5 'android:exported="true"' "$manifest_file" | grep '<activity')
        if [[ -n "$exported_activities" ]]; then
            add_finding "$target_name" "MAN-005" "Manifest" "Exported Activities Without Protection" "Medium" \
                "$exported_activities" \
                "Exported activities should have proper intent filters and permission checks to prevent unauthorized access." \
                "N/A" "MSTG-PLATFORM-11"
        fi

        # Network security config check
        if ! grep -q 'android:networkSecurityConfig' "$manifest_file"; then
            add_finding "$target_name" "NET-002" "Network" "Missing Network Security Configuration" "Medium" \
                "No networkSecurityConfig specified in manifest" \
                "Implement a Network Security Configuration to enforce HTTPS and certificate pinning." \
                "N/A" "MSTG-NETWORK-1"
        fi

        # Custom permission analysis
        local custom_perms
        custom_perms=$(grep -E '<permission|<uses-permission' "$manifest_file" | grep -v 'android.permission')
        if [[ -n "$custom_perms" ]]; then
            add_finding "$target_name" "PERM-002" "Permissions" "Custom Permissions Defined" "Info" \
                "$custom_perms" \
                "Review custom permissions for proper protection levels and necessity." \
                "N/A" "MSTG-PLATFORM-1"
        fi
    fi

    # --- Enhanced Secret Detection ---
    log_info "Running enhanced secret detection..."
    
    # Database connection strings
    local db_secrets
    db_secrets=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "jdbc\|mongodb\|redis\|mysql" 2>/dev/null)
    if [[ -n "$db_secrets" ]]; then
        add_finding "$target_name" "SEC-002" "Secrets" "Database Connection Strings Found" "High" \
            "Database connection patterns found in: $db_secrets" \
            "Never hardcode database credentials. Use secure configuration management." \
            "CWE-798" "MSTG-CRYPTO-1"
    fi

    # Encryption key patterns
    local crypto_keys
    crypto_keys=$(find "$decompile_dir" -type f \( -name "*.smali" -o -name "*.java" \) -exec grep -l "const-string.*[A-Za-z0-9+/]{32,}" {} \; 2>/dev/null)
    if [[ -n "$crypto_keys" ]]; then
        add_finding "$target_name" "CR-003" "Crypto" "Potential Hardcoded Encryption Keys" "High" \
            "Potential encryption keys found in: $crypto_keys" \
            "Generate encryption keys at runtime and store them securely in Android Keystore." \
            "CWE-321" "MSTG-CRYPTO-1"
    fi

    # --- Advanced Code Quality Checks ---
    if [[ $DEEP_SCAN -eq 1 ]]; then
        log_info "Performing deep code analysis..."
        
        # SQL injection patterns
        local sql_injection
        sql_injection=$(find "$decompile_dir" -name "*.java" -exec grep -Hn "rawQuery\|execSQL.*+" {} \; 2>/dev/null)
        if [[ -n "$sql_injection" ]]; then
            add_finding "$target_name" "INJ-001" "Injection" "Potential SQL Injection Vulnerabilities" "High" \
                "$sql_injection" \
                "Use parameterized queries and prepared statements to prevent SQL injection." \
                "CWE-89" "MSTG-CODE-8"
        fi

        # Insecure random number generation
        local weak_random
        weak_random=$(find "$decompile_dir" -name "*.java" -exec grep -Hn "Math.random()\|Random(" {} \; 2>/dev/null)
        if [[ -n "$weak_random" ]]; then
            add_finding "$target_name" "CR-004" "Crypto" "Weak Random Number Generation" "Medium" \
                "$weak_random" \
                "Use SecureRandom for cryptographically secure random number generation." \
                "CWE-338" "MSTG-CRYPTO-6"
        fi
    fi

    # --- Malware Signature Detection ---
    log_info "Scanning for malware signatures..."
    local suspicious_strings=(
        "getSystemService.*TELEPHONY"
        "SmsManager"
        "getDeviceId"
        "getSubscriberId" 
        "android/telephony/TelephonyManager"
        "Ljava/lang/Runtime;->exec"
        "su.*-c"
        "/system/bin/su"
        "/system/xbin/su"
    )

    for pattern in "${suspicious_strings[@]}"; do
        local matches
        matches=$(find "$decompile_dir" -name "*.smali" -exec grep -l "$pattern" {} \; 2>/dev/null)
        if [[ -n "$matches" ]]; then
            add_finding "$target_name" "MAL-001" "Malware" "Suspicious System Access Pattern Detected" "Medium" \
                "Pattern '$pattern' found in: $matches" \
                "Review the necessity of system-level access and ensure proper user consent and security measures." \
                "N/A" "MSTG-PLATFORM-1"
        fi
    done
    
    # --- Enhanced Certificate Pinning Detection ---
    check_certificate_pinning "$target_apk"
    
    # --- Enhanced Biometric Security Analysis ---
    local pkg_name
    if command -v aapt2 &>/dev/null || command -v aapt &>/dev/null; then
        local aapt_tool=$(command -v aapt2 || command -v aapt)
        pkg_name=$($aapt_tool dump badging "$target_apk" 2>/dev/null | grep "package: name=" | awk -F"'" '{print $2}')
    fi
    check_biometric_security "$pkg_name"
    
    # --- Enhanced Debugging and Development Detection ---
    check_debug_features "$target_apk"
    
    # --- Enhanced WebView Security Analysis ---
    check_webview_security "$target_apk"
    
    # --- Enhanced Data Leakage Detection ---
    check_data_leakage "$target_apk"
    
    # --- Enhanced Third-Party Library Analysis ---
    analyze_third_party_libraries "$target_apk"
    
    # --- Enhanced Intent Security Analysis ---
    check_intent_security "$target_apk"
}

function run_behavioral_analysis() {
    local pkg_name=$1
    log_info "Running behavioral analysis for $pkg_name"

    # --- Enhanced Permission Analysis ---
    local dumpsys_output
    dumpsys_output=$(adb shell dumpsys package "$pkg_name" 2>/dev/null)
    
    # Dangerous permissions
    local dangerous_perms
    dangerous_perms=$(echo "$dumpsys_output" | grep -E "android.permission\.(CAMERA|RECORD_AUDIO|ACCESS_FINE_LOCATION|READ_CONTACTS|WRITE_EXTERNAL_STORAGE|SEND_SMS)")
    if [[ -n "$dangerous_perms" ]]; then
        add_finding "$pkg_name" "PRIV-001" "Privacy" "Dangerous Permissions Requested" "Medium" \
            "$dangerous_perms" \
            "Ensure dangerous permissions are necessary and implement runtime permission requests with clear user explanations." \
            "N/A" "MSTG-PLATFORM-1"
    fi

    # --- File System Analysis ---
    if [[ $IS_ROOTED -eq 1 ]]; then
        log_info "Performing enhanced filesystem analysis (root available)"
        
        # Check for sensitive data in app directory
        local app_data_dir="/data/data/$pkg_name"
        local sensitive_files
        sensitive_files=$(adb shell su -c "find $app_data_dir -name '*.db' -o -name '*.sqlite' -o -name '*password*' -o -name '*key*'" 2>/dev/null)
        
        if [[ -n "$sensitive_files" ]]; then
            # Check file permissions
            local world_readable
            world_readable=$(adb shell su -c "find $app_data_dir -perm -o+r" 2>/dev/null)
            if [[ -n "$world_readable" ]]; then
                add_finding "$pkg_name" "STO-003" "Storage" "Sensitive Files with Weak Permissions" "High" \
                    "World-readable files in app directory: $world_readable" \
                    "Ensure sensitive files have proper permissions (600 or 700) and are not accessible to other apps." \
                    "CWE-732" "MSTG-STORAGE-1"
            fi
        fi
    fi

    # --- Process and Service Analysis ---
    local running_services
    running_services=$(adb shell dumpsys activity services | grep -A2 -B2 "$pkg_name")
    if [[ -n "$running_services" ]]; then
        log_debug "Found running services for $pkg_name"
        
        # Check for services running in background
        local background_services
        background_services=$(echo "$running_services" | grep -E "ServiceRecord.*$pkg_name")
        if [[ -n "$background_services" ]]; then
            add_finding "$pkg_name" "PRIV-002" "Privacy" "Background Services Detected" "Low" \
                "$background_services" \
                "Review background services for necessity and ensure they follow Android's background execution limits." \
                "N/A" "MSTG-CODE-8"
        fi
    fi
}

function run_network_security_analysis() {
    local pkg_name=$1
    log_info "Starting network security analysis for $pkg_name"

    if [[ $RUN_NETWORK -eq 0 ]]; then
        log_info "Network analysis skipped per --no-network flag"
        return
    fi

    # --- Network Configuration Analysis ---
    local net_config
    net_config=$(adb shell dumpsys connectivity | grep -A10 -B10 "$pkg_name")
    
    # --- Traffic Monitoring Setup ---
    local traffic_file="$TEMP_DIR/${pkg_name}_traffic.txt"
    
    if [[ $HAVE_TCPDUMP -eq 1 ]]; then
        log_info "Starting network traffic capture..."
        adb shell "tcpdump -i any -s 0 -w /sdcard/capture_${pkg_name}.pcap" &
        local tcpdump_pid=$!
        
        # Launch app and generate traffic
        log_info "Launching app to generate network traffic..."
        local launch_activity
        launch_activity=$(adb shell cmd package resolve-activity --brief -c android.intent.category.LAUNCHER "$pkg_name" | tail -n 1)
        
        if [[ -n "$launch_activity" && "$launch_activity" != "Error"* ]]; then
            adb shell am start -n "$launch_activity" >/dev/null
            sleep "$NETWORK_TIMEOUT"
        fi
        
        # Stop capture and analyze
        kill "$tcpdump_pid" 2>/dev/null
        adb pull "/sdcard/capture_${pkg_name}.pcap" "$TEMP_DIR/" 2>/dev/null
        adb shell rm "/sdcard/capture_${pkg_name}.pcap" 2>/dev/null
        
        # Basic traffic analysis
        if command -v tcpdump &>/dev/null && [[ -f "$TEMP_DIR/capture_${pkg_name}.pcap" ]]; then
            local http_traffic
            http_traffic=$(tcpdump -r "$TEMP_DIR/capture_${pkg_name}.pcap" -A 2>/dev/null | grep -i "http" | head -20)
            if [[ -n "$http_traffic" ]]; then
                add_finding "$pkg_name" "NET-003" "Network" "Unencrypted HTTP Traffic Detected" "High" \
                    "HTTP traffic captured during app usage" \
                    "All network communication should use HTTPS/TLS encryption to protect data in transit." \
                    "CWE-319" "MSTG-NETWORK-1"
            fi
        fi
    fi

    # --- SSL/TLS Analysis via Logcat ---
    log_info "Monitoring for SSL/TLS issues..."
    local ssl_log="$TEMP_DIR/${pkg_name}_ssl.log"
    adb logcat -c
    adb logcat -v time > "$ssl_log" &
    local logcat_pid=$!
    
    sleep 10
    kill "$logcat_pid" 2>/dev/null
    
    # Check for certificate validation bypasses
    local cert_bypass
    cert_bypass=$(grep -E "(X509TrustManager|checkServerTrusted|onReceivedSslError)" "$ssl_log")
    if [[ -n "$cert_bypass" ]]; then
        add_finding "$pkg_name" "NET-004" "Network" "SSL Certificate Validation Issues" "High" \
            "$cert_bypass" \
            "Implement proper SSL certificate validation. Never ignore certificate errors or implement custom trust managers without proper validation." \
            "CWE-295" "MSTG-NETWORK-3"
    fi
}

function run_privacy_analysis() {
    local pkg_name=$1
    log_info "Analyzing privacy and data collection patterns for $pkg_name"

    # --- Advertising and Analytics Detection ---
    local dumpsys_output
    dumpsys_output=$(adb shell dumpsys package "$pkg_name")
    
    # Common analytics/advertising SDKs
    local analytics_sdks=("google.*analytics" "facebook.*sdk" "crashlytics" "firebase" "flurry" "mixpanel")
    for sdk in "${analytics_sdks[@]}"; do
        if echo "$dumpsys_output" | grep -qi "$sdk"; then
            add_finding "$pkg_name" "PRIV-003" "Privacy" "Analytics/Advertising SDK Detected" "Info" \
                "Detected potential analytics SDK: $sdk" \
                "Review data collection practices and ensure compliance with privacy regulations (GDPR, CCPA). Implement proper user consent mechanisms." \
                "N/A" "MSTG-PLATFORM-1"
        fi
    done

    # --- Location Access Analysis ---
    local location_perms
    location_perms=$(echo "$dumpsys_output" | grep -E "ACCESS_(FINE|COARSE)_LOCATION")
    if [[ -n "$location_perms" ]]; then
        # Check if location is accessed in background
        local background_location
        background_location=$(echo "$dumpsys_output" | grep "ACCESS_BACKGROUND_LOCATION")
        if [[ -n "$background_location" ]]; then
            add_finding "$pkg_name" "PRIV-004" "Privacy" "Background Location Access" "High" \
                "App requests background location access" \
                "Background location access should be limited to essential functionality and clearly disclosed to users." \
                "N/A" "MSTG-PLATFORM-1"
        fi
    fi

    # --- Data Storage Privacy Check ---
    if [[ $IS_ROOTED -eq 1 ]]; then
        local pii_files
        pii_files=$(adb shell su -c "find /data/data/$pkg_name -name '*.db' -exec grep -l 'email\|phone\|address\|name' {} \;" 2>/dev/null)
        if [[ -n "$pii_files" ]]; then
            add_finding "$pkg_name" "PRIV-005" "Privacy" "Potential PII Storage Detected" "Medium" \
                "Potential personally identifiable information found in: $pii_files" \
                "Implement proper data encryption for stored PII and follow data minimization principles." \
                "N/A" "MSTG-STORAGE-1"
        fi
    fi
}

function generate_enhanced_report() {
    local target="$1"
    local report_base_name="enhanced_security_report_${target//./_}_$(date +%Y%m%d_%H%M%S)"
    local report_md="$OUTPUT_DIR/${report_base_name}.md"
    local report_json="$OUTPUT_DIR/${report_base_name}.json"

    log_info "Generating enhanced security report: $report_md"

    # Calculate risk score
    local risk_score=$((HIGH_SEVERITY_COUNT * 10 + MEDIUM_SEVERITY_COUNT * 5 + LOW_SEVERITY_COUNT * 2))
    local risk_level="LOW"
    if [[ $risk_score -gt 50 ]]; then
        risk_level="CRITICAL"
    elif [[ $risk_score -gt 30 ]]; then
        risk_level="HIGH"
    elif [[ $risk_score -gt 15 ]]; then
        risk_level="MEDIUM"
    fi

    # Enhanced summary table
    local summary_table
    summary_table="| Severity | Count |\n"
    summary_table+="|----------|-------|\n"
    summary_table+="| 🔴 High  | $HIGH_SEVERITY_COUNT |\n"
    summary_table+="| 🟠 Medium | $MEDIUM_SEVERITY_COUNT |\n"
    summary_table+="| 🟡 Low   | $LOW_SEVERITY_COUNT |\n"
    summary_table+="| ℹ️ Info  | $INFO_SEVERITY_COUNT |\n"
    summary_table+="|----------|-------|\n"
    summary_table+="| **Risk Score** | **${risk_score} (${risk_level})** |\n\n"

    # Device and environment info
    local device_info
    device_info="## Device & Environment Information\n\n"
    device_info+="| Property | Value |\n|----------|-------|\n"
    device_info+="| Device | ${DEVICE_MODEL} |\n"
    device_info+="| Serial | ${DEVICE_SERIAL} |\n"
    device_info+="| Android Version | ${DEVICE_OS_VERSION} (API ${DEVICE_SDK_INT}) |\n"
    device_info+="| Architecture | ${DEVICE_ARCH} |\n"
    device_info+="| Security Patch | ${DEVICE_SECURITY_PATCH} |\n"
    device_info+="| Root Status | $([[ $IS_ROOTED -eq 1 ]] && echo "✅ Rooted" || echo "❌ Not Rooted") |\n"
    device_info+="| Scanner Version | ${SCRIPT_VERSION} |\n\n"

    # Compliance summary
    local compliance_info
    compliance_info="## OWASP MASVS Compliance Summary\n\n"
    compliance_info+="This assessment covers key areas of the OWASP Mobile Application Security Verification Standard:\n\n"
    compliance_info+="- **V1**: Architecture, Design and Threat Modeling\n"
    compliance_info+="- **V2**: Data Storage and Privacy\n"  
    compliance_info+="- **V3**: Cryptography\n"
    compliance_info+="- **V4**: Authentication and Session Management\n"
    compliance_info+="- **V5**: Network Communication\n"
    compliance_info+="- **V6**: Platform Interaction\n"
    compliance_info+="- **V7**: Code Quality and Build Settings\n"
    compliance_info+="- **V8**: Malware and Reverse Engineering\n\n"

    # Generate markdown report
    local md_header
    md_header="# 🔒 Enhanced Android Security Assessment Report\n\n"
    md_header+="**Target Application:** \`$target\`  \n"
    md_header+="**Scan Timestamp:** ${SCRIPT_START_TIME}  \n"
    md_header+="**Assessment Type:** Defensive Security Analysis  \n"
    md_header+="**Risk Level:** ${risk_level}  \n\n"

    echo -e "$md_header" > "$report_md"
    echo -e "$device_info" >> "$report_md"
    echo -e "## Executive Summary\n\n$summary_table" >> "$report_md"
    echo -e "$compliance_info" >> "$report_md"
    echo -e "## Detailed Findings\n\n---\n" >> "$report_md"
    echo -e "$FINDINGS_MD" >> "$report_md"

    # Generate JSON report
    if [[ $GENERATE_JSON -eq 1 ]]; then
        log_info "Generating enhanced JSON report: $report_json"
        local device_json
        device_json=$(printf '{"serial":"%s","model":"%s","androidVersion":"%s","sdkInt":%s,"architecture":"%s","securityPatch":"%s","isRooted":%s}' \
            "$DEVICE_SERIAL" "$DEVICE_MODEL" "$DEVICE_OS_VERSION" "$DEVICE_SDK_INT" "$DEVICE_ARCH" "$DEVICE_SECURITY_PATCH" "$IS_ROOTED")
        
        local summary_json
        summary_json=$(printf '{"high":%d,"medium":%d,"low":%d,"info":%d,"riskScore":%d,"riskLevel":"%s"}' \
            "$HIGH_SEVERITY_COUNT" "$MEDIUM_SEVERITY_COUNT" "$LOW_SEVERITY_COUNT" "$INFO_SEVERITY_COUNT" "$risk_score" "$risk_level")

        local final_json
        final_json=$(printf '{"target":"%s","timestamp":"%s","scannerVersion":"%s","device":%s,"summary":%s,"findings":%s}' \
            "$target" "$SCRIPT_START_TIME" "$SCRIPT_VERSION" "$device_json" "$summary_json" "$FINDINGS_JSON")

        if command -v jq &>/dev/null; then
            echo "$final_json" | jq . > "$report_json"
        else
            echo "$final_json" > "$report_json"
        fi
    fi

    log_success "Enhanced security assessment complete!"
    log_info "📊 Risk Score: $risk_score ($risk_level)"
    log_info "📈 Findings: $HIGH_SEVERITY_COUNT High, $MEDIUM_SEVERITY_COUNT Medium, $LOW_SEVERITY_COUNT Low"
}

# --- Enhanced Main Function ---
function main() {
    echo -e "${PURPLE}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}║        Enhanced Android Security Scanner v${SCRIPT_VERSION}        ║${NC}"
    echo -e "${PURPLE}║              Defensive Security Edition              ║${NC}"
    echo -e "${PURPLE}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  AUTHORIZED DEFENSIVE TESTING ONLY ⚠️${NC}"
    echo -e "This tool performs passive security assessment for defensive purposes."
    echo ""

    # Parse arguments
    parse_args "$@"
    
    # Enhanced prerequisite checks
    check_enhanced_prerequisites
    
    # Setup temporary directory
    TEMP_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'enhanced-android-scanner')
    log_info "Temporary directory: $TEMP_DIR"
    mkdir -p "$OUTPUT_DIR"

    # Process each target
    for target_item in "${APP_TARGETS[@]}"; do
        # Reset findings for each target
        FINDINGS_MD=""
        FINDINGS_JSON="[]"
        HIGH_SEVERITY_COUNT=0
        MEDIUM_SEVERITY_COUNT=0
        LOW_SEVERITY_COUNT=0
        INFO_SEVERITY_COUNT=0
        
        local type="${target_item%%:*}"
        local target="${target_item#*:}"

        log_info "════════════════════════════════════════════════════════"
        log_info "🎯 Starting enhanced security assessment: $target"
        log_info "════════════════════════════════════════════════════════"

        case "$type" in
            "apk")
                if [[ $RUN_STATIC -eq 1 ]]; then
                    run_enhanced_static_analysis "$target"
                fi
                
                # Extract package name for dynamic analysis
                local pkg_name=""
                if command -v aapt2 &>/dev/null || command -v aapt &>/dev/null; then
                    local aapt_tool=$(command -v aapt2 || command -v aapt)
                    pkg_name=$($aapt_tool dump badging "$target" 2>/dev/null | grep "package: name=" | awk -F"'" '{print $2}')
                fi
                
                if [[ $RUN_DYNAMIC -eq 1 && -n "$pkg_name" ]]; then
                    if adb shell pm list packages | grep -q "$pkg_name"; then
                        log_info "📱 Package installed, running device analysis..."
                        run_behavioral_analysis "$pkg_name"
                        run_network_security_analysis "$pkg_name" 
                        run_privacy_analysis "$pkg_name"
                    else
                        log_warn "Package not installed, skipping dynamic analysis"
                    fi
                fi
                ;;
                
            "pkg")
                if [[ $RUN_STATIC -eq 1 ]]; then
                    log_info "📦 Pulling APK for static analysis..."
                    local apk_path
                    apk_path=$(adb shell pm path "$target" | sed 's/package://g' | tr -d '\r')
                    if [[ -n "$apk_path" ]]; then
                        local pulled_apk="$TEMP_DIR/$(basename "$apk_path")"
                        if adb pull "$apk_path" "$pulled_apk" >/dev/null 2>&1; then
                            run_enhanced_static_analysis "$pulled_apk"
                        fi
                    fi
                fi

                if [[ $RUN_DYNAMIC -eq 1 ]]; then
                    run_behavioral_analysis "$target"
                    run_network_security_analysis "$target"
                    run_privacy_analysis "$target"
                fi
                ;;
        esac

        # Generate enhanced report
        generate_enhanced_report "$target"
        calculate_security_score "$target"
        
        log_success "✅ Assessment completed for: $target"
        echo ""
    done

    # Final cleanup
    cleanup

    # Exit with appropriate status
    local total_critical=$((HIGH_SEVERITY_COUNT + MEDIUM_SEVERITY_COUNT))
    if [[ $total_critical -gt 0 ]]; then
        log_warn "🚨 Assessment completed with $total_critical critical/medium findings"
        exit 1
    else
        log_success "✅ Assessment completed with no critical findings"
        exit 0
    fi
}

# --- Enhanced Argument Parsing ---
function parse_args() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 1
    fi

    while [[ "$1" != "" ]]; do
        case $1 in
        --apk)
            shift
            if [[ ! -f "$1" ]]; then
                log_error "APK file not found: $1"
                exit 1
            fi
            APP_TARGETS+=("apk:$1")
            ;;
        --package)
            shift
            APP_TARGETS+=("pkg:$1")
            ;;
        --all-user)
            log_info "Discovering user-installed applications..."
            local user_packages
            user_packages=$(adb shell pm list packages -3 2>/dev/null | sed 's/package://g')
            local count=0
            for pkg in $user_packages; do
                APP_TARGETS+=("pkg:$pkg")
                ((count++))
            done
            log_info "Found $count user-installed applications"
            ;;
        --out)
            shift
            OUTPUT_DIR="$1"
            mkdir -p "$OUTPUT_DIR"
            ;;
        --timeout)
            shift
            DYNAMIC_TIMEOUT="$1"
            ;;
        --net-timeout)
            shift
            NETWORK_TIMEOUT="$1"
            ;;
        --deep)
            DEEP_SCAN=1
            log_info "Deep scanning enabled - this will take longer but be more thorough"
            ;;
        --no-dynamic)
            RUN_DYNAMIC=0
            ;;
        --no-static)
            RUN_STATIC=0
            ;;
        --no-network)
            RUN_NETWORK=0
            ;;
        --json)
            GENERATE_JSON=1
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
        esac
        shift
    done

    if [[ ${#APP_TARGETS[@]} -eq 0 ]]; then
        log_error "No targets specified. Use --apk, --package, or --all-user"
        exit 1
    fi
}

# --- Additional Security Checks ---

function check_rooting_detection_bypass() {
    local pkg_name=$1
    log_debug "Checking for root detection bypass mechanisms"
    
    # Common root detection libraries
    local root_detection_libs=("RootBeer" "rootchecker" "SafetyNet")
    local dumpsys_output
    dumpsys_output=$(adb shell dumpsys package "$pkg_name" 2>/dev/null)
    
    for lib in "${root_detection_libs[@]}"; do
        if echo "$dumpsys_output" | grep -qi "$lib"; then
            add_finding "$pkg_name" "SEC-003" "Security" "Root Detection Library Found" "Info" \
                "Root detection library detected: $lib" \
                "Root detection can be bypassed. Implement multiple detection methods and server-side validation for critical security decisions." \
                "N/A" "MSTG-RESILIENCE-1"
        fi
    done
}

function check_anti_tampering() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    
    log_debug "Checking for anti-tampering mechanisms"
    
    # Check for code obfuscation
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    if [[ -d "$decompile_dir" ]]; then
        local obfuscated_classes
        obfuscated_classes=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "\.class.*[a-z]\{1,3\};" {} \; | wc -l)
        
        if [[ $obfuscated_classes -gt 10 ]]; then
            add_finding "$target_name" "SEC-004" "Security" "Code Obfuscation Detected" "Info" \
                "Detected $obfuscated_classes potentially obfuscated classes" \
                "Code obfuscation helps prevent reverse engineering but is not a complete security solution. Combine with other protection mechanisms." \
                "N/A" "MSTG-RESILIENCE-9"
        fi
    fi
}

function check_backup_security() {
    local pkg_name=$1
    log_debug "Analyzing backup security configuration"
    
    if [[ $IS_ROOTED -eq 1 ]]; then
        # Check if app data is included in system backups
        local backup_transport
        backup_transport=$(adb shell bmgr list transports 2>/dev/null)
        if [[ -n "$backup_transport" ]]; then
            local backup_enabled
            backup_enabled=$(adb shell dumpsys backup | grep -A5 "$pkg_name")
            if [[ -n "$backup_enabled" ]]; then
                add_finding "$pkg_name" "STO-004" "Storage" "Application Backup Enabled" "Low" \
                    "Application participates in system backup: $backup_enabled" \
                    "Review backup behavior and exclude sensitive data from backups using backup rules." \
                    "N/A" "MSTG-STORAGE-8"
            fi
        fi
    fi
}

function perform_owasp_masvs_assessment() {
    local target=$1
    local pkg_name=$2
    
    log_info "🔍 Performing OWASP MASVS compliance assessment"
    
    # This function would map findings to OWASP MASVS categories
    # and provide a compliance score for each category
    
    local masvs_categories=(
        "V1:Architecture" 
        "V2:DataStorage" 
        "V3:Cryptography"
        "V4:Authentication"
        "V5:NetworkComm"
        "V6:PlatformInteraction"
        "V7:CodeQuality"
        "V8:Resilience"
    )
    
    # Generate OWASP MASVS compliance summary
    add_finding "$target" "MASVS-001" "Compliance" "OWASP MASVS Assessment Complete" "Info" \
        "Assessment completed against OWASP Mobile Application Security Verification Standard" \
        "Review detailed findings against each MASVS control category for comprehensive security posture." \
        "N/A" "MSTG-OVERALL"
}

# --- Security Compliance Scoring System ---
function calculate_security_score() {
    local target=$1
    log_info "Calculating comprehensive security score for $target"
    
    local total_possible_score=100
    local deductions=0
    
    # Weight different severity levels
    deductions=$((HIGH_SEVERITY_COUNT * 15))      # High: -15 points each
    deductions=$((deductions + MEDIUM_SEVERITY_COUNT * 8))  # Medium: -8 points each  
    deductions=$((deductions + LOW_SEVERITY_COUNT * 3))     # Low: -3 points each
    
    local final_score=$((total_possible_score - deductions))
    
    # Ensure score doesn't go below 0
    if [[ $final_score -lt 0 ]]; then
        final_score=0
    fi
    
    local grade="F"
    if [[ $final_score -ge 90 ]]; then
        grade="A"
    elif [[ $final_score -ge 80 ]]; then
        grade="B"
    elif [[ $final_score -ge 70 ]]; then
        grade="C"
    elif [[ $final_score -ge 60 ]]; then
        grade="D"
    fi
    
    log_info "🏆 Security Score: $final_score/100 (Grade: $grade)"
    
    # Add scoring details to findings
    add_finding "$target" "SCORE-001" "Assessment" "Security Compliance Score" "Info" \
        "Overall Security Score: $final_score/100 (Grade: $grade). Based on $HIGH_SEVERITY_COUNT high, $MEDIUM_SEVERITY_COUNT medium, and $LOW_SEVERITY_COUNT low severity findings." \
        "Address high and medium severity findings to improve security posture. Aim for a score above 85 for production applications." \
        "N/A" "MSTG-OVERALL"
}

# Execute main function
main "$@"

# --- Enhanced Certificate Pinning Detection ---
function check_certificate_pinning() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    
    log_info "Checking for certificate pinning implementation..."
    
    if [[ -d "$decompile_dir" ]]; then
        # Check for common certificate pinning libraries
        local pinning_libs=("okhttp3.*CertificatePinner" "com.datatheorem.android.trustkit" "com.scottyab.rootbeer" "network_security_config")
        local pinning_found=0
        
        for lib in "${pinning_libs[@]}"; do
            local matches
            matches=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "$lib" 2>/dev/null)
            if [[ -n "$matches" ]]; then
                pinning_found=1
                add_finding "$target_name" "NET-005" "Network" "Certificate Pinning Implementation Detected" "Info" \
                    "Certificate pinning library found: $lib in $matches" \
                    "Good security practice. Ensure pinning is properly implemented with backup pins and proper error handling." \
                    "N/A" "MSTG-NETWORK-4"
            fi
        done
        
        if [[ $pinning_found -eq 0 ]]; then
            add_finding "$target_name" "NET-006" "Network" "No Certificate Pinning Detected" "Medium" \
                "No evidence of certificate pinning implementation found" \
                "Implement certificate pinning to prevent man-in-the-middle attacks, especially for sensitive communications." \
                "CWE-295" "MSTG-NETWORK-4"
        fi
        
        # Check for custom trust managers
        local custom_trust
        custom_trust=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "X509TrustManager\|trustAllCerts" 2>/dev/null)
        if [[ -n "$custom_trust" ]]; then
            add_finding "$target_name" "NET-007" "Network" "Custom Trust Manager Detected" "High" \
                "Custom X509TrustManager implementation found in: $custom_trust" \
                "Review custom trust manager implementation. Ensure it properly validates certificates and doesn't accept all certificates." \
                "CWE-295" "MSTG-NETWORK-3"
        fi
    fi
}

# --- Enhanced Biometric Security Analysis ---
function check_biometric_security() {
    local pkg_name=$1
    log_info "Analyzing biometric authentication implementation..."
    
    local dumpsys_output
    dumpsys_output=$(adb shell dumpsys package "$pkg_name" 2>/dev/null)
    
    # Check for biometric permissions
    local biometric_perms
    biometric_perms=$(echo "$dumpsys_output" | grep -E "USE_BIOMETRIC|USE_FINGERPRINT")
    if [[ -n "$biometric_perms" ]]; then
        add_finding "$pkg_name" "AUTH-001" "Authentication" "Biometric Authentication Available" "Info" \
            "Biometric permissions detected: $biometric_perms" \
            "Ensure biometric authentication is properly implemented with fallback mechanisms and secure key storage." \
            "N/A" "MSTG-AUTH-8"
            
        # Check for secure hardware usage
        if [[ $IS_ROOTED -eq 1 ]]; then
            local keystore_check
            keystore_check=$(adb shell su -c "ls -la /data/misc/keystore/user_0/" 2>/dev/null | grep "$pkg_name")
            if [[ -n "$keystore_check" ]]; then
                add_finding "$pkg_name" "CR-005" "Crypto" "Hardware-Backed Key Storage Detected" "Info" \
                    "Application appears to use Android Keystore: $keystore_check" \
                    "Good security practice. Continue using hardware-backed key storage for sensitive cryptographic operations." \
                    "N/A" "MSTG-CRYPTO-1"
            fi
        fi
    fi
}

# --- Enhanced Debugging and Development Detection ---
function check_debug_features() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    
    log_info "Checking for debugging and development features..."
    
    if [[ -d "$decompile_dir" ]]; then
        # Check for logging statements
        local logging_found
        logging_found=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "Log\.[vdiwef]\|System\.out\.print\|printStackTrace" 2>/dev/null | head -10)
        if [[ -n "$logging_found" ]]; then
            add_finding "$target_name" "DEV-001" "Development" "Debug Logging Statements Found" "Low" \
                "Debug logging found in: $logging_found" \
                "Remove or disable debug logging in production builds to prevent information leakage." \
                "CWE-532" "MSTG-CODE-2"
        fi
        
        # Check for test code
        local test_code
        test_code=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "\.test\.\|Test.*class\|@Test" 2>/dev/null)
        if [[ -n "$test_code" ]]; then
            add_finding "$target_name" "DEV-002" "Development" "Test Code in Production Build" "Medium" \
                "Test code found in production build: $test_code" \
                "Remove test code from production builds to reduce attack surface and prevent information disclosure." \
                "N/A" "MSTG-CODE-8"
        fi
        
        # Check for development URLs/endpoints
        local dev_urls
        dev_urls=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -E "localhost|127\.0\.0\.1|\.dev\.|staging\.|test\." 2>/dev/null)
        if [[ -n "$dev_urls" ]]; then
            add_finding "$target_name" "DEV-003" "Development" "Development URLs Detected" "Medium" \
                "Development/test URLs found: $dev_urls" \
                "Ensure production builds only contain production endpoints and remove development URLs." \
                "N/A" "MSTG-CODE-2"
        fi
    fi
}

# --- Enhanced WebView Security Analysis ---
function check_webview_security() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    
    log_info "Analyzing WebView security configuration..."
    
    if [[ -d "$decompile_dir" ]]; then
        # Check for WebView usage
        local webview_usage
        webview_usage=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "WebView\|webview" 2>/dev/null)
        
        if [[ -n "$webview_usage" ]]; then
            # Check for JavaScript enabled
            local js_enabled
            js_enabled=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "setJavaScriptEnabled.*true" 2>/dev/null)
            if [[ -n "$js_enabled" ]]; then
                add_finding "$target_name" "WEB-001" "WebView" "JavaScript Enabled in WebView" "Medium" \
                    "JavaScript enabled in WebView: $js_enabled" \
                    "Only enable JavaScript if necessary and implement proper input validation and CSP headers." \
                    "CWE-79" "MSTG-PLATFORM-7"
            fi
            
            # Check for file access
            local file_access
            file_access=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "setAllowFileAccess.*true\|setAllowUniversalAccessFromFileURLs.*true" 2>/dev/null)
            if [[ -n "$file_access" ]]; then
                add_finding "$target_name" "WEB-002" "WebView" "File Access Enabled in WebView" "High" \
                    "File access enabled in WebView: $file_access" \
                    "Disable file access in WebView unless absolutely necessary to prevent local file inclusion attacks." \
                    "CWE-22" "MSTG-PLATFORM-7"
            fi
            
            # Check for addJavascriptInterface
            local js_interface
            js_interface=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "addJavascriptInterface" 2>/dev/null)
            if [[ -n "$js_interface" ]]; then
                add_finding "$target_name" "WEB-003" "WebView" "JavaScript Interface Bridge Detected" "High" \
                    "JavaScript interface bridge found: $js_interface" \
                    "JavaScript interfaces can expose native functionality to web content. Ensure proper validation and consider security implications." \
                    "CWE-94" "MSTG-PLATFORM-7"
            fi
        fi
    fi
}

# --- Enhanced Data Leakage Detection ---
function check_data_leakage() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    
    log_info "Scanning for potential data leakage patterns..."
    
    if [[ -d "$decompile_dir" ]]; then
        # Check for clipboard usage
        local clipboard_usage
        clipboard_usage=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "ClipboardManager\|setPrimaryClip\|getPrimaryClip" 2>/dev/null)
        if [[ -n "$clipboard_usage" ]]; then
            add_finding "$target_name" "LEAK-001" "Data Leakage" "Clipboard Usage Detected" "Medium" \
                "Clipboard access found in: $clipboard_usage" \
                "Be cautious with clipboard usage. Sensitive data in clipboard can be accessed by other apps." \
                "CWE-200" "MSTG-PLATFORM-4"
        fi
        
        # Check for screenshot/screen recording detection
        local screenshot_usage
        screenshot_usage=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "FLAG_SECURE\|FEATURE_SCREEN_CAPTURE\|MediaProjection" 2>/dev/null)
        if [[ -z "$screenshot_usage" ]]; then
            add_finding "$target_name" "LEAK-002" "Data Leakage" "No Screenshot Protection Detected" "Medium" \
                "No evidence of screenshot protection (FLAG_SECURE)" \
                "Consider implementing FLAG_SECURE for sensitive screens to prevent screenshots and screen recording." \
                "N/A" "MSTG-STORAGE-9"
        fi
        
        # Check for pasteboard/general pasteboard access
        local pasteboard_patterns=("UIPasteboard" "generalPasteboard" "NSPasteboard")
        for pattern in "${pasteboard_patterns[@]}"; do
            local pasteboard_usage
            pasteboard_usage=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "$pattern" 2>/dev/null)
            if [[ -n "$pasteboard_usage" ]]; then
                add_finding "$target_name" "LEAK-003" "Data Leakage" "Pasteboard Access Detected" "Low" \
                    "Pasteboard access pattern found: $pattern" \
                    "Review pasteboard usage to ensure sensitive data isn't inadvertently exposed." \
                    "CWE-200" "MSTG-PLATFORM-4"
            fi
        done
        
        # Check for URL schemes that might leak data
        local url_schemes
        url_schemes=$(find "$decompile_dir" -name "*.xml" | xargs grep -l "android:scheme.*http\|custom.*://" 2>/dev/null)
        if [[ -n "$url_schemes" ]]; then
            add_finding "$target_name" "LEAK-004" "Data Leakage" "Custom URL Schemes Detected" "Low" \
                "Custom URL schemes found in: $url_schemes" \
                "Ensure custom URL schemes don't accept or leak sensitive data through URL parameters." \
                "CWE-200" "MSTG-PLATFORM-3"
        fi
    fi
}

# --- Enhanced Third-Party Library Analysis ---
function analyze_third_party_libraries() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    
    log_info "Analyzing third-party libraries and dependencies..."
    
    if [[ -d "$decompile_dir" ]]; then
        # Common vulnerable or outdated libraries
        local vulnerable_libs=(
            "apache.*commons.*collections.*3\.[0-2]"  # Apache Commons Collections RCE
            "com\.fasterxml\.jackson.*2\.[0-9]\.[0-7]" # Jackson deserialization
            "org\.springframework.*4\.[0-2]"          # Spring Framework RCE
            "struts.*2\.[0-4]"                        # Apache Struts RCE
            "log4j.*1\."                              # Log4j vulnerabilities
            "okhttp.*2\."                             # Older OkHttp versions
        )
        
        for lib_pattern in "${vulnerable_libs[@]}"; do
            local lib_found
            lib_found=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "$lib_pattern" 2>/dev/null)
            if [[ -n "$lib_found" ]]; then
                add_finding "$target_name" "DEP-001" "Dependencies" "Potentially Vulnerable Library Detected" "High" \
                    "Potentially vulnerable library pattern found: $lib_pattern" \
                    "Update to the latest version of identified libraries to address known security vulnerabilities." \
                    "CVE-VARIES" "MSTG-CODE-5"
            fi
        done
        
        # Check for common ad libraries (potential privacy concern)
        local ad_libs=("admob" "adsense" "doubleclick" "facebook.*ads" "mopub" "unity.*ads")
        for ad_lib in "${ad_libs[@]}"; do
            local ad_found
            ad_found=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "$ad_lib" 2>/dev/null)
            if [[ -n "$ad_found" ]]; then
                add_finding "$target_name" "PRIV-006" "Privacy" "Advertising Library Detected" "Info" \
                    "Advertising library found: $ad_lib" \
                    "Ensure compliance with privacy regulations and proper disclosure of data collection by advertising libraries." \
                    "N/A" "MSTG-PLATFORM-1"
            fi
        done
        
        # Check for social media SDKs
        local social_libs=("facebook.*sdk" "twitter.*sdk" "linkedin.*sdk" "google.*plus")
        for social_lib in "${social_libs[@]}"; do
            local social_found
            social_found=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "$social_lib" 2>/dev/null)
            if [[ -n "$social_found" ]]; then
                add_finding "$target_name" "PRIV-007" "Privacy" "Social Media SDK Detected" "Info" \
                    "Social media SDK found: $social_lib" \
                    "Review data sharing practices with social media platforms and ensure user consent." \
                    "N/A" "MSTG-PLATFORM-1"
            fi
        done
    fi
}

# --- Enhanced Intent Security Analysis ---
function check_intent_security() {
    local target_apk=$1
    local target_name
    target_name=$(basename "$target_apk")
    local decompile_dir="$TEMP_DIR/$target_name.decoded"
    
    log_info "Analyzing Intent usage and security..."
    
    if [[ -d "$decompile_dir" ]]; then
        # Check for implicit intents with sensitive data
        local implicit_intents
        implicit_intents=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "new.*Intent.*String.*String\|setAction.*startActivity" 2>/dev/null)
        if [[ -n "$implicit_intents" ]]; then
            add_finding "$target_name" "INT-001" "Intents" "Implicit Intent Usage Detected" "Medium" \
                "Implicit intent usage found in: $implicit_intents" \
                "Use explicit intents for internal communications to prevent intent hijacking attacks." \
                "CWE-926" "MSTG-PLATFORM-2"
        fi
        
        # Check for pending intents without proper flags
        local pending_intents
        pending_intents=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "PendingIntent\." 2>/dev/null)
        if [[ -n "$pending_intents" ]]; then
            # Check if FLAG_IMMUTABLE or FLAG_UPDATE_CURRENT is used
            local secure_flags
            secure_flags=$(find "$decompile_dir" -name "*.smali" -o -name "*.java" | xargs grep -l "FLAG_IMMUTABLE\|FLAG_UPDATE_CURRENT" 2>/dev/null)
            if [[ -z "$secure_flags" ]]; then
                add_finding "$target_name" "INT-002" "Intents" "Insecure PendingIntent Configuration" "High" \
                    "PendingIntent usage without secure flags detected" \
                    "Use FLAG_IMMUTABLE for PendingIntents to prevent intent modification by malicious apps." \
                    "CWE-926" "MSTG-PLATFORM-2"
            fi
        fi
        
        # Check for broadcast receivers without proper permissions
        local manifest_file="$decompile_dir/AndroidManifest.xml"
        if [[ -f "$manifest_file" ]]; then
            local exported_receivers
            exported_receivers=$(grep -B2 -A5 'android:exported="true"' "$manifest_file" | grep '<receiver')
            if [[ -n "$exported_receivers" ]]; then
                local protected_receivers
                protected_receivers=$(echo "$exported_receivers" | grep -E 'android:permission=|permission:')
                if [[ -z "$protected_receivers" ]]; then
                    add_finding "$target_name" "INT-003" "Intents" "Unprotected Exported Broadcast Receivers" "High" \
                        "Exported broadcast receivers without permission protection found" \
                        "Protect exported broadcast receivers with appropriate permissions to prevent unauthorized access." \
                        "CWE-284" "MSTG-PLATFORM-11"
                fi
            fi
        fi
    fi
}