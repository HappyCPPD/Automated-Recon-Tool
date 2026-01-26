#!/bin/bash

PURPLE='\033[0;35m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET_DIR=""
TARGET=""
LOG_FILE=""
RESULTS_DIR=""
TOOLS_DIR=""
SCAN_TIMEOUT=300
THREADS=50
CONCURRENT_SCANS=5

DISCORD_WEBHOOK_URL=""
DISCORD_ENABLED=false

declare -A TOOLS=(
    ["dalfox"]="github.com/hahwul/dalfox/v2"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx"
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    ["anew"]="github.com/tomnomnom/anew"
    ["assetfinder"]="github.com/tomnomnom/assetfinder"
    ["gau"]="github.com/lc/gau/v2/cmd/gau"
    ["waybackurls"]="github.com/tomnomnom/waybackurls"
    ["qsreplace"]="github.com/tomnomnom/qsreplace"
    ["findomain"]="github.com/Edu4rdSHL/findomain"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v2/cmd/nuclei"
    ["ffuf"]="github.com/ffuf/ffuf"
    ["gospider"]="github.com/jaeles-project/gospider"
    ["paramspider"]="github.com/devanshbatham/ParamSpider"
    ["crlfuzz"]="github.com/dwisiswant0/crlfuzz/cmd/crlfuzz"
)

generate_html_report() {
    local output_dir="$RESULTS_DIR/report"
    mkdir -p "$output_dir"
    
    cat > "$output_dir/index.html" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Recon Report - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .finding { border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; background: #f8f9fa; }
        .critical { border-left-color: #e74c3c; }
        .high { border-left-color: #e67e22; }
        .medium { border-left-color: #f1c40f; }
        .low { border-left-color: #2ecc71; }
        .nav { background: white; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .nav a { margin-right: 15px; text-decoration: none; color: #2c3e50; }
        .nav a:hover { color: #3498db; }
        .pagination { text-align: center; margin-top: 20px; }
        .pagination a { margin: 0 5px; padding: 5px 10px; border: 1px solid #ddd; text-decoration: none; }
        .pagination a.active { background: #3498db; color: white; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Recon Report</h1>
            <p>Target: $TARGET</p>
            <p class="timestamp">Generated: $(date)</p>
        </div>
        <div class="nav">
            <a href="#summary">Summary</a>
            <a href="#subdomains">Subdomains</a>
            <a href="#vulnerabilities">Vulnerabilities</a>
            <a href="#xss">XSS Findings</a>
            <a href="#content">Content Discovery</a>
            <a href="#fuzzing">Fuzzing Results</a>
        </div>
        <div id="summary" class="summary">
            <h2>Summary</h2>
            <div id="summary-content"></div>
        </div>
    </div>
    <script>
        // Pagination settings
        const itemsPerPage = 50;
        let currentPage = 1;
        
        function createPaginatedSection(containerId, data, title) {
            const container = document.getElementById(containerId);
            const totalPages = Math.ceil(data.length / itemsPerPage);
            
            const pagination = document.createElement('div');
            pagination.className = 'pagination';
            for (let i = 1; i <= totalPages; i++) {
                const pageLink = document.createElement('a');
                pageLink.href = '#';
                pageLink.textContent = i;
                pageLink.onclick = (e) => {
                    e.preventDefault();
                    showPage(containerId, data, i);
                };
                pagination.appendChild(pageLink);
            }
            
            showPage(containerId, data, 1);
            container.appendChild(pagination);
        }
        
        function showPage(containerId, data, page) {
            const container = document.getElementById(containerId);
            const start = (page - 1) * itemsPerPage;
            const end = start + itemsPerPage;
            const pageData = data.slice(start, end);
            
            container.innerHTML = '';
            
            pageData.forEach(item => {
                const finding = document.createElement('div');
                finding.className = 'finding';
                finding.innerHTML = item;
                container.appendChild(finding);
            });
            
            const pagination = container.nextElementSibling;
            if (pagination) {
                const links = pagination.getElementsByTagName('a');
                for (let link of links) {
                    link.classList.remove('active');
                    if (parseInt(link.textContent) === page) {
                        link.classList.add('active');
                    }
                }
            }
        }
    </script>
</body>
</html>
EOF

    [ -f "$RESULTS_DIR/subdomains.txt" ] && generate_section_report "subdomains" "$RESULTS_DIR/subdomains.txt" "$output_dir"
    [ -f "$RESULTS_DIR/vulnerabilities/nuclei_results.txt" ] && generate_section_report "vulnerabilities" "$RESULTS_DIR/vulnerabilities/nuclei_results.txt" "$output_dir"
    [ -f "$RESULTS_DIR/xss_results.txt" ] && generate_section_report "xss" "$RESULTS_DIR/xss_results.txt" "$output_dir"
    [ -f "$RESULTS_DIR/content/interesting_files.txt" ] && generate_section_report "content" "$RESULTS_DIR/content/interesting_files.txt" "$output_dir"
    [ -f "$RESULTS_DIR/fuzzing/api_endpoints.txt" ] && generate_section_report "fuzzing" "$RESULTS_DIR/fuzzing/api_endpoints.txt" "$output_dir"
    update_summary "$output_dir"
    
    log "SUCCESS" "HTML report generated at $output_dir/index.html"
}

generate_section_report() {
    local section=$1
    local input_file=$2
    local output_dir=$3
    
    if [ -f "$input_file" ] && [ -s "$input_file" ]; then
        local count=$(wc -l < "$input_file" 2>/dev/null || echo "0")
        local output_file="$output_dir/${section}.html"
        cat > "$output_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Report - Recon Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .section { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .finding { border-left: 4px solid #3498db; padding: 10px; margin: 10px 0; background: #f8f9fa; word-break: break-all; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; font-size: 12px; }
        h2 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="section">
EOF
        
        echo "<h2>${section^} Results</h2>" >> "$output_file"
        echo "<p><strong>Total findings: $count</strong></p>" >> "$output_file"
        echo "<div id=\"findings\">" >> "$output_file"
        while IFS= read -r line; do
            line=$(printf '%s\n' "$line" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g; s/'\''/\&#39;/g')
            echo "<div class='finding'><pre>$line</pre></div>" >> "$output_file"
        done < "$input_file"
        cat >> "$output_file" << 'EOF'
        </div>
    </div>
</body>
</html>
EOF
        log "INFO" "Generated $section report"
    fi
}

update_summary() {
    local output_dir=$1
    local summary_file="$output_dir/summary.html"
    local subdomain_count=$(wc -l < "$RESULTS_DIR/subdomains.txt" 2>/dev/null || echo "0")
    local vuln_count=$(wc -l < "$RESULTS_DIR/vulnerabilities/nuclei_results.txt" 2>/dev/null || echo "0")
    local xss_count=$(wc -l < "$RESULTS_DIR/xss_results.txt" 2>/dev/null || echo "0")
    local content_count=$(wc -l < "$RESULTS_DIR/content/interesting_files.txt" 2>/dev/null || echo "0")
    local fuzzing_count=$(wc -l < "$RESULTS_DIR/fuzzing/api_endpoints.txt" 2>/dev/null || echo "0")
    cat > "$summary_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Summary - $TARGET</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; }
        .summary { background: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stat { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
        .stat h3 { margin: 0; color: #2c3e50; }
        .stat p { margin: 5px 0 0; font-size: 24px; color: #3498db; }
    </style>
</head>
<body>
    <div class="container">
        <div class="summary">
            <h2>Summary</h2>
            <div class="stat">
                <h3>Subdomains</h3>
                <p>$subdomain_count</p>
            </div>
            <div class="stat">
                <h3>Vulnerabilities</h3>
                <p>$vuln_count</p>
            </div>
            <div class="stat">
                <h3>XSS Findings</h3>
                <p>$xss_count</p>
            </div>
            <div class="stat">
                <h3>Interesting Files</h3>
                <p>$content_count</p>
            </div>
            <div class="stat">
                <h3>API Endpoints</h3>
                <p>$fuzzing_count</p>
            </div>
        </div>
    </div>
</body>
</html>
EOF
}

log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ ! -f "$LOG_FILE" ]; then
        touch "$LOG_FILE"
    fi
    
    echo -e "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

check_dependencies() {
    local missing_deps=()
    
    for cmd in go curl wget git; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [ ${#missing_deps[@]} -ne 0 ]; then
        log "ERROR" "Missing dependencies: ${missing_deps[*]}"
        return 1
    fi
    return 0
}

setup_environment() {
    RESULTS_DIR="$TARGET_DIR/results"
    TOOLS_DIR="$TARGET_DIR/tools"
    LOG_FILE="$TARGET_DIR/recon.log"
    
    mkdir -p "$RESULTS_DIR" "$TOOLS_DIR" \
             "$RESULTS_DIR/vulnerabilities" \
             "$RESULTS_DIR/content" \
             "$RESULTS_DIR/fuzzing" \
             "$RESULTS_DIR/parameters" \
             "$RESULTS_DIR/screenshots" \
             "$RESULTS_DIR/report"
    
    echo "=== Recon Session Started at $(date) ===" > "$LOG_FILE"
    log "INFO" "Target: $TARGET"
    log "INFO" "Results directory: $RESULTS_DIR"
    log "INFO" "Log file: $LOG_FILE"
}

install_go_tool() {
    local tool_name=$1
    local repo_path=$2
    
    log "INFO" "Installing $tool_name..."
    
    if command -v "$tool_name" &> /dev/null; then
        log "INFO" "$tool_name is already installed"
        return 0
    fi
    
    if go install "${repo_path}@latest" 2>> "$LOG_FILE"; then
        log "SUCCESS" "$tool_name installed successfully"
        return 0
    else
        log "WARNING" "Standard installation failed for $tool_name"
        return 1
    fi
}

install_python_tool() {
    local tool_name=$1
    local package_name=$2    if command -v "$tool_name" &> /dev/null; then
        log "INFO" "$tool_name is already installed"
        return 0
    fi
    
    if pip3 install "$package_name" >> "$LOG_FILE" 2>&1; then
        log "SUCCESS" "$tool_name installed successfully"
        return 0
    else
        log "WARNING" "Failed to install $tool_name"
        return 1
    fi
}

install_git_tool() {
    local tool_name=$1
    local repo_url=$2
    local install_cmd=$3
    
    log "INFO" "Installing from git: $tool_name"
    
    if [ -d "$TOOLS_DIR/$tool_name" ]; then
        log "INFO" "$tool_name already cloned, updating..."
        cd "$TOOLS_DIR/$tool_name" && git pull >> "$LOG_FILE" 2>&1 && cd - > /dev/null
        return 0
    fi
    
    if git clone "$repo_url" "$TOOLS_DIR/$tool_name" >> "$LOG_FILE" 2>&1; then
        cd "$TOOLS_DIR/$tool_name" && eval "$install_cmd" >> "$LOG_FILE" 2>&1 && cd - > /dev/null
        log "SUCCESS" "$tool_name installed successfully"
        return 0
    else
        log "WARNING" "Failed to install $tool_name"
        return 1
    fi
}

install_tools() {
    log "INFO" "Starting tools installation"
    
    if ! check_dependencies; then
        log "ERROR" "Missing required dependencies"
        exit 1
    fi
    
    export PATH=$PATH:$(go env GOPATH)/bin
    export GOPATH=$(go env GOPATH)
    
    for tool in "${!TOOLS[@]}"; do
        install_go_tool "$tool" "${TOOLS[$tool]}" || true
    done
    
    install_python_tool "arjun" "arjun" || true
    
    log "SUCCESS" "Tool installation phase completed"
}

find_subdomains() {
    local output_file="$RESULTS_DIR/subdomains.txt"
    log "INFO" "Starting subdomain enumeration"
    
    {
        command -v subfinder &>/dev/null && subfinder -d "$TARGET" -silent 2>/dev/null || true
        command -v assetfinder &>/dev/null && assetfinder "$TARGET" 2>/dev/null || true
        command -v findomain &>/dev/null && findomain -t "$TARGET" -q 2>/dev/null || true
    } | grep -v "^$" | sort -u > "$output_file"
    
    local count=$(wc -l < "$output_file")
    log "SUCCESS" "Found $count subdomains"
}

find_live_hosts() {
    local input_file="$RESULTS_DIR/subdomains.txt"
    local output_file="$RESULTS_DIR/live_hosts.txt"
    
    log "INFO" "Finding live hosts"
    
    if command -v httpx &> /dev/null; then
        cat "$input_file" | httpx -silent -threads 50 -status-code -title -tech-detect -o "$output_file" 2>/dev/null || true
    else
        log "WARNING" "httpx not installed, using curl-based host discovery"
        cat "$input_file" | while read -r host; do
            if timeout 5 curl -s -o /dev/null -w "%{http_code}" "http://$host" 2>/dev/null | grep -q "200\|301\|302"; then
                echo "http://$host" >> "$output_file"
            fi
            if timeout 5 curl -s -o /dev/null -w "%{http_code}" "https://$host" 2>/dev/null | grep -q "200\|301\|302"; then
                echo "https://$host" >> "$output_file"
            fi
        done
    fi
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Found $count live hosts"
}

xss_scan() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_file="$RESULTS_DIR/xss_results.txt"
    
    log "INFO" "Starting XSS scan"
    
    {
        cat "$input_file" | while read -r host; do
            gau "$host" 2>/dev/null | grep "=" || true
            waybackurls "$host" 2>/dev/null | grep "=" || true
        done
    } | sort -u > "$RESULTS_DIR/urls_with_params.txt"
    
    if command -v dalfox &> /dev/null; then
        log "INFO" "Running dalfox XSS scanner"
        cat "$RESULTS_DIR/urls_with_params.txt" | \
        xargs -I@ -P "$CONCURRENT_SCANS" sh -c 'timeout 10 dalfox url "@" --silence 2>&1' | \
        grep -v "^$" > "$output_file" 2>/dev/null || true
    else
        log "WARNING" "dalfox not installed, skipping XSS scan"
        touch "$output_file"
    fi
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Found $count potential XSS vulnerabilities"
}

vulnerability_scan() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/vulnerabilities"
    
    mkdir -p "$output_dir"
    log "INFO" "Starting vulnerability scan with Nuclei"
    
    if command -v nuclei &> /dev/null; then
        nuclei -l "$input_file" \
            -severity critical,high,medium \
            -o "$output_dir/nuclei_results.txt" \
            -silent 2>/dev/null || true
    else
        log "WARNING" "Nuclei not installed, skipping vulnerability scan"
        touch "$output_dir/nuclei_results.txt"
    fi
    
    log "SUCCESS" "Vulnerability scan completed"
}

content_discovery() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/content"
    
    mkdir -p "$output_dir"
    log "INFO" "Starting content discovery"
    
    cat "$input_file" | while read -r host; do
        gau "$host" 2>/dev/null | sort -u
        waybackurls "$host" 2>/dev/null | sort -u
    done | sort -u > "$output_dir/all_urls.txt"
    
    grep -i "\.js$" "$output_dir/all_urls.txt" > "$output_dir/js_files.txt" 2>/dev/null || true
    
    grep -iE "\.(php|asp|aspx|jsp|xml|json|txt|sql|bak|old)$" "$output_dir/all_urls.txt" > "$output_dir/interesting_files.txt" 2>/dev/null || true
    
    local url_count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo "0")
    log "SUCCESS" "Content discovery completed - Found $url_count URLs"
}

take_screenshots() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/screenshots"
    
    mkdir -p "$output_dir"
    log "INFO" "Taking screenshots"
    
    if command -v gowitness &> /dev/null; then
        gowitness file -f "$input_file" --destination "$output_dir"
        log "SUCCESS" "Screenshots completed"
    else
        log "WARNING" "gowitness not installed, skipping screenshots"
    fi
}

run_all_scans() {
    log "INFO" "Starting comprehensive recon"
    
    if [ "$DISCORD_ENABLED" = true ]; then
        send_discord_message "Starting comprehensive recon for $TARGET" "3447003" "Recon Started"
    fi
    
    find_subdomains || log "WARNING" "Subdomain enumeration failed"
    find_live_hosts || log "WARNING" "Live host discovery failed"
    xss_scan || log "WARNING" "XSS scan failed"
    vulnerability_scan || log "WARNING" "Vulnerability scan failed"
    content_discovery || log "WARNING" "Content discovery failed"
    take_screenshots || log "WARNING" "Screenshot capture failed"
    
    generate_html_report || log "WARNING" "Report generation failed"
    
    if [ "$DISCORD_ENABLED" = true ] && [ -f "$RESULTS_DIR/report/index.html" ]; then
        send_discord_file "$RESULTS_DIR/report/index.html" "Final Recon Report for $TARGET" || true
    fi
    
    log "SUCCESS" "All scans completed and report generated"
    echo -e "\n${GREEN}Results saved to: $RESULTS_DIR${NC}\n"
}

display_title() {
    clear
    echo -e "${PURPLE}"
    cat << "EOF"
  ____  *             *      _____                      
 |  * \| |           | |    |  *_ \                    
 | |_) | | ** ***** *** | | ** | |**) |___  ___ ___  * *_  
 |  * <| |/ *` | '_ \| |/ / |  *  // * \/ __/ * \| '* \
 | |_) | | (_| | | | |   <  | | \ \  __/ (_| (_) | | | |
 |____/|_|\__,_|_| |_|_|\_\ |_|  \_\___|\___\___/|_| |_|
EOF
    echo -e "${NC}"
}

display_menu() {
    echo -e "\n${PURPLE}Advanced Recon Menu:${NC}"
    echo "1. Advanced Subdomain Enumeration"
    echo "2. Find Live Hosts"
    echo "3. Advanced Parameter Discovery"
    echo "4. Advanced XSS Scan"
    echo "5. Advanced Vulnerability Scan"
    echo "6. Advanced Content Discovery"
    echo "7. Advanced Fuzzing"
    echo "8. Take Screenshots"
    echo "9. Run ALL Scans"
    echo "0. Exit"
}

setup_target() {
    read -p "Enter target domain (without http/https): " TARGET
    TARGET_DIR="$(pwd)/recon_$TARGET"
    mkdir -p "$TARGET_DIR"
    cd "$TARGET_DIR" || exit
    echo "$TARGET" > target.txt
    
    setup_environment
    
    log "INFO" "Created target directory: $TARGET_DIR"
}

setup_discord() {
    read -p "Do you want to enable Discord notifications? (y/n): " enable_discord
    if [[ $enable_discord == "y" || $enable_discord == "Y" ]]; then
        read -p "Enter Discord webhook URL: " webhook_url
        if [[ -n $webhook_url ]]; then
            DISCORD_WEBHOOK_URL=$webhook_url
            DISCORD_ENABLED=true
            log "INFO" "Discord notifications enabled"
        else
            log "WARNING" "Invalid webhook URL, Discord notifications disabled"
        fi
    fi
}

send_discord_message() {
    local message=$1
    local color=$2
    local title=$3
    
    if [ "$DISCORD_ENABLED" = true ]; then
        local json_payload=$(cat <<EOF
{
    "embeds": [{
        "title": "$title",
        "description": "$message",
        "color": $color,
        "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    }]
}
EOF
)
        curl -s -H "Content-Type: application/json" -X POST -d "$json_payload" "$DISCORD_WEBHOOK_URL"
    fi
}

send_discord_file() {
    local file_path=$1
    local title=$2
    
    if [ "$DISCORD_ENABLED" = true ]; then
        curl -s -F "file=@$file_path" -F "content=$title" "$DISCORD_WEBHOOK_URL"
    fi
}

main() {
    display_title
    
    if ! check_dependencies; then
        log "ERROR" "Missing critical dependencies. Please install curl, wget, git, and go"
        exit 1
    fi
    
    log "INFO" "Checking and installing tools..."
    install_tools
    
    setup_target
    setup_discord

    while true; do
        display_menu
        read -p "Enter your choice: " choice
        
        case $choice in
            1) advanced_subdomain_enum ;;
            2) find_live_hosts ;;
            3) advanced_parameter_discovery ;;
            4) advanced_xss_scan ;;
            5) advanced_vulnerability_scan ;;
            6) advanced_content_discovery ;;
            7) advanced_fuzzing ;;
            8) take_screenshots ;;
            9) run_all_scans ;;
            0) 
                log "INFO" "Exiting..."
                exit 0 
                ;;
            *) 
                log "WARNING" "Invalid option selected"
                ;;
        esac
        
        read -p "Press Enter to continue..." 
    done
}

trap 'log "ERROR" "Script interrupted by user"; exit 1' INT TERM

main

advanced_subdomain_enum() {
    local output_file="$RESULTS_DIR/subdomains.txt"
    log "INFO" "Starting advanced subdomain enumeration"
    {
        command -v subfinder &>/dev/null && subfinder -d "$TARGET" -silent 2>/dev/null || true
        command -v assetfinder &>/dev/null && assetfinder "$TARGET" 2>/dev/null || true
        command -v findomain &>/dev/null && findomain -t "$TARGET" -q 2>/dev/null || true
        waybackurls "$TARGET" 2>/dev/null | grep -E "\.$TARGET" | cut -d'/' -f3 | sort -u || true
        gau "$TARGET" 2>/dev/null | grep -E "\.$TARGET" | cut -d'/' -f3 | sort -u || true
    } | grep -v "^$" | sort -u > "$output_file"
    
    log "INFO" "Performing subdomain permutations"
    {
        cat "$output_file"
        cat "$output_file" | while read -r subdomain; do
            echo "dev-$subdomain"
            echo "staging-$subdomain"
            echo "test-$subdomain"
            echo "api-$subdomain"
            echo "admin-$subdomain"
            echo "internal-$subdomain"
            echo "prod-$subdomain"
            echo "cdn-$subdomain"
            echo "www-$subdomain"
            echo "mail-$subdomain"
        done
    } | sort -u > "${output_file}.tmp" && mv "${output_file}.tmp" "$output_file"
    
    local count=$(wc -l < "$output_file")
    log "SUCCESS" "Found $count subdomains"
    
    if [ "$count" -gt 0 ] && [ "$DISCORD_ENABLED" = true ]; then
        send_discord_message "Found $count subdomains for $TARGET\n\nFirst 10 subdomains:\n$(head -n 10 $output_file)" "3447003" "Subdomain Discovery Results"
    fi
}

advanced_parameter_discovery() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/parameters"
    
    mkdir -p "$output_dir"
    log "INFO" "Starting advanced parameter discovery"
    
    {
        cat "$input_file" | while read -r host; do
            gau "$host" 2>/dev/null | grep -o "?[^=]*=" | sort -u
            waybackurls "$host" 2>/dev/null | grep -o "?[^=]*=" | sort -u
        done
    } | sort -u > "$output_dir/all_parameters.txt"    # Try arjun if available
    if command -v arjun &> /dev/null; then
        log "INFO" "Running Arjun for parameter discovery"
        cat "$input_file" | xargs -I@ -P "$CONCURRENT_SCANS" arjun -u @ -q >> "$output_dir/all_parameters.txt" 2>/dev/null || true
    fi
    
    local param_count=$(wc -l < "$output_dir/all_parameters.txt" 2>/dev/null || echo "0")
    log "SUCCESS" "Parameter discovery completed - Found $param_count parameters"
}

advanced_xss_scan() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_file="$RESULTS_DIR/xss_results.txt"
    
    log "INFO" "Starting advanced XSS scan"
    
    {
        cat "$input_file" | while read -r host; do
            gau "$host" 2>/dev/null | grep "="
            waybackurls "$host" 2>/dev/null | grep "="
        done
    } | sort -u > "$RESULTS_DIR/urls_with_params.txt"
    
    if command -v dalfox &> /dev/null; then
        log "INFO" "Running dalfox XSS scanner"
        cat "$RESULTS_DIR/urls_with_params.txt" | \
        xargs -I@ -P "$CONCURRENT_SCANS" sh -c 'timeout 10 dalfox url "@" --silence 2>&1' | \
        grep -v "^$" > "$output_file" 2>/dev/null || true
    else
        log "WARNING" "dalfox not installed, skipping XSS scan"
        touch "$output_file"
    fi
    
    local count=$(wc -l < "$output_file" 2>/dev/null || echo "0")
    log "SUCCESS" "Found $count potential XSS vulnerabilities"
    
    if [ "$count" -gt 0 ] && [ "$DISCORD_ENABLED" = true ]; then
        send_discord_message "Found $count potential XSS vulnerabilities for $TARGET\n\nFirst 5 findings:\n$(head -n 5 $output_file)" "15158332" "XSS Scan Results"
    fi
}

advanced_vulnerability_scan() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/vulnerabilities"
    
    mkdir -p "$output_dir"
    log "INFO" "Starting advanced vulnerability scan"
    
    if command -v nuclei &> /dev/null; then
        log "INFO" "Running Nuclei vulnerability scanner"
        nuclei -l "$input_file" \
            -severity critical,high,medium \
            -o "$output_dir/nuclei_results.txt" \
            -silent 2>/dev/null || true
    else
        log "WARNING" "Nuclei not installed, skipping vulnerability scan"
        touch "$output_dir/nuclei_results.txt"
    fi
    
    if command -v crlfuzz &> /dev/null; then
        log "INFO" "Running CRLF injection scan"
        crlfuzz -l "$input_file" -o "$output_dir/crlf_results.txt" 2>/dev/null || true
    fi
    
    log "SUCCESS" "Advanced vulnerability scan completed"
    
    if [ -f "$output_dir/nuclei_results.txt" ]; then
        local vuln_count=$(wc -l < "$output_dir/nuclei_results.txt" 2>/dev/null || echo "0")
        if [ "$vuln_count" -gt 0 ] && [ "$DISCORD_ENABLED" = true ]; then
            send_discord_message "Found $vuln_count vulnerabilities for $TARGET\n\nFirst 5 findings:\n$(head -n 5 $output_dir/nuclei_results.txt)" "15158332" "Vulnerability Scan Results"
        fi
    fi
}

advanced_content_discovery() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/content"
    
    mkdir -p "$output_dir"
    log "INFO" "Starting advanced content discovery"
    
    log "INFO" "Collecting URLs from multiple sources"
    {
        cat "$input_file" | while read -r host; do
            waybackurls "$host" 2>/dev/null
        done
        
        cat "$input_file" | while read -r host; do
            gau "$host" 2>/dev/null
        done
        
        if command -v gospider &> /dev/null; then
            cat "$input_file" | gospider -c 5 -d 3 2>/dev/null || true
        fi
    } | sort -u > "$output_dir/all_urls.txt"
    
    grep -iE "\.(php|asp|aspx|jsp|js|json|xml|txt|pdf|doc|docx|xls|xlsx|zip|rar|tar|gz|sql|bak|old|backup|config|env|keys|pem|crt)$" "$output_dir/all_urls.txt" > "$output_dir/interesting_files.txt" 2>/dev/null || true
    
    grep -i "\.js$" "$output_dir/all_urls.txt" > "$output_dir/js_files.txt" 2>/dev/null || true
    
    if [ -s "$output_dir/js_files.txt" ]; then
        log "INFO" "Analyzing JS files for secrets"
        while IFS= read -r js_file; do
            curl -s -k -m 10 "$js_file" 2>/dev/null | grep -iE "api[_-]?key|secret|token|password|client[_-]?id|client[_-]?secret|authorization|bearer|aws[_-]?|gcp[_-]?|firebase" >> "$output_dir/js_secrets.txt" 2>/dev/null || true
        done < "$output_dir/js_files.txt"
    fi
    
    local url_count=$(wc -l < "$output_dir/all_urls.txt" 2>/dev/null || echo "0")
    log "SUCCESS" "Advanced content discovery completed - Found $url_count URLs"
}

advanced_fuzzing() {
    local input_file="$RESULTS_DIR/live_hosts.txt"
    local output_dir="$RESULTS_DIR/fuzzing"
    
    mkdir -p "$output_dir"
    log "INFO" "Starting advanced fuzzing"
    local wordlist=""
    if [ -f "/usr/share/wordlists/dirb/common.txt" ]; then
        wordlist="/usr/share/wordlists/dirb/common.txt"
    elif [ -f "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt" ]; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
    elif [ -f "/usr/share/seclists/Discovery/Web-Content/common.txt" ]; then
        wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
    else
        log "WARNING" "No suitable wordlist found for fuzzing"
        return 1
    fi
    if command -v ffuf &> /dev/null; then
        log "INFO" "Running ffuf directory fuzzing"
        cat "$input_file" | while read -r url; do
            ffuf -u "${url}/FUZZ" -w "$wordlist" -mc 200,204,301,302,307,401,403 -o "$output_dir/ffuf_$(echo ${url##*/} | tr -d ':')_results.json" -of json 2>/dev/null || true
        done
    fi
    log "INFO" "Discovering API endpoints"
    cat "$input_file" | while read -r url; do
        for endpoint in "api" "v1" "v2" "rest" "graphql" "swagger" "docs" "admin" "dev" "test" "staging" ".well-known"; do
            curl -s -k -m 5 "${url}/${endpoint}" 2>/dev/null | grep -iq "api\|swagger\|graphql\|rest" && echo "${url}/${endpoint}" >> "$output_dir/api_endpoints.txt"
        done
    done 2>/dev/null || true
    
    log "SUCCESS" "Advanced fuzzing completed"
}