#!/bin/bash

PURPLE='\033[0;35m'
BLUE='\033[0;34m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' 

TARGET_DIR=""
TARGET=""
START_TIME=$(date +%s)

display_title() {
    echo -e "${PURPLE}"
    cat << "EOF" 

  ____  _             _      _____                      
 |  _ \| |           | |    |  __ \                     
 | |_) | | __ _ _ __ | | __ | |__) |___  ___ ___  _ __  
 |  _ <| |/ _` | '_ \| |/ / |  _  // _ \/ __/ _ \| '_ \ 
 | |_) | | (_| | | | |   <  | | \ \  __/ (_| (_) | | | |
 |____/|_|\__,_|_| |_|_|\_\ |_|  \_\___|\___\___/|_| |_|
                                                        
                                                                            
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}=== Comprehensive Reconnaissance & Vulnerability Scanner ===${NC}"
    echo -e "${BLUE}Made by: HappyCPPD ${NC}"
    echo
}

log_message() {
    local level=$1
    local message=$2
    local color=$GREEN
    
    case $level in
        "INFO") color=$GREEN ;;
        "WARN") color=$YELLOW ;;
        "ERROR") color=$RED ;;
        "SUCCESS") color=$CYAN ;;
    esac
    
    echo -e "[$(date +"%Y-%m-%d %H:%M:%S")] ${color}[$level]${NC} $message"
}

setup_target_dir() {
    echo
    read -p "Enter target domain (without http/https): " TARGET
    
    if [[ -z "$TARGET" ]]; then
        log_message "ERROR" "Target domain cannot be empty."
        setup_target_dir
        return
    fi
    
    TARGET_DIR="$(pwd)/recon_$TARGET"
    mkdir -p "$TARGET_DIR"
    mkdir -p "$TARGET_DIR/subdomains"
    mkdir -p "$TARGET_DIR/endpoints"
    mkdir -p "$TARGET_DIR/vulnerabilities"
    mkdir -p "$TARGET_DIR/screenshots"
    mkdir -p "$TARGET_DIR/reports"
    
    cd "$TARGET_DIR" || exit
    echo "$TARGET" > target.txt
    
    log_message "SUCCESS" "Created target directory: $TARGET_DIR"
    echo
}

install_system_packages() {
    log_message "INFO" "Checking for required system packages..."
    
    packages=(lolcat jq golang-go python3-pip)
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q $package; then
            log_message "INFO" "Installing $package..."
            sudo apt-get update && sudo apt-get install -y $package
        fi
    done
    
    if [[ ! "$PATH" == *"$HOME/go/bin"* ]]; then
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        export PATH=$PATH:$HOME/go/bin
    fi
}

install_tools() {
    log_message "INFO" "Checking and installing required tools..."
    
    declare -A tool_sources=(
        ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        ["httpx"]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
        ["findomain"]="curl -LO https://github.com/Findomain/Findomain/releases/latest/download/findomain-linux && chmod +x findomain-linux && sudo mv findomain-linux /usr/local/bin/findomain"
        ["waybackurls"]="go install -v github.com/tomnomnom/waybackurls@latest"
        ["gf"]="go install -v github.com/tomnomnom/gf@latest"
        ["sqlmap"]="pip3 install sqlmap"
        ["gau"]="go install -v github.com/lc/gau/v2/cmd/gau@latest"
        ["qsreplace"]="go install -v github.com/tomnomnom/qsreplace@latest"
        ["dalfox"]="go install -v github.com/hahwul/dalfox/v2@latest"
        ["anew"]="go install -v github.com/tomnomnom/anew@latest"
        ["assetfinder"]="go install -v github.com/tomnomnom/assetfinder@latest"
        ["page-fetch"]="go install -v github.com/detectify/page-fetch@latest"
        ["gowitness"]="go install -v github.com/sensepost/gowitness@latest"
        ["haktrails"]="go install -v github.com/hakluke/haktrails@latest"
        ["tojson"]="go install -v github.com/tomnomnom/hacks/tojson@latest"
        ["html-tool"]="go install -v github.com/tomnomnom/hacks/html-tool@latest"
        ["jq"]="sudo apt-get install -y jq"
    )
    
    for tool in "${!tool_sources[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_message "INFO" "Installing $tool..."
            eval "${tool_sources[$tool]}" 2>/dev/null || log_message "ERROR" "Failed to install $tool"
        else
            log_message "INFO" "$tool is already installed."
        fi
    done
    
    if command -v gf &> /dev/null && [ ! -d "$HOME/.gf" ]; then
        log_message "INFO" "Setting up GF patterns..."
        mkdir -p "$HOME/.gf"
        git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf/Gf-Patterns
        cp ~/.gf/Gf-Patterns/*.json ~/.gf/
    fi
    
    log_message "SUCCESS" "Tool installation completed."
}

progress_monitor() {
    local pid=$1
    local message=$2
    local start_time=$(date +%s)
    
    echo -ne "${YELLOW}$message... ${NC}"
    
    while kill -0 $pid 2>/dev/null; do
        local elapsed=$(($(date +%s) - start_time))
        local mins=$((elapsed / 60))
        local secs=$((elapsed % 60))
        echo -ne "\r${YELLOW}$message... (Elapsed: ${mins}m ${secs}s) ${NC}"
        sleep 2
    done
    
    local total_elapsed=$(($(date +%s) - start_time))
    local total_mins=$((total_elapsed / 60))
    local total_secs=$((total_elapsed % 60))
    echo -e "\r${GREEN}$message... Completed (Took: ${total_mins}m ${total_secs}s) ${NC}"
}

enumerate_subdomains() {
    log_message "INFO" "Starting subdomain enumeration for $TARGET..."
    
    log_message "INFO" "Running subfinder..."
    subfinder -d "$TARGET" -silent > "$TARGET_DIR/subdomains/subfinder_results.txt" &
    subfinder_pid=$!
    progress_monitor $subfinder_pid "Subfinder scanning"
    
    if command -v findomain &> /dev/null; then
        log_message "INFO" "Running findomain..."
        findomain -t "$TARGET" -q > "$TARGET_DIR/subdomains/findomain_results.txt" &
        findomain_pid=$!
        progress_monitor $findomain_pid "Findomain scanning"
    fi
    
    log_message "INFO" "Running assetfinder..."
    assetfinder --subs-only "$TARGET" > "$TARGET_DIR/subdomains/assetfinder_results.txt" &
    assetfinder_pid=$!
    progress_monitor $assetfinder_pid "Assetfinder scanning"

    log_message "INFO" "Combining subdomain results..."
    cat "$TARGET_DIR/subdomains/"*_results.txt | sort -u > "$TARGET_DIR/subdomains/all_subdomains.txt"
    
    local count=$(wc -l < "$TARGET_DIR/subdomains/all_subdomains.txt")
    log_message "SUCCESS" "Found $count unique subdomains. Results saved to $TARGET_DIR/subdomains/all_subdomains.txt"
}

http_probe() {
    log_message "INFO" "Probing for live HTTP/HTTPS services..."
    
    cat "$TARGET_DIR/subdomains/all_subdomains.txt" | httpx -silent -threads 100 -status-code -title -follow-redirects -timeout 15 -o "$TARGET_DIR/subdomains/live_subdomains.txt" &
    httpx_pid=$!
    progress_monitor $httpx_pid "HTTP probing with httpx"
    
    local count=$(wc -l < "$TARGET_DIR/subdomains/live_subdomains.txt")
    log_message "SUCCESS" "Found $count live HTTP services. Results saved to $TARGET_DIR/subdomains/live_subdomains.txt"
}

fetch_urls() {
    log_message "INFO" "Fetching URLs from various sources..."
    
    if [ ! -f "$TARGET_DIR/subdomains/live_subdomains.txt" ]; then
        log_message "ERROR" "No live subdomains found. Run HTTP probing first."
        return 1
    fi
    
    cut -d' ' -f1 "$TARGET_DIR/subdomains/live_subdomains.txt" > "$TARGET_DIR/subdomains/live_domains.txt"
    
    log_message "INFO" "Running waybackurls..."
    cat "$TARGET_DIR/subdomains/live_domains.txt" | waybackurls > "$TARGET_DIR/endpoints/wayback_urls.txt" &
    wayback_pid=$!
    progress_monitor $wayback_pid "Fetching from Wayback Machine"
    
    log_message "INFO" "Running gau..."
    cat "$TARGET_DIR/subdomains/live_domains.txt" | gau --threads 5 > "$TARGET_DIR/endpoints/gau_urls.txt" &
    gau_pid=$!
    progress_monitor $gau_pid "Fetching URLs with gau"
    
    log_message "INFO" "Combining URL results..."
    cat "$TARGET_DIR/endpoints/"*_urls.txt | sort -u > "$TARGET_DIR/endpoints/all_urls.txt"
    
    log_message "INFO" "Filtering URLs with parameters..."
    grep "?" "$TARGET_DIR/endpoints/all_urls.txt" > "$TARGET_DIR/endpoints/parameterized_urls.txt"
    
    local all_count=$(wc -l < "$TARGET_DIR/endpoints/all_urls.txt")
    local param_count=$(wc -l < "$TARGET_DIR/endpoints/parameterized_urls.txt")
    log_message "SUCCESS" "Found $all_count unique URLs, including $param_count with parameters."
}

take_screenshots() {
    log_message "INFO" "Taking screenshots of live websites..."
    
    if [ ! -f "$TARGET_DIR/subdomains/live_domains.txt" ]; then
        log_message "ERROR" "No live domains found. Run HTTP probing first."
        return 1
    fi
    
    gowitness file -f "$TARGET_DIR/subdomains/live_domains.txt" -P "$TARGET_DIR/screenshots" --no-http &
    gowitness_pid=$!
    progress_monitor $gowitness_pid "Taking screenshots with gowitness"
    
    log_message "SUCCESS" "Screenshots saved to $TARGET_DIR/screenshots directory."
}

scan_xss() {
    log_message "INFO" "Starting XSS vulnerability scanning..."
    
    if [ ! -f "$TARGET_DIR/endpoints/parameterized_urls.txt" ]; then
        log_message "ERROR" "No parameterized URLs found. Run URL fetching first."
        return 1
    fi
    
    head -n 100 "$TARGET_DIR/endpoints/parameterized_urls.txt" > "$TARGET_DIR/endpoints/xss_targets.txt"
    
    log_message "INFO" "Running dalfox XSS scanner on sampled URLs..."
    cat "$TARGET_DIR/endpoints/xss_targets.txt" | dalfox pipe -o "$TARGET_DIR/vulnerabilities/xss_results.txt" &
    dalfox_pid=$!
    progress_monitor $dalfox_pid "Scanning for XSS vulnerabilities"
    
    local vuln_count=$(grep -c "VULN" "$TARGET_DIR/vulnerabilities/xss_results.txt" || echo "0")
    log_message "SUCCESS" "XSS scanning complete. Found approximately $vuln_count potential vulnerabilities."
}

scan_sqli() {
    log_message "INFO" "Starting SQL Injection vulnerability scanning..."
    
    if [ ! -f "$TARGET_DIR/endpoints/parameterized_urls.txt" ]; then
        log_message "ERROR" "No parameterized URLs found. Run URL fetching first."
        return 1
    fi
    
    head -n 20 "$TARGET_DIR/endpoints/parameterized_urls.txt" > "$TARGET_DIR/endpoints/sqli_targets.txt"
    
    mkdir -p "$TARGET_DIR/vulnerabilities/sqlmap_output"
    
    log_message "INFO" "Running SQLMap on sampled URLs (this may take a while)..."
    
    while read -r url; do
        local domain=$(echo "$url" | awk -F/ '{print $3}' | tr '.' '_')
        log_message "INFO" "Testing $url for SQL injection..."
        
        sqlmap -u "$url" --batch --random-agent --level=1 --risk=1 --output-dir="$TARGET_DIR/vulnerabilities/sqlmap_output" --tamper=space2comment &
        sqlmap_pid=$!
        progress_monitor $sqlmap_pid "SQLMap scanning $domain"
    done < "$TARGET_DIR/endpoints/sqli_targets.txt"
    
    log_message "SUCCESS" "SQL Injection scanning complete. Results in $TARGET_DIR/vulnerabilities/sqlmap_output/"
}

run_pattern_matching() {
    log_message "INFO" "Running pattern matching with GF..."
    
    if [ ! -f "$TARGET_DIR/endpoints/all_urls.txt" ]; then
        log_message "ERROR" "No URLs found. Run URL fetching first."
        return 1
    fi
    
    mkdir -p "$TARGET_DIR/vulnerabilities/patterns"
    
    patterns=("xss" "ssrf" "redirect" "rce" "idor" "sqli" "lfi" "ssti")
    
    for pattern in "${patterns[@]}"; do
        log_message "INFO" "Searching for $pattern patterns..."
        cat "$TARGET_DIR/endpoints/all_urls.txt" | gf "$pattern" > "$TARGET_DIR/vulnerabilities/patterns/${pattern}_endpoints.txt" 2>/dev/null
        
        local count=$(wc -l < "$TARGET_DIR/vulnerabilities/patterns/${pattern}_endpoints.txt" || echo "0")
        log_message "INFO" "Found $count potential $pattern endpoints."
    done
    
    log_message "SUCCESS" "Pattern matching complete. Results in $TARGET_DIR/vulnerabilities/patterns/"
}

generate_report() {
    log_message "INFO" "Generating comprehensive report..."
    
    local report_file="$TARGET_DIR/reports/recon_report_$(date +%Y%m%d_%H%M%S).md"
    
    local end_time=$(date +%s)
    local total_time=$((end_time - START_TIME))
    local hours=$((total_time / 3600))
    local minutes=$(( (total_time % 3600) / 60 ))
    local seconds=$((total_time % 60))
    
    local subdomains_count=$(wc -l < "$TARGET_DIR/subdomains/all_subdomains.txt" 2>/dev/null || echo "0")
    local live_subdomains_count=$(wc -l < "$TARGET_DIR/subdomains/live_subdomains.txt" 2>/dev/null || echo "0")
    local urls_count=$(wc -l < "$TARGET_DIR/endpoints/all_urls.txt" 2>/dev/null || echo "0")
    local param_urls_count=$(wc -l < "$TARGET_DIR/endpoints/parameterized_urls.txt" 2>/dev/null || echo "0")
    
    cat << EOL > "$report_file"
# Reconnaissance Report for $TARGET
**Date**: $(date '+%Y-%m-%d %H:%M:%S')
**Target**: $TARGET
**Total Execution Time**: ${hours}h ${minutes}m ${seconds}s

## Summary
- Total Subdomains Found: $subdomains_count
- Live HTTP Services: $live_subdomains_count
- Total URLs Discovered: $urls_count
- URLs with Parameters: $param_urls_count

## Subdomain Enumeration Results
EOL

    if [ -f "$TARGET_DIR/subdomains/live_subdomains.txt" ]; then
        echo -e "\n### Top 10 Live Subdomains\n" >> "$report_file"
        head -n 10 "$TARGET_DIR/subdomains/live_subdomains.txt" | while read -r line; do
            echo "- \`$line\`" >> "$report_file"
        done
    fi
    
    echo -e "\n## Potential Vulnerabilities\n" >> "$report_file"
    
    if [ -f "$TARGET_DIR/vulnerabilities/xss_results.txt" ]; then
        local xss_count=$(grep -c "VULN" "$TARGET_DIR/vulnerabilities/xss_results.txt" || echo "0")
        echo "### XSS Vulnerabilities" >> "$report_file"
        echo "- Total Potential XSS Issues: $xss_count" >> "$report_file"
        
        if [ "$xss_count" -gt 0 ]; then
            echo -e "\n#### Sample XSS Vulnerable Endpoints\n" >> "$report_file"
            grep "VULN" "$TARGET_DIR/vulnerabilities/xss_results.txt" | head -n 5 | while read -r line; do
                echo "- \`$line\`" >> "$report_file"
            done
        fi
    fi
    
    echo -e "\n### Pattern Matching Results\n" >> "$report_file"
    
    patterns=("xss" "ssrf" "redirect" "rce" "idor" "sqli" "lfi" "ssti")
    
    for pattern in "${patterns[@]}"; do
        if [ -f "$TARGET_DIR/vulnerabilities/patterns/${pattern}_endpoints.txt" ]; then
            local pattern_count=$(wc -l < "$TARGET_DIR/vulnerabilities/patterns/${pattern}_endpoints.txt" || echo "0")
            echo "- $pattern (potential): $pattern_count endpoints" >> "$report_file"
        fi
    done
    
    echo -e "\n## Visual Reconnaissance\n" >> "$report_file"
    local screenshot_count=$(find "$TARGET_DIR/screenshots" -type f -name "*.png" | wc -l || echo "0")
    echo "- Total Screenshots Captured: $screenshot_count" >> "$report_file"
    echo "- Screenshots are stored in the \`screenshots\` directory." >> "$report_file"
    
    cat << EOL >> "$report_file"

## Next Steps
1. Manually verify the potential vulnerabilities
2. Explore the identified endpoints with parameters
3. Review the pattern matching results for security issues
4. Check the screenshots for any visual clues or sensitive information

## Disclaimer
This report was automatically generated by the Recon & Vulnerability Scanner script.
The results should be manually verified before drawing conclusions.
EOL
    
    log_message "SUCCESS" "Report generated: $report_file"
}

display_menu() {
    echo
    echo -e "${BLUE}=== RECONNAISSANCE MENU ===${NC}"
    echo -e "${YELLOW}1.${NC} Setup Target"
    echo -e "${YELLOW}2.${NC} Install Required Tools"
    echo -e "${YELLOW}3.${NC} Enumerate Subdomains"
    echo -e "${YELLOW}4.${NC} HTTP Probe (Find Live Services)"
    echo -e "${YELLOW}5.${NC} Fetch URLs (Wayback + GAU)"
    echo -e "${YELLOW}6.${NC} Take Screenshots of Live Websites"
    echo -e "${YELLOW}7.${NC} Run XSS Vulnerability Scan"
    echo -e "${YELLOW}8.${NC} Run SQL Injection Scan"
    echo -e "${YELLOW}9.${NC} Run Pattern Matching (GF)"
    echo -e "${YELLOW}10.${NC} Generate Report"
    echo -e "${YELLOW}11.${NC} Run Full Reconnaissance (All Steps)"
    echo -e "${YELLOW}0.${NC} Exit"
    echo
}

run_full_recon() {
    START_TIME=$(date +%s)
    setup_target_dir
    install_system_packages
    install_tools
    enumerate_subdomains
    http_probe
    fetch_urls
    take_screenshots
    run_pattern_matching
    scan_xss
    scan_sqli
    generate_report
    
    log_message "SUCCESS" "Full reconnaissance completed!"
}

main() {
    clear
    display_title
    
    install_system_packages
    
    if ! command -v lolcat &> /dev/null; then
        log_message "WARN" "lolcat not installed. Using regular output."
    fi
    
    while true; do
        display_menu
        
        read -p "$(echo -e "${PURPLE}Enter your choice: ${NC}")" choice
        
        case $choice in
            1) setup_target_dir ;;
            2) install_tools ;;
            3) enumerate_subdomains ;;
            4) http_probe ;;
            5) fetch_urls ;;
            6) take_screenshots ;;
            7) scan_xss ;;
            8) scan_sqli ;;
            9) run_pattern_matching ;;
            10) generate_report ;;
            11) run_full_recon ;;
            0)
                log_message "INFO" "Exiting. Goodbye!"
                exit 0
                ;;
            *)
                log_message "ERROR" "Invalid option. Try again."
                ;;
        esac
        
        read -p "$(echo -e "${PURPLE}Press Enter to continue...${NC}")"
        clear
        display_title
    done
}

main
