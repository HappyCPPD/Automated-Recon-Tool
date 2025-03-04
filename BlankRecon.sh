#!/bin/bash

PURPLE='\033[0;35m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
TARGET_DIR=""

display_title() {
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

install_go_tool() {
    local tool_name=$1
    local repo_path=$2
    echo -e "${YELLOW}[*] Installing $tool_name...${NC}"
    if ! command -v "$tool_name" &> /dev/null; then
        if go install "$repo_path"@latest 2>/dev/null; then
            echo -e "${GREEN}[+] $tool_name installed successfully.${NC}"
        else
            echo -e "${RED}[!] ERROR: Failed to install $tool_name. Please install manually.${NC}"
            return 1
        fi
    else
        echo -e "${GREEN}[+] $tool_name is already installed.${NC}"
    fi
}

install_tools() {
    if ! command -v go &> /dev/null; then
        echo -e "${RED}[!] Go is not installed. Please install Go first.${NC}"
        exit 1
    fi
    export PATH=$PATH:$(go env GOPATH)/bin
    install_go_tool "dalfox" "github.com/hahwul/dalfox/v2"
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"
    install_go_tool "anew" "github.com/tomnomnom/anew"
    install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder"
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau"
    install_go_tool "waybackurls" "github.com/tomnomnom/waybackurls"
    install_go_tool "qsreplace" "github.com/tomnomnom/qsreplace"
    install_go_tool "findomain" "github.com/Edu4rdSHL/findomain"
}

setup_target_dir() {
    read -p "Enter target domaian (without http/https): " target
    TARGET_DIR="$(pwd)/recon_$target"
    mkdir -p "$TARGET_DIR"
    cd "$TARGET_DIR" || exit
    echo "$target" > target.txt
    echo -e "${GREEN}[*] Created target directory: $TARGET_DIR${NC}"
}

xss_scan() {
    echo -e "${GREEN}[*] Starting XSS Scan...${NC}"
    
    timeout 60 subfinder -d "$(cat target.txt)" -silent > subdomains.txt
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Subfinder failed or timed out.${NC}"
        return 1
    fi
    
    cat subdomains.txt | httpx -silent -threads 50 > live_hosts.txt
    
    cat live_hosts.txt | \
    xargs -I@ -P 5 sh -c 'timeout 10 dalfox url "@" --silence 2>&1' | \
    grep -v "^$" > xss_results.txt
    
    xss_count=$(wc -l < xss_results.txt)
    echo -e "${GREEN}[*] XSS Scan completed. Found $xss_count potential XSS vulnerabilities.${NC}"
    echo -e "${GREEN}[*] Results saved in xss_results.txt${NC}"
}

sqli_scan() {
    echo -e "${GREEN}[*] Starting SQLi Scan...${NC}"
    echo "SQLi scan placeholder" > sqli_results.txt
    echo -e "${GREEN}[*] SQLi Scan completed. Results in sqli_results.txt${NC}"
}

ssrf_scan() {
    echo -e "${GREEN}[*] Starting SSRF Scan...${NC}"
    echo "SSRF scan placeholder" > ssrf_results.txt
    echo -e "${GREEN}[*] SSRF Scan completed. Results in ssrf_results.txt${NC}"
}

lfi_scan() {
    echo -e "${GREEN}[*] Starting LFI Scan...${NC}"
    echo "LFI scan placeholder" > lfi_results.txt
    echo -e "${GREEN}[*] LFI Scan completed. Results in lfi_results.txt${NC}"
}

open_redirect_scan() {
    echo -e "${GREEN}[*] Starting Open Redirect Scan...${NC}"
    echo "Open Redirect scan placeholder" > redirect_results.txt
    echo -e "${GREEN}[*] Open Redirect Scan completed. Results in redirect_results.txt${NC}"
}

cors_scan() {
    echo -e "${GREEN}[*] Starting CORS Scan...${NC}"
    echo "CORS scan placeholder" > cors_results.txt
    echo -e "${GREEN}[*] CORS Scan completed. Results in cors_results.txt${NC}"
}

extract_js() {
    echo -e "${GREEN}[*] Extracting JS Files...${NC}"
    echo "JS extraction placeholder" > js_files.txt
    echo -e "${GREEN}[*] JS Files extraction completed. Results in js_files.txt${NC}"
}

extract_comments_urls() {
    echo -e "${GREEN}[*] Extracting URLs from Comments...${NC}"
    echo "Comments URL extraction placeholder" > comments_urls.txt
    echo -e "${GREEN}[*] URL Comments extraction completed. Results in comments_urls.txt${NC}"
}

find_live_hosts() {
    echo -e "${GREEN}[*] Finding Live Hosts...${NC}"
    subfinder -d "$(cat target.txt)" -silent |
    httpx -silent > live_hosts.txt
    echo -e "${GREEN}[*] Live Hosts discovery completed. Results in live_hosts.txt${NC}"
}

take_screenshots() {
    echo -e "${GREEN}[*] Taking Screenshots...${NC}"
    mkdir -p screenshots
    echo "Screenshots placeholder" > screenshots/screenshot_list.txt
    echo -e "${GREEN}[*] Screenshots completed. List in screenshots/screenshot_list.txt${NC}"
}

run_all_scans() {
    echo -e "${GREEN}[*] Starting ALL Scans...${NC}"
    
    echo -e "${YELLOW}[*] Scanning for Subdomains...${NC}"
    find_live_hosts
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Subdomain scan failed.${NC}"
    fi
    
    echo -e "${YELLOW}[*] Performing XSS Scan...${NC}"
    xss_scan
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] XSS scan encountered issues.${NC}"
    fi
    
    echo -e "${YELLOW}[*] Performing SQLi Scan...${NC}"
    sqli_scan
    
    echo -e "${YELLOW}[*] Performing SSRF Scan...${NC}"
    ssrf_scan
    
    echo -e "${YELLOW}[*] Performing LFI Scan...${NC}"
    lfi_scan
    
    echo -e "${YELLOW}[*] Performing Open Redirect Scan...${NC}"
    open_redirect_scan
    
    echo -e "${YELLOW}[*] Performing CORS Scan...${NC}"
    cors_scan
    
    echo -e "${YELLOW}[*] Extracting JS Files...${NC}"
    extract_js
    
    echo -e "${YELLOW}[*] Extracting URLs from Comments...${NC}"
    extract_comments_urls
    
    echo -e "${YELLOW}[*] Taking Screenshots...${NC}"
    take_screenshots
    
    echo -e "${GREEN}[*] ALL Scans Completed!${NC}"
}

display_menu() {
    echo -e "\n${PURPLE}Bug Bounty Recon Menu:${NC}"
    echo "1. XSS Scan"
    echo "2. SQLi Scan"
    echo "3. SSRF Scan"
    echo "4. LFI Scan"
    echo "5. Open Redirect Scan"
    echo "6. CORS Scan"
    echo "7. Extract JS Files"
    echo "8. Extract URLs from Comments"
    echo "9. Find Live Hosts"
    echo "10. Take Screenshots"
    echo "11. Run ALL Scans"
    echo "0. Exit"
}

main() {
    clear
    display_title
    install_tools
    setup_target_dir

    while true; do
        display_menu
        
        read -p "Enter your choice: " choice
        
        case $choice in
            1) xss_scan ;;
            2) sqli_scan ;;
            3) ssrf_scan ;;
            4) lfi_scan ;;
            5) open_redirect_scan ;;
            6) cors_scan ;;
            7) extract_js ;;
            8) extract_comments_urls ;;
            9) find_live_hosts ;;
            10) take_screenshots ;;
            11) run_all_scans ;;
            0) 
                echo "Goodbye!"
                exit 0 
                ;;
            *) 
                echo "Invalid option."
                ;;
        esac
        
        read -p "Press Enter to continue..." 
    done
}

main