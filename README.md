# XSS Recon - Comprehensive Web Application Security Scanner

A production-ready bash script for automated security reconnaissance on target web applications. Designed for Kali Linux with a focus on subdomain enumeration, vulnerability discovery, XSS detection, and comprehensive reporting.

## Features

### Core Reconnaissance Capabilities
- **Subdomain Enumeration**: Multi-tool approach using subfinder, assetfinder, findomain, gau, and waybackurls
- **Live Host Discovery**: Identifies active hosts with httpx or curl fallback
- **Parameter Discovery**: Extracts parameters from historical and current URLs
- **XSS Vulnerability Scanning**: Automated XSS detection using dalfox
- **Vulnerability Assessment**: Nuclei-based template scanning for CVEs and misconfigurations
- **Content Discovery**: JS file analysis, sensitive file detection, API endpoint discovery
- **Fuzzing**: Directory enumeration with ffuf and API endpoint probing
- **Screenshots**: Website snapshots with optional gowitness integration

### Additional Features
- **Discord Integration**: Real-time notifications and report uploads
- **HTML Reporting**: Professional multi-page reports with paginated findings
- **Comprehensive Logging**: Detailed execution logs for auditing
- **Flexible Tool Detection**: Gracefully handles missing tools with fallbacks
- **Concurrent Execution**: Configurable parallel scanning for speed
- **Subdomain Permutation**: Generates common variations (dev-, staging-, api-, admin-, etc.)

## Installation & Setup

### Prerequisites
```bash
# System requirements
- Kali Linux or similar Linux distribution
- Bash 4.0+
- Go 1.16+ (for Go-based tools)
- Python 3.7+ with pip3
- curl, wget, git

# Install Go (if not already installed)
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

### Quick Start
```bash
# Clone and prepare
chmod +x BlankRecon.sh
./BlankRecon.sh

# Enter target domain when prompted (e.g., example.com)
# The script will automatically:
# 1. Check/install required tools
# 2. Create results directory
# 3. Display interactive menu
```

## Usage

### Menu Options

```
1. Advanced Subdomain Enumeration    - Discovers all subdomains with permutations
2. Find Live Hosts                    - Tests which discovered hosts are alive
3. Advanced Parameter Discovery       - Extracts URL parameters from historical data
4. Advanced XSS Scan                  - Tests for XSS vulnerabilities
5. Advanced Vulnerability Scan        - Checks for known vulnerabilities with Nuclei
6. Advanced Content Discovery         - Crawls and extracts interesting files/endpoints
7. Advanced Fuzzing                   - Directory and API endpoint fuzzing
8. Take Screenshots                   - Captures website screenshots
9. Run ALL Scans                      - Executes complete reconnaissance
0. Exit                               - Quit the script
```

### Examples

#### Run Full Recon
```bash
./BlankRecon.sh
# Select option 9 to run all scans
```

#### Run Specific Scans
```bash
./BlankRecon.sh
# Select individual options (1-8)
```

#### With Discord Notifications
```bash
./BlankRecon.sh
# When prompted, enter your Discord webhook URL
# Notifications will be sent for major milestones
```

## Output Structure

```
recon_example.com/
├── recon.log                          # Detailed execution log
├── target.txt                         # Target domain
├── results/
│   ├── subdomains.txt                 # All discovered subdomains
│   ├── live_hosts.txt                 # Active hosts with status codes
│   ├── xss_results.txt                # XSS findings
│   ├── urls_with_params.txt           # URLs with parameters
│   ├── vulnerabilities/
│   │   ├── nuclei_results.txt         # Vulnerability scan results
│   │   └── crlf_results.txt           # CRLF injection findings
│   ├── parameters/
│   │   └── all_parameters.txt         # Discovered parameters
│   ├── content/
│   │   ├── all_urls.txt               # All discovered URLs
│   │   ├── interesting_files.txt      # Sensitive files
│   │   ├── js_files.txt               # JavaScript file URLs
│   │   └── js_secrets.txt             # Potential secrets in JS
│   ├── fuzzing/
│   │   ├── api_endpoints.txt          # Discovered API endpoints
│   │   └── ffuf_*.json                # Fuzzing results
│   ├── screenshots/                   # Website screenshots
│   └── report/
│       ├── index.html                 # Main report
│       ├── subdomains.html
│       ├── vulnerabilities.html
│       ├── xss.html
│       ├── content.html
│       └── summary.html
└── tools/                              # Cloned tool repositories
```

## Tools Integrated

### Go-based Tools (Auto-installed)
- **subfinder** - Subdomain enumeration
- **httpx** - HTTP probing and tech detection
- **assetfinder** - Public domain asset finder
- **dalfox** - XSS vulnerability scanner
- **nuclei** - Template-based vulnerability scanner
- **ffuf** - Web fuzzer
- **findomain** - Domain/subdomain finder
- **gau** - Get All URLs
- **waybackurls** - Wayback Machine URLs
- **anew** - File deduplication
- **qsreplace** - Parameter replacement
- **gospider** - Web crawler
- **crlfuzz** - CRLF injection scanner

### Python Tools
- **arjun** - Parameter discovery

### Optional Tools
- **gowitness** - Website screenshots

## Configuration

### Environment Variables
```bash
THREADS=50              # Threads for parallel operations
CONCURRENT_SCANS=5      # Concurrent scan instances
SCAN_TIMEOUT=300        # Timeout for operations (seconds)
```

### Discord Webhook
Get a Discord webhook URL from:
1. Server Settings → Integrations → Webhooks
2. Create New Webhook
3. Copy the URL when running the script

## Performance Optimization

### For Large Targets
```bash
# Edit THREADS variable in script
THREADS=100
CONCURRENT_SCANS=10
```

### For Quick Scans
```bash
# Run specific scans instead of all
# Choose options 1-2 for initial reconnaissance
```

## Troubleshooting

### "Tool not found" errors
- **Solution**: Script auto-installs tools. If issues persist:
  ```bash
  go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  ```

### No subdomains discovered
- Ensure target is valid and public
- Try option 1 multiple times (results are cumulative)
- Check internet connection for Wayback Machine access

### Slow scanning
- Increase timeouts: `SCAN_TIMEOUT=600`
- Reduce threads: `THREADS=25`
- Run specific scans instead of all

### Report not generated
- Verify results directory has content
- Check disk space: `df -h`
- Review log file: `cat recon.log`

## Security Notes

- ✅ Designed for authorized testing only
- ✅ All target requests logged to recon.log
- ✅ HTML output sanitizes special characters
- ✅ Timeouts prevent infinite hangs
- ✅ Graceful degradation if tools missing

## Performance Expectations

| Operation | Time | Notes |
|-----------|------|-------|
| Subdomain enum | 2-5 min | Depends on target size |
| Live host check | 1-3 min | 50 concurrent threads |
| XSS scan | 3-10 min | Per discovered parameter |
| Vulnerability scan | 5-20 min | Number of active hosts |
| Full recon | 20-60 min | Complete assessment |

## Customization

### Add Custom Wordlist for Fuzzing
```bash
# Edit advanced_fuzzing() to point to your wordlist
wordlist="/path/to/custom/wordlist.txt"
```

### Modify Reporting
- Edit `generate_html_report()` function
- Customize HTML output in report generation sections

### Add New Scans
```bash
# Create new function following existing pattern
new_scan_function() {
    log "INFO" "Starting new scan"
    # Your scan logic
    log "SUCCESS" "Scan completed"
}

# Add to display_menu()
echo "10. New Custom Scan"

# Add to main() case statement
10) new_scan_function ;;
```

## Limitations & Known Issues

- Nuclei templates require internet for updates
- Large wordlists may impact fuzzing performance
- Some targets may block automated scanning
- Screenshots require display capability

## Future Enhancements

- [ ] Database integration for multi-target tracking
- [ ] API for programmatic access
- [ ] Custom payload loading
- [ ] Machine learning-based finding prioritization
- [ ] Slack/Teams integration
- [ ] Multi-threading for serial operations

## License

Use responsibly and only on targets you have permission to test.

## Support

For issues, check:
1. Script logs: `cat recon.log`
2. Tool installations: `command -v <tool_name>`
3. Network connectivity: `curl -I https://www.google.com`

---

**Last Updated**: 2026-01-26  
**Version**: 2.0

I DO NOT ENDORSE USING THIS TOOL FOR MALICIOUS PURPOSES!
