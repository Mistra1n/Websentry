#!/bin/bash
# Full Security Scan Script

TARGET="$1"
if [ -z "$TARGET" ]; then
    echo "Usage: ./full_scan.sh <target-domain>"
    echo "Example: ./full_scan.sh malikes-zone.tappi.ke"
    exit 1
fi

# Clean domain name
DOMAIN=$(echo "$TARGET" | sed -e 's|https\?://||' -e 's|/.*||')
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT_DIR="scans/${DOMAIN}_${TIMESTAMP}"
mkdir -p "$REPORT_DIR"

echo "==================================="
echo "Full Security Scan: $DOMAIN"
echo "Report Directory: $REPORT_DIR"
echo "Started at: $(date)"
echo "==================================="

# Setup environment
source venv/bin/activate
export PATH="$HOME/go/bin:$PATH"

# 1. Subdomain Enumeration
echo -e "\n[1/7] Enumerating subdomains..."
subfinder -d "$DOMAIN" -silent 2>/dev/null > "$REPORT_DIR/subdomains.txt" || \
    echo "$DOMAIN" > "$REPORT_DIR/subdomains.txt"
echo "  - Found $(wc -l < "$REPORT_DIR/subdomains.txt") subdomains"

# 2. HTTP Probing
echo -e "\n[2/7] Probing live hosts..."
httpx -l "$REPORT_DIR/subdomains.txt" -silent -o "$REPORT_DIR/live_hosts.txt" 2>/dev/null
echo "  - Found $(wc -l < "$REPORT_DIR/live_hosts.txt" 2>/dev/null || echo 0) live hosts"

# 3. Wayback URLs
echo -e "\n[3/7] Gathering historical URLs..."
echo "$DOMAIN" | waybackurls > "$REPORT_DIR/wayback_urls.txt" 2>/dev/null
echo "  - Collected $(wc -l < "$REPORT_DIR/wayback_urls.txt") historical URLs"

# 4. Directory Bruteforce
echo -e "\n[4/7] Running directory scan..."
if [ -f "tools/dirsearch/dirsearch.py" ]; then
    python3 tools/dirsearch/dirsearch.py -u "https://$DOMAIN" \
        --random-agent \
        -e php,html,js,asp,aspx,jsp \
        -x 404,403,500 \
        --simple-report="$REPORT_DIR/directories.txt" \
        2>/dev/null
    echo "  - Directory scan complete"
fi

# 5. XSS Scanning with Dalfox
echo -e "\n[5/7] Scanning for XSS vulnerabilities..."
if [ -f "$REPORT_DIR/wayback_urls.txt" ]; then
    cat "$REPORT_DIR/wayback_urls.txt" | grep -E "\?.*=" | head -50 | while read url; do
        dalfox url "$url" --silence --no-color 2>/dev/null
    done > "$REPORT_DIR/xss_results.txt"
    echo "  - XSS scan complete"
fi

# 6. SQL Injection Testing
echo -e "\n[6/7] Testing for SQL injection..."
if [ -f "$REPORT_DIR/wayback_urls.txt" ]; then
    cat "$REPORT_DIR/wayback_urls.txt" | grep -E "\?.*=" | head -10 | while read url; do
        python3 tools/sqlmap/sqlmap.py -u "$url" --batch --random-agent --level=2 --risk=2 2>/dev/null | \
            grep -E "(vulnerable|Parameter)" >> "$REPORT_DIR/sql_results.txt"
    done
    echo "  - SQL scan complete"
fi

# 7. Nuclei Vulnerability Scan
echo -e "\n[7/7] Running comprehensive vulnerability scan..."
if [ -f "$REPORT_DIR/live_hosts.txt" ] && [ -s "$REPORT_DIR/live_hosts.txt" ]; then
    nuclei -l "$REPORT_DIR/live_hosts.txt" \
        -severity low,medium,high,critical \
        -silent \
        -o "$REPORT_DIR/nuclei_results.txt" \
        2>/dev/null
    echo "  - Nuclei scan complete"
fi

# Generate Summary Report
echo -e "\n==================================="
echo "Scan Complete! Generating summary..."
echo "==================================="

cat > "$REPORT_DIR/summary.html" << 'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .section { background: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .vuln-high { color: red; font-weight: bold; }
        .vuln-medium { color: orange; }
        .vuln-low { color: green; }
    </style>
</head>
<body>
    <h1>Security Scan Report</h1>
    <p>Target: DOMAIN_PLACEHOLDER</p>
    <p>Scan Date: DATE_PLACEHOLDER</p>
    
    <div class="section">
        <h2>Summary</h2>
        <p>Subdomains Found: SUBDOMAINS_COUNT</p>
        <p>Live Hosts: LIVE_HOSTS_COUNT</p>
        <p>Historical URLs: URLS_COUNT</p>
    </div>
</body>
</html>
HTML

sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" "$REPORT_DIR/summary.html"
sed -i "s/DATE_PLACEHOLDER/$(date)/g" "$REPORT_DIR/summary.html"
sed -i "s/SUBDOMAINS_COUNT/$(wc -l < "$REPORT_DIR/subdomains.txt" 2>/dev/null || echo 0)/g" "$REPORT_DIR/summary.html"
sed -i "s/LIVE_HOSTS_COUNT/$(wc -l < "$REPORT_DIR/live_hosts.txt" 2>/dev/null || echo 0)/g" "$REPORT_DIR/summary.html"
sed -i "s/URLS_COUNT/$(wc -l < "$REPORT_DIR/wayback_urls.txt" 2>/dev/null || echo 0)/g" "$REPORT_DIR/summary.html"

echo ""
echo "=== SCAN COMPLETE ==="
echo "Report saved to: $REPORT_DIR"
echo "View HTML report: $REPORT_DIR/summary.html"
echo ""
echo "Key findings:"
echo "  - XSS findings: $(wc -l < "$REPORT_DIR/xss_results.txt" 2>/dev/null || echo 0) potential issues"
echo "  - Nuclei findings: $(wc -l < "$REPORT_DIR/nuclei_results.txt" 2>/dev/null || echo 0) vulnerabilities"
echo ""
