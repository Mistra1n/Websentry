#!/usr/bin/env python3
import os
import sys
import subprocess
from pathlib import Path
import argparse
import requests
from urllib.parse import urlparse
import re
from jinja2 import Environment, FileSystemLoader
import json
from datetime import datetime

def send_notification(scan_results, config_file="config/notifications.json"):
    """Send scan results to configured notification channels"""
    try:
        with open(config_file) as f:
            config = json.load(f)
    except FileNotFoundError:
        return
    
    message = {
        "text": f"WebSentry Scan Completed for {scan_results['domain']}",
        "attachments": [{
            "color": "#36a64f" if not scan_results['vulnerabilities'] else "#ff0000",
            "fields": [
                {"title": "Vulnerabilities Found", "value": str(len(scan_results['vulnerabilities'])), "short": True},
                {"title": "Sensitive Directories", "value": str(len(scan_results['directories'])), "short": True},
                {"title": "Scan Duration", "value": scan_results['duration'], "short": True}
            ]
        }]
    }

    # Slack Notification
    if 'slack' in config:
        try:
            requests.post(
                config['slack']['webhook_url'],
                json=message,
                headers={'Content-Type': 'application/json'}
            )
        except Exception as e:
            print(f"[!] Slack notification failed: {str(e)}")

    # Discord Notification
    if 'discord' in config:
        try:
            discord_msg = {
                "content": f"**WebSentry Scan Report**\nTarget: {scan_results['domain']}",
                "embeds": [{
                    "title": "Scan Results",
                    "color": 65280 if not scan_results['vulnerabilities'] else 16711680,
                    "fields": [
                        {"name": "Vulnerabilities", "value": str(len(scan_results['vulnerabilities'])), "inline": True},
                        {"name": "Directories", "value": str(len(scan_results['directories'])), "inline": True}
                    ]
                }]
            }
            requests.post(
                config['discord']['webhook_url'],
                json=discord_msg,
                headers={'Content-Type': 'application/json'}
            )
        except Exception as e:
            print(f"[!] Discord notification failed: {str(e)}")
def handle_cloudflare(urls_file):
    """Check for and bypass Cloudflare protection"""
    from urllib.parse import urlparse
    from cloudflare_bypass import CloudflareBypass
    
    with open(urls_file) as f:
        urls = [line.strip() for line in f if line.strip()]
    
    bypassed_urls = []
    for url in urls:
        domain = urlparse(url).netloc
        bypass = CloudflareBypass(domain)
        bypass_url = bypass.test_bypass(url)
        if bypass_url:
            bypassed_urls.append(bypass_url)
    
    if bypassed_urls:
        with open(urls_file, 'w') as f:
            f.write('\n'.join(bypassed_urls))
        print(f"  - Bypassed Cloudflare for {len(bypassed_urls)} URLs")
        
def generate_html_report(domain, scan_dir):
    """Generate professional HTML report"""
    clean_domain = sanitize_domain(domain)
    target_dir = scan_dir / "targets" / clean_domain
    report_file = scan_dir / "reports" / f"{clean_domain}_report.html"
    
    # Collect scan data
    report_data = {
        "domain": clean_domain,
        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "nuclei": {},
        "dirsearch": [],
        "sqlmap": ""
    }

    # Gather Nuclei results
    nuclei_dir = target_dir / "nuclei"
    for category in ["cves", "exposures", "xss"]:
        result_file = nuclei_dir / category / "results.txt"
        if result_file.exists():
            with open(result_file) as f:
                report_data["nuclei"][category] = [line.strip() for line in f if line.strip()]

    # Gather Dirsearch results
    dirsearch_file = target_dir / "dirsearch" / "results.txt"
    if dirsearch_file.exists():
        with open(dirsearch_file) as f:
            report_data["dirsearch"] = [line.strip() for line in f if line.strip()]

    # Gather SQLmap results
    sqlmap_file = target_dir / "sqlmap" / "results.txt"
    if sqlmap_file.exists():
        with open(sqlmap_file) as f:
            report_data["sqlmap"] = f.read()

    # Render HTML template
    env = Environment(loader=FileSystemLoader('templates'))
    template = env.get_template('report.html')
    html_content = template.render(data=report_data)
    
    with open(report_file, 'w') as f:
        f.write(html_content)
    
    print(f"\n[+] Generated HTML report: {report_file}")
    return report_file
# Configuration
SCAN_DIR = Path.home() / "Desktop" / "Websentry"
TOOLS = {
    'sqlmap': SCAN_DIR / "tools" / "sqlmap" / "sqlmap.py",
    'dirsearch': SCAN_DIR / "tools" / "dirsearch" / "dirsearch.py",
    'nuclei': Path("/usr/bin/nuclei"),
    'httpx': Path("/usr/local/bin/httpx"),
    'waybackurls': Path("/usr/local/bin/waybackurls")
}

def sanitize_domain(domain):
    """Remove http:// or https:// from domain if present"""
    return re.sub(r'^https?://', '', domain).strip('/')

def check_dependencies():
    """Check all required dependencies are installed"""
    try:
        import requests
        from urllib.parse import urlparse
        import defusedxml
        return True
    except ImportError as e:
        print(f"[!] Missing dependency: {str(e)}")
        print("[!] Install with: pip install requests defusedxml")
        return False

def check_tools():
    """Verify required tools are installed and working"""
    missing = []
    for tool, path in TOOLS.items():
        if not path.exists():
            missing.append(tool)
    
    if missing:
        print(f"[!] Missing tools: {', '.join(missing)}")
        print("[!] Installation instructions:")
        print("  - sqlmap: git clone https://github.com/sqlmapproject/sqlmap.git tools/sqlmap")
        print("  - dirsearch: git clone https://github.com/maurosoria/dirsearch.git tools/dirsearch")
        print("  - waybackurls/httpx/nuclei: go install github.com/projectdiscovery/[tool]@latest")
        return False
    
    # Verify nuclei templates
    nuclei_templates = Path.home() / "nuclei-templates"
    if not nuclei_templates.exists() or not any(nuclei_templates.iterdir()):
        print("[!] Nuclei templates not found. Run:")
        print("    nuclei -update-templates")
        return False
    
    return True

def create_folders(target):
    """Create organized scan directory structure"""
    sanitized_target = sanitize_domain(target).replace('/', '_')
    target_dir = SCAN_DIR / "targets" / sanitized_target
    paths = [
        target_dir / "nuclei" / "cves",
        target_dir / "nuclei" / "exposures",
        target_dir / "nuclei" / "xss",
        target_dir / "sqlmap",
        target_dir / "dirsearch",
        SCAN_DIR / "payloads",
        SCAN_DIR / "scripts",
        SCAN_DIR / "reports"
    ]
    
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)
    return target_dir

def run_waybackurls(domain):
    """Get historical URLs from Wayback Machine"""
    clean_domain = sanitize_domain(domain)
    print(f"\n[+] Gathering Wayback URLs for {clean_domain}")
    output_file = SCAN_DIR / "targets" / clean_domain / "wayback_urls.txt"
    
    try:
        result = subprocess.run(
            [TOOLS['waybackurls'], clean_domain],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Remove duplicates and save
        urls = list(set(result.stdout.splitlines()))
        with open(output_file, 'w') as f:
            f.write('\n'.join(urls))
            
        print(f"  - Found {len(urls)} unique URLs")
        return output_file, len(urls)
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Waybackurls failed: {e.stderr}")
        return None, 0

def run_httpx(urls_file):
    """Check which URLs are live"""
    print("\n[+] Checking live URLs")
    output_file = urls_file.parent / "live_urls.txt"
    
    try:
        with open(urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
        
        # Basic HTTP check if httpx fails
        if not TOOLS['httpx'].exists():
            return basic_http_check(urls, output_file)
            
        cmd = f"cat {urls_file} | {TOOLS['httpx']} -silent -status-code -title -tech-detect -o {output_file}"
        subprocess.run(cmd, shell=True, check=True)
        
        with open(output_file) as f:
            live_count = sum(1 for _ in f)
            
        print(f"  - Found {live_count} live URLs")
        return output_file, live_count
        
    except Exception as e:
        print(f"[!] HTTPX failed: {str(e)}")
        return basic_http_check(urls, output_file)

def basic_http_check(urls, output_file):
    """Fallback HTTP checker"""
    live_urls = []
    for url in urls[:1000]:  # Limit to first 1000 URLs
        try:
            if not urlparse(url).scheme:
                url = f"http://{url}"
            response = requests.head(url, timeout=5, allow_redirects=True)
            if response.status_code < 400:
                live_urls.append(url)
        except:
            continue
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(live_urls))
    
    print(f"  - Found {len(live_urls)} live URLs (basic check)")
    return output_file, len(live_urls)

def run_nuclei(domain, urls_file):
    """Run Nuclei scans with proper error handling"""
    print("\n[+] Running Nuclei scans")
    clean_domain = sanitize_domain(domain)
    target_dir = SCAN_DIR / "targets" / clean_domain
    
    template_groups = {
        "cves": "cves/",
        "exposures": "exposed-panels,misconfiguration/",
        "xss": "xss/"
    }
    
    for name, templates in template_groups.items():
        output_file = target_dir / "nuclei" / name / f"results.txt"
        cmd = [
            str(TOOLS['nuclei']),
            "-l", str(urls_file),
            "-t", templates,
            "-o", str(output_file),
            "-stats",
            "-silent"
        ]
        
        try:
            print(f"  - Running {name} scan with templates: {templates}")
            subprocess.run(cmd, check=True)
            # Verify output was created
            if output_file.exists() and os.path.getsize(output_file) > 0:
                print(f"  - {name} scan completed successfully")
            else:
                print(f"  - {name} scan ran but no results found")
        except subprocess.CalledProcessError as e:
            print(f"[!] Nuclei {name} scan failed: {e.stderr if e.stderr else 'Check template installation'}")
            
    # Verify at least one scan worked
    if not any((target_dir / "nuclei").iterdir()):
        print("[!] All Nuclei scans failed. Check template installation.")
        print("    Run: nuclei -update-templates")

def run_dirsearch(domain):
    """Modern directory brute-forcing with ffuf fallback to dirsearch"""
    clean_domain = sanitize_domain(domain)
    target_dir = SCAN_DIR / "targets" / clean_domain
    output_file = target_dir / "dirsearch" / "results.txt"
    
    # Use ffuf if available
    if Path("/usr/bin/ffuf").exists():
        try:
            cmd = [
                "ffuf",
                "-u", f"https://{clean_domain}/FUZZ",
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-o", str(output_file),
                "-of", "json"
            ]
            subprocess.run(cmd, check=True)
            print("  - Directory brute-forcing completed with ffuf")
            return
        except Exception as e:
            print(f"[!] ffuf failed: {str(e)}")
    
    # Try native dirsearch
    if TOOLS['dirsearch'].exists():
        try:
            cmd = [
                "python3",
                str(TOOLS['dirsearch']),
                "-u", f"https://{clean_domain}",
                "-e", "php,asp,aspx,jsp,html,js",
                "-t", "20",
                "-o", str(output_file)
            ]
            subprocess.run(cmd, check=True)
            if output_file.exists():
                print(f"  - Dirsearch completed. Results in {output_file}")
            return
        except Exception as e:
            print(f"[!] Dirsearch failed: {str(e)}")
    
    # Fallback to basic check
    print("  - Using basic directory check")
    common_dirs = ["admin", "wp-admin", "backup", "config", "api"]
    found = []
    
    for directory in common_dirs:
        url = f"https://{clean_domain}/{directory}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code < 400:
                found.append(url)
        except:
            continue
    
    with open(output_file, 'w') as f:
        f.write('\n'.join(found))
    
    print(f"  - Found {len(found)} common directories")
    
def run_dirsearch(domain):
    """Modern directory brute-forcing with ffuf"""
    clean_domain = sanitize_domain(domain)
    output_file = SCAN_DIR / "targets" / clean_domain / "dirsearch" / "results.txt"
    
    # Use ffuf if available
    if Path("/usr/bin/ffuf").exists():
        try:
            cmd = [
                "ffuf",
                "-u", f"https://{clean_domain}/FUZZ",
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-o", str(output_file),
                "-of", "json"
            ]
            subprocess.run(cmd, check=True)
            print("  - Directory brute-forcing completed with ffuf")
            return
        except Exception as e:
            print(f"[!] ffuf failed: {str(e)}")
    
    # Fallback to existing implementation
    print("  - Using basic directory check")
    
def run_sqlmap(domain):
    """Run SQLmap scan with basic check fallback"""
    print("\n[+] Testing for SQL injection")
    clean_domain = sanitize_domain(domain)
    target_dir = SCAN_DIR / "targets" / clean_domain
    output_file = target_dir / "sqlmap" / "results.txt"
    
    if TOOLS['sqlmap'].exists():
        try:
            test_url = f"https://{clean_domain}/search?q=1"
            cmd = [
                "python3",
                str(TOOLS['sqlmap']),
                "-u", test_url,
                "--batch",
                "--crawl=1",
                "--output-dir=" + str(target_dir / "sqlmap")
            ]
            process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Write output to file
            with open(output_file, 'w') as f:
                f.write(process.stdout)
                if process.stderr:
                    f.write("\nERRORS:\n" + process.stderr)
            
            if "SQL injection" in process.stdout:
                print("  - Possible SQL injection found!")
            else:
                print("  - No SQL injection found")
        except Exception as e:
            print(f"[!] SQLmap failed: {str(e)}")
    else:
        print("  - SQLmap not available, skipping")

def full_scan(domain):
    """Run complete scan workflow with error handling"""
    if not check_dependencies() or not check_tools():
        sys.exit(1)
        
    clean_domain = sanitize_domain(domain)
    target_dir = create_folders(clean_domain)
    print(f"\n[+] Starting scan for {clean_domain}")
    
    # Run scans with proper error handling
    wayback_file, url_count = run_waybackurls(clean_domain)
    if url_count == 0:
        print("[!] No URLs found, check target availability")
        return
    
    live_file, live_count = run_httpx(wayback_file)
    if live_count == 0:
        print("[!] No live URLs found, scanning main domain only")
        with open(live_file, 'w') as f:
            f.write(f"https://{clean_domain}")
    
    # Add Cloudflare bypass
    handle_cloudflare(live_file)
    
    # Run scans
    run_nuclei(clean_domain, live_file)  # Only one call now
    run_dirsearch(clean_domain)
    run_sqlmap(clean_domain)
    
    # Generate report
    report_file = generate_html_report(clean_domain, SCAN_DIR)
    
    print("\n[+] Scan completed!")
    print(f"    Results saved in: {target_dir}")
    print(f"    Report generated: {report_file}")
    
def main():
    parser = argparse.ArgumentParser(description='Advanced Web Vulnerability Scanner')
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    scan_parser = subparsers.add_parser('scan', help='Run full scan on target')
    scan_parser.add_argument('domain', help='Target domain to scan (with or without http://)')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        full_scan(args.domain)

if __name__ == '__main__':
    main()
