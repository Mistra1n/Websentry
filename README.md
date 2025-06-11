# WebSentry 🛡️

**Advanced Web Vulnerability Scanner with WAF Bypass Capabilities**

![Alt text](https://raw.githubusercontent.com/Mistra1n/Websentry/refs/heads/main/templates/Screenshot_2025-06-06_22_12_56.png)
![Watch the video](https://github.com/Mistra1n/Websentry/blob/main/templates/new-2025-06-07_15.03.00.mkv)
## Features

- 🌐 Full website reconnaissance
- 🕵️‍♂️ XSS/SQLi/LFI detection
- 🛡️ Cloudflare/WAF bypass techniques
- 📊 Organized reporting system
- ⚡ Multi-threaded scanning

## Installation

```bash
git clone https://github.com/Mistra1n/Websentry.git
cd WebSentry
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt


Usage

# Basic scan
python3 scripts/websentry.py scan example.com

# Full scan with all tests
python3 scripts/websentry.py full-scan example.com --waf-bypass

# XSS-only scan
python3 scripts/websentry.py xss-scan example.com/login
dalfox url https://example.com/login?test=123
# WAF testing
python3 scripts/waf_breaker.py https://example.com
```

## Let's try running the websentry script now that we're in the virtual environment with all dependencies installed.

```bash          
command: python scripts/websentry.py scan example.com
```
          
Let's clone the required tools starting with sqlmap and dirsearch.
        
```bash
command: git clone https://github.com/sqlmapproject/sqlmap.git tools/sqlmap
```
          
Now let's clone dirsearch repository.
        
```bash          
command: git clone https://github.com/maurosoria/dirsearch.git tools/dirsearch
```
          
Let's check if Go is installed since it's needed for the remaining tools (waybackurls, httpx, nuclei).
        
```bash           
command: go version
```
          
I've helped diagnose and partially resolve the dependency issues. Here's the current status and next steps:

1. Successfully installed Python dependencies from `requirements.txt`
2. Successfully cloned required tools:
   - sqlmap in `tools/sqlmap`
   - dirsearch in `tools/dirsearch`

3. **Remaining Requirements**:
You need to install Go and the following Go-based tools:
- waybackurls
- httpx
- nuclei

To complete the setup:

1. Install Go from https://golang.org/dl/
2. After installing Go, run these commands:
```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
```

Once these tools are installed, you should be able to run the websentry script successfully.
        

# Install tools
if any error just install the error pakage or contact me 2547264268**
tool not complete or it is madify to your option
