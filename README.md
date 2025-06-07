# WebSentry 🛡️

**Advanced Web Vulnerability Scanner with WAF Bypass Capabilities**

![Alt text](https://raw.githubusercontent.com/Mistra1n/Websentry/refs/heads/main/templates/Screenshot_2025-06-06_22_12_56.png)

## Features

- 🌐 Full website reconnaissance
- 🕵️‍♂️ XSS/SQLi/LFI detection
- 🛡️ Cloudflare/WAF bypass techniques
- 📊 Organized reporting system
- ⚡ Multi-threaded scanning

## Installation

```bash
git clone --recurse-submodules https://github.com/Mistra1n/Websentry.git
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

# WAF testing
python3 scripts/waf_breaker.py https://example.com


# Install tools
if any error just install the error pakage or contact me 2547264268**
tool not complete or it is madify to your option
