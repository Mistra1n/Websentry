# WebSentry 🛡️

**Advanced Web Vulnerability Scanner with WAF Bypass Capabilities**

![WebSentry Logo](https://i.imgur.com/JQ9w8Bp.png) *(placeholder image)*

## Features

- 🌐 Full website reconnaissance
- 🕵️‍♂️ XSS/SQLi/LFI detection
- 🛡️ Cloudflare/WAF bypass techniques
- 📊 Organized reporting system
- ⚡ Multi-threaded scanning

## Installation

```bash
git clone --recurse-submodules https://github.com/yourusername/WebSentry.git
cd WebSentry
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install tools
chmod +x setup.sh
./setup.sh

Usage

# Basic scan
python3 scripts/websentry.py scan example.com

# Full scan with all tests
python3 scripts/websentry.py full-scan example.com --waf-bypass

# XSS-only scan
python3 scripts/websentry.py xss-scan example.com/login

# WAF testing
python3 scripts/waf_breaker.py https://example.com
