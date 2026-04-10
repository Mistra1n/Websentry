#!/usr/bin/env python3
import sys
import requests
from urllib.parse import urlparse

def test_waf(url):
    """Basic WAF detection"""
    test_payloads = [
        "' OR '1'='1",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "UNION SELECT",
        "1 AND 1=1"
    ]
    
    print(f"[*] Testing WAF on {url}")
    
    for payload in test_payloads:
        try:
            r = requests.get(f"{url}?test={payload}", timeout=5)
            if r.status_code in [403, 406, 501]:
                print(f"[!] Possible WAF detected - Payload '{payload}' returned {r.status_code}")
            elif r.status_code == 200:
                print(f"[+] No WAF block for '{payload}'")
        except Exception as e:
            print(f"[-] Error testing {payload}: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        test_waf(sys.argv[1])
    else:
        print("Usage: python3 waf_breaker.py <URL>")
