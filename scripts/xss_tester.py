#!/usr/bin/env python3
import requests
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

# Configuration
PAYLOAD_FILE = "payloads/xss.txt"
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)"
]
TIMEOUT = 5
THREADS = 10

def load_payloads():
    with open(PAYLOAD_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def test_xss(url, param, payload):
    try:
        # URL encode payload
        encoded_payload = urllib.parse.quote(payload)
        
        # Test in URL parameter
        test_url = f"{url}?{param}={encoded_payload}"
        
        # Test in POST data if URL fails
        test_data = {param: payload}
        
        # Try different user agents
        for ua in USER_AGENTS:
            headers = {"User-Agent": ua}
            
            # Test GET request
            r_get = requests.get(test_url, headers=headers, timeout=TIMEOUT)
            if payload.lower() in r_get.text.lower():
                return f"GET - {test_url}"
            
            # Test POST request
            r_post = requests.post(url, data=test_data, headers=headers, timeout=TIMEOUT)
            if payload.lower() in r_post.text.lower():
                return f"POST - {url} with {param}={payload}"
    
    except Exception as e:
        return None

def scan_url(url):
    print(f"[*] Testing {url}")
    payloads = load_payloads()
    common_params = ["q", "search", "id", "name", "query", "redirect", "url"]
    
    results = []
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for param in common_params:
            for payload in payloads:
                future = executor.submit(test_xss, url, param, payload)
                result = future.result()
                if result:
                    results.append(result)
    
    if results:
        print(f"\n[!] Potential XSS found in {url}:")
        for r in results:
            print(f"  - {r}")
    else:
        print(f"[+] No XSS found in {url}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 xss_tester.py <url>")
        sys.exit(1)
    
    scan_url(sys.argv[1])
