#!/usr/bin/env python3
import requests
import socket
import sys
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[!] dnspython not available, some bypass techniques disabled")

class CloudflareBypass:
    def __init__(self, domain):
        self.domain = domain
        self.headers = {
            "X-Forwarded-For": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }
    
    def find_origin_ip(self):
        """Try to find origin server IP"""
        if DNS_AVAILABLE:
            try:
                # Check historical DNS records
                answers = dns.resolver.resolve(self.domain, 'A')
                for ip in answers:
                    print(f"[+] Found IP: {ip}")
                    return str(ip)
            except:
                pass
        
        # Check common subdomains that might bypass CF
        subdomains = ["origin", "direct", "backend", "api", "internal"]
        for sub in subdomains:
            try:
                host = f"{sub}.{self.domain}"
                ip = socket.gethostbyname(host)
                print(f"[+] Found direct IP via {host}: {ip}")
                return ip
            except:
                continue
        
        return None
    
    def test_bypass(self, url):
        """Test different bypass techniques"""
        techniques = [
            ("direct IP", self._test_direct_ip),
            ("header bypass", self._test_header_bypass),
            ("HTTP/2", self._test_http2)
        ]
        
        for name, method in techniques:
            print(f"\n[!] Trying {name} bypass")
            result = method(url)
            if result:
                print(f"[+] {name} worked: {result}")
                return result
        
        print("[!] All bypass techniques failed")
        return None
    
    def _test_direct_ip(self, url):
        origin_ip = self.find_origin_ip()
        if origin_ip:
            ip_url = url.replace(self.domain, origin_ip)
            try:
                r = requests.get(ip_url, headers=self.headers, timeout=5)
                if r.status_code == 200:
                    return ip_url
            except:
                pass
        return None
    
    def _test_header_bypass(self, url):
        try:
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                return url
        except:
            pass
        return None
    
    def _test_http2(self, url):
        try:
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                return url
        except:
            pass
        return None

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 cloudflare_bypass.py <url>")
        sys.exit(1)
    
    domain = urlparse(sys.argv[1]).netloc
    bypass = CloudflareBypass(domain)
    result = bypass.test_bypass(sys.argv[1])
    
    if result:
        print(f"\n[+] Successful bypass: {result}")
    else:
        print("\n[!] Could not bypass Cloudflare protection")
