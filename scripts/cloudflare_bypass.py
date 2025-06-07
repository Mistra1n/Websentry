#!/usr/bin/env python3
import requests
import socket
import dns.resolver

# Cloudflare bypass techniques
class CloudflareBypass:
    def __init__(self, domain):
        self.domain = domain
        self.headers = {
            "X-Forwarded-For": "127.0.0.1",
            "CF-Connecting-IP": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0"
        }
    
    def find_origin_ip(self):
        """Try to find origin server IP"""
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
        origin_ip = self.find_origin_ip()
        if origin_ip:
            print("\n[!] Testing direct IP access")
            ip_url = url.replace(self.domain, origin_ip)
            try:
                r = requests.get(ip_url, headers=self.headers, timeout=5)
                if r.status_code == 200:
                    print(f"[+] Direct IP access worked: {ip_url}")
                    return ip_url
            except:
                pass
        
        print("\n[!] Trying header-based bypass")
        try:
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                print(f"[+] Header bypass worked: {url}")
                return url
        except:
            pass
        
        print("\n[!] Trying HTTP/2 protocol")
        try:
            r = requests.get(url, headers=self.headers, timeout=5)
            if r.status_code == 200:
                print(f"[+] HTTP/2 worked: {url}")
                return url
        except:
            pass
        
        return None

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python3 cloudflare_bypass.py <url>")
        sys.exit(1)
    
    from urllib.parse import urlparse
    domain = urlparse(sys.argv[1]).netloc
    bypass = CloudflareBypass(domain)
    bypass.test_bypass(sys.argv[1])
