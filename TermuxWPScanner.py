#!/usr/bin/env python3
"""
WordPress Security Scanner - Termux Edition
"""
import requests
import sys
import time
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class TermuxWPScanner:
    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.vulnerabilities = []
        self.found_users = []
        
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════╗
║         WordPress Scanner            ║
║           Termux Edition             ║
╚═══════════════════════════════════════╝
        """
        print(banner)
    
    def check_wordpress(self):
        """Check if site is running WordPress"""
        print("[*] Checking if target is WordPress...")
        try:
            response = self.session.get(self.target, timeout=10, verify=False)
            if 'wp-content' in response.text or 'wordpress' in response.text.lower():
                print("[+] Confirmed: WordPress site detected")
                return True
            else:
                print("[-] This doesn't appear to be a WordPress site")
                return False
        except Exception as e:
            print(f"[-] Error: {str(e)}")
            return False
    
    def user_enumeration(self):
        """Enumerate WordPress users"""
        print("[*] Attempting user enumeration...")
        
        methods = [
            f"{self.target}/?author=1",
            f"{self.target}/wp-json/wp/v2/users",
            f"{self.target}/wp-json/wp/v2/users/1"
        ]
        
        for method in methods:
            try:
                response = self.session.get(method, timeout=5, verify=False)
                if response.status_code == 200:
                    if 'author' in response.url or 'user' in response.text.lower():
                        print(f"[+] User enumeration possible via: {method}")
                        self.vulnerabilities.append('User Enumeration')
            except:
                continue
    
    def check_xmlrpc(self):
        """Check XML-RPC functionality"""
        print("[*] Checking XML-RPC...")
        try:
            response = self.session.post(
                f"{self.target}/xmlrpc.php",
                data='<methodCall><methodName>system.listMethods</methodName></methodCall>',
                headers={'Content-Type': 'text/xml'},
                timeout=5,
                verify=False
            )
            if 'methodName' in response.text:
                print("[+] XML-RPC is enabled (potential attack vector)")
                self.vulnerabilities.append('XML-RPC Enabled')
        except:
            print("[-] XML-RPC not accessible")
    
    def check_wp_admin(self):
        """Check if wp-admin is accessible"""
        print("[*] Checking wp-admin access...")
        try:
            response = self.session.get(f"{self.target}/wp-admin/", timeout=5, verify=False)
            if response.status_code == 200:
                print("[+] wp-admin is accessible")
                if 'login' in response.text.lower():
                    print("[+] Login page is accessible")
        except:
            print("[-] Cannot access wp-admin")
    
    def scan_plugins(self):
        """Check for common plugins"""
        print("[*] Scanning for common plugins...")
        
        plugins = [
            'wp-content/plugins/contact-form-7/',
            'wp-content/plugins/yoast-seo/',
            'wp-content/plugins/wordfence/',
            'wp-content/plugins/akismet/',
            'wp-content/plugins/woocommerce/'
        ]
        
        found_plugins = []
        for plugin in plugins:
            try:
                response = self.session.get(f"{self.target}/{plugin}", timeout=3, verify=False)
                if response.status_code == 200:
                    found_plugins.append(plugin)
                    print(f"[+] Found plugin: {plugin}")
            except:
                pass
        
        if found_plugins:
            self.vulnerabilities.append(f'Plugins: {", ".join(found_plugins)}')
    
    def run_scan(self):
        """Execute complete scan"""
        self.print_banner()
        print(f"[*] Starting scan of: {self.target}")
        print("[*] This may take a few moments...\n")
        
        if not self.check_wordpress():
            return
        
        # Run all checks
        checks = [
            self.user_enumeration,
            self.check_xmlrpc,
            self.check_wp_admin,
            self.scan_plugins
        ]
        
        for check in checks:
            try:
                check()
                time.sleep(1)  # Be polite
            except Exception as e:
                print(f"[-] Error in {check.__name__}: {str(e)}")
        
        # Print results
        print("\n" + "="*50)
        print("SCAN RESULTS")
        print("="*50)
        
        if self.vulnerabilities:
            print("[!] POTENTIAL VULNERABILITIES FOUND:")
            for vuln in self.vulnerabilities:
                print(f"    • {vuln}")
        else:
            print("[-] No obvious vulnerabilities detected")
        
        print("\n[*] Scan completed!")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python wp-scanner.py http://target-site.com")
        sys.exit(1)
    
    target = sys.argv[1]
    scanner = TermuxWPScanner(target)
    scanner.run_scan()
