#!/usr/bin/env python3
"""
Black-Box Reconnaissance Toolkit
A comprehensive Phase 1 reconnaissance automation framework for authorized penetration testing.

Author: Ukasha Mehmood
License: MIT
"""

import requests
import socket
import ssl
import time
import random
import json
import os
import sys
import argparse
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
import warnings
warnings.filterwarnings('ignore')

class ReconToolkit:
    def __init__(self, target_domain, target_url=None, threads=10, timeout=15, delay=(0.5, 2.0)):
        self.target_domain = target_domain
        self.target_url = target_url or f"https://{target_domain}"
        self.threads = threads
        self.timeout = timeout
        self.delay_min, self.delay_max = delay
        self.output_dir = "recon_output"
        os.makedirs(self.output_dir, exist_ok=True)

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        ]

        self.sensitive_paths = self._load_sensitive_paths()
        self.subdomain_wordlist = self._load_wordlist()

    def _load_sensitive_paths(self):
        """Load sensitive file paths for discovery"""
        return [
            ".env", ".env.local", ".env.production", ".env.dev", ".env.backup",
            ".env.save", ".env.swp", ".env~", ".env.old", ".env.dist",
            "env.txt", "environment.txt",
            ".git/config", ".git/HEAD", ".git/index", ".gitignore",
            "config.php", "config.php.bak", "config.php~", "wp-config.php",
            "database.yml", "settings.py", "application.properties",
            "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
            "phpinfo.php", "info.php", "test.php",
            "api/", "api/v1/", "swagger.json", "api-docs/",
            "robots.txt", "sitemap.xml",
            "admin/", "administrator/", "wp-admin/", "login/", "signin/",
            "uploads/", "files/", "documents/",
            "README.md", "composer.json", "package.json",
            "Dockerfile", "docker-compose.yml",
        ]

    def _load_wordlist(self):
        """Load subdomain wordlist"""
        wordlist_path = os.path.join(os.path.dirname(__file__), "..", "wordlists", "subdomains.txt")
        if os.path.exists(wordlist_path):
            with open(wordlist_path) as f:
                return [line.strip() for line in f if line.strip()]
        return ["www", "mail", "ftp", "localhost", "webmail", "smtp", "api", "admin", "test", "dev", "staging"]

    def get_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'DNT': '1',
        }

    def random_delay(self):
        time.sleep(random.uniform(self.delay_min, self.delay_max))

    def request(self, url, method='GET', headers=None, allow_redirects=True, retries=3):
        """Make HTTP request with retry logic and delays"""
        default_headers = self.get_headers()
        if headers:
            default_headers.update(headers)

        for attempt in range(retries):
            try:
                self.random_delay()
                resp = requests.request(
                    method, url, headers=default_headers, timeout=self.timeout,
                    allow_redirects=allow_redirects, verify=False
                )
                return resp
            except requests.exceptions.Timeout:
                print(f"    [!] Timeout on {url}, attempt {attempt+1}/{retries}")
                time.sleep(5)
            except Exception as e:
                if attempt == retries - 1:
                    return None
                time.sleep(3)
        return None

    def log(self, category, data, filename):
        path = os.path.join(self.output_dir, f"{filename}.json")
        with open(path, 'a') as f:
            json.dump({"timestamp": time.strftime("%Y-%m-%d %H:%M:%S"), "category": category, **data}, f)
            f.write("\n")

    def dns_resolution(self):
        """Resolve DNS records"""
        print(f"[*] DNS Resolution for {self.target_domain}")
        results = {"domain": self.target_domain, "records": {}}

        try:
            ips = socket.gethostbyname_ex(self.target_domain)[2]
            results["records"]["A"] = ips
            print(f"    [A] {', '.join(ips)}")
        except Exception as e:
            results["records"]["A_error"] = str(e)

        for qtype in ['MX', 'NS', 'TXT']:
            try:
                import subprocess
                output = subprocess.check_output(
                    ["nslookup", f"-query={qtype}", self.target_domain],
                    stderr=subprocess.DEVNULL, timeout=10
                ).decode()
                results["records"][qtype] = output
                print(f"    [{qtype}] Records found")
            except:
                pass

        self.log("dns", results, "dns_records")
        return results

    def subdomain_enum(self):
        """Bruteforce subdomains"""
        print(f"[*] Subdomain Enumeration for {self.target_domain}")
        found = []

        def check(sub):
            subdomain = f"{sub}.{self.target_domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                print(f"    [FOUND] {subdomain} -> {ip}")
                return {"subdomain": subdomain, "ip": ip}
            except:
                return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, sub): sub for sub in self.subdomain_wordlist}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)

        print(f"    [+] Found {len(found)} subdomains")
        self.log("subdomains", {"count": len(found), "subdomains": found}, "subdomains")
        return found

    def tech_fingerprint(self):
        """Fingerprint web technologies"""
        print(f"[*] Technology Fingerprinting for {self.target_url}")
        results = {"url": self.target_url, "technologies": []}

        resp = self.request(self.target_url)
        if not resp:
            print("    [!] Could not reach target")
            return results

        headers = resp.headers
        body = resp.text[:5000].lower()

        # Server header
        server = headers.get('Server', 'Unknown')
        results["technologies"].append({"type": "server", "value": server})
        print(f"    [Server] {server}")

        # X-Powered-By
        powered = headers.get('X-Powered-By', '')
        if powered:
            results["technologies"].append({"type": "powered_by", "value": powered})
            print(f"    [X-Powered-By] {powered}")

        # Framework detection
        frameworks = {
            'laravel': ['laravel', 'csrf-token'],
            'wordpress': ['wp-content', 'wp-includes', '/wp-json/'],
            'django': ['csrfmiddlewaretoken', 'django'],
            'rails': ['authenticity_token', 'rails'],
            'react': ['reactroot', 'react-dom'],
            'angular': ['ng-app', 'angular.js'],
        }

        for framework, indicators in frameworks.items():
            for indicator in indicators:
                if indicator in body:
                    results["technologies"].append({"type": "framework", "name": framework})
                    print(f"    [Framework] {framework}")
                    break

        # Cookie detection
        cookies = headers.get('Set-Cookie', '')
        cookie_indicators = {
            'PHPSESSID': 'PHP',
            'laravel_session': 'Laravel',
            'wordpress_logged_in': 'WordPress',
            'django_session': 'Django',
        }
        for cookie_name, tech in cookie_indicators.items():
            if cookie_name in cookies:
                results["technologies"].append({"type": "framework", "name": tech, "method": "cookie"})
                print(f"    [Cookie] {tech} detected")

        self.log("fingerprint", results, "technology_fingerprint")
        return results

    def sensitive_file_hunt(self, base_urls=None):
        """Hunt for exposed sensitive files"""
        base_urls = base_urls or [self.target_url]
        print(f"[*] Sensitive File Hunt")
        findings = []

        def check(base_url, path):
            url = urljoin(base_url, path)
            resp = self.request(url, allow_redirects=False)  # FIXED: removed timeout kwarg
            if resp and resp.status_code == 200:
                content_length = len(resp.content)
                content_type = resp.headers.get('Content-Type', 'unknown')

                if 'text/html' in content_type and content_length < 500:
                    return None

                severity = "CRITICAL" if '.env' in path else "HIGH"
                print(f"    [{severity}] {url} | Size: {content_length}")

                finding = {
                    "url": url,
                    "status": resp.status_code,
                    "size": content_length,
                    "content_type": content_type,
                    "severity": severity,
                }
                if '.env' in path and content_length < 50000:
                    finding["preview"] = resp.text[:500]
                return finding
            return None

        checks = [(base, path) for base in base_urls for path in self.sensitive_paths]

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, base, path): (base, path) for base, path in checks}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    findings.append(result)
                    self.log("sensitive_file", result, "sensitive_files")

        print(f"    [+] Found {len(findings)} sensitive files")
        return findings

    def ssl_analysis(self):
        """Analyze SSL/TLS configuration"""
        print(f"[*] SSL/TLS Analysis for {self.target_domain}")
        results = {"domain": self.target_domain}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    cert = ssock.getpeercert()
                    results.update({
                        "ssl_version": ssock.version(),
                        "cipher": ssock.cipher(),
                        "subject": cert.get('subject'),
                        "issuer": cert.get('issuer'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    })
                    print(f"    [SSL] {ssock.version()} | Subject: {cert.get('subject')}")
        except Exception as e:
            results["error"] = str(e)
            print(f"    [!] SSL Error: {e}")

        self.log("ssl", results, "ssl_analysis")
        return results

    def port_scan(self, ports=None):
        """Lightweight port scan"""
        ports = ports or [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443, 8888, 9000]
        print(f"[*] Port Scan for {self.target_domain}")
        open_ports = []

        def check(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                if sock.connect_ex((self.target_domain, port)) == 0:
                    print(f"    [OPEN] Port {port}")
                    return {"port": port, "state": "open"}
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(check, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)

        self.log("ports", {"ports": open_ports}, "port_scan")
        return open_ports

    def run_all(self):
        """Execute all reconnaissance modules"""
        print("="*60)
        print("BLACK-BOX RECONNAISSANCE TOOLKIT")
        print(f"Target: {self.target_domain}")
        print("="*60)

        self.dns_resolution()
        self.subdomain_enum()
        self.ssl_analysis()
        self.tech_fingerprint()
        self.sensitive_file_hunt()
        self.port_scan()

        print("\n" + "="*60)
        print("RECONNAISSANCE COMPLETE")
        print(f"Results saved to: {self.output_dir}/")
        print("="*60)


def main():
    parser = argparse.ArgumentParser(description="Black-Box Reconnaissance Toolkit")
    parser.add_argument("-d", "--domain", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-u", "--url", help="Target URL (default: https://domain)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds (default: 15)")
    parser.add_argument("--delay-min", type=float, default=0.5, help="Minimum delay between requests")
    parser.add_argument("--delay-max", type=float, default=2.0, help="Maximum delay between requests")

    args = parser.parse_args()

    toolkit = ReconToolkit(
        target_domain=args.domain,
        target_url=args.url,
        threads=args.threads,
        timeout=args.timeout,
        delay=(args.delay_min, args.delay_max)
    )
    toolkit.run_all()


if __name__ == "__main__":
    main()