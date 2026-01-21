import requests
import time
import json

BASE_URL = "http://localhost:8080"
TEST_IP = "1.2.3.4"

def main():
    print(f"--- Blacklist Reproduction Test for IP {TEST_IP} ---")

    # 1. Clear Blacklist (optional, but good for clean state)
    # The current API doesn't support "Clear Blacklist", so we just ensure our IP is removed first
    requests.delete(f"{BASE_URL}/api/blacklist", json={"ip": TEST_IP})
    
    # 2. Verify Access (Should be ALLOWED)
    print("\n[1] Testing Access BEFORE Blacklisting...")
    resp = requests.get(f"{BASE_URL}/products", headers={"X-Forwarded-For": TEST_IP})
    print(f"Status: {resp.status_code} | WAF: {resp.headers.get('X-WAF-Status', 'ALLOW')}")
    if resp.status_code != 200:
        print("ERROR: Request was blocked before blacklisting!")
        return

    # 3. Add to Blacklist
    print(f"\n[2] Adding {TEST_IP} to Blacklist...")
    resp = requests.post(f"{BASE_URL}/api/blacklist", json={"ip": TEST_IP})
    print(f"API Response: {resp.status_code} {resp.text}")
    if resp.status_code != 200:
         print("ERROR: Failed to add to blacklist!")
         return

    time.sleep(1) # Give it a moment (though it should be instant)

    # 4. Verify Access (Should be BLOCKED)
    print("\n[3] Testing Access AFTER Blacklisting...")
    resp = requests.get(f"{BASE_URL}/products", headers={"X-Forwarded-For": TEST_IP})
    print(f"Status: {resp.status_code} | WAF: {resp.headers.get('X-WAF-Status', 'ALLOW')}")
    
    if resp.status_code == 403:
        print("SUCCESS: IP was correctly blocked.")
    else:
        print("FAILURE: IP was NOT blocked!")

    # 5. Cleanup
    print(f"\n[4] Removing {TEST_IP} from Blacklist...")
    requests.delete(f"{BASE_URL}/api/blacklist", json={"ip": TEST_IP})

if __name__ == "__main__":
    main()
