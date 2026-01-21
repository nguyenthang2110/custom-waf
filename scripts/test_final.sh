#!/bin/bash

# Comprehensive Whitelist/Blacklist Test with new config
BASE_URL="http://localhost:8080"
API_URL="${BASE_URL}/api"

echo "=============================================="
echo "FINAL Whitelist/Blacklist Test"
echo "(With enable_whitelist/enable_blacklist config)"
echo "=============================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get our IP
curl -s "${BASE_URL}/health" > /dev/null
sleep 1
OUR_IP=$(curl -s "${API_URL}/ips" | jq -r '.[0].ip' 2>/dev/null)
echo -e "Testing IP: ${YELLOW}${OUR_IP}${NC}"
echo ""

# ==================== BLACKLIST TESTS ====================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}         BLACKLIST TESTS                  ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BLUE}1. Normal request (baseline)${NC}"
RESP=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/?test=normal")
echo -e "   Response: ${YELLOW}HTTP $RESP${NC}"
echo ""

echo -e "${BLUE}2. Adding IP to BLACKLIST${NC}"
curl -s -X POST "${API_URL}/blacklist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" | jq -r '.status'
echo ""

echo -e "${BLUE}3. Testing request while BLACKLISTED (should be 403)${NC}"
RESP=$(curl -s -o /tmp/block.html -w "%{http_code}" "${BASE_URL}/?test=blacklisted")
if [ "$RESP" -eq 403 ]; then
    echo -e "   ${GREEN}✓✓✓ SUCCESS! Blacklisted IP blocked (HTTP $RESP)${NC}"
    cat /tmp/block.html | grep -i "blacklisted" | head -1
else
    echo -e "   ${RED}✗ FAILED - Expected 403, got HTTP $RESP${NC}"
fi
echo ""

echo -e "${BLUE}4. Removing from BLACKLIST${NC}"
curl -s -X DELETE "${API_URL}/blacklist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" | jq -r '.status'
echo ""

# ==================== WHITELIST TESTS ====================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}         WHITELIST TESTS                  ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BLUE}5. Sending XSS attack (should be BLOCKED)${NC}"
RESP=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/?q=<script>alert('xss')</script>")
if [ "$RESP" -eq 403 ]; then
    echo -e "   ${GREEN}✓ Attack blocked (HTTP $RESP)${NC}"
else
    echo -e "   ${YELLOW}Not blocked (HTTP $RESP)${NC}"
fi
echo ""

echo -e "${BLUE}6. Adding IP to WHITELIST${NC}"
curl -s -X POST "${API_URL}/whitelist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" | jq -r '.status'
echo ""

echo -e "${BLUE}7. Testing XSS with WHITELIST (should be ALLOWED)${NC}"
RESP=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/?q=<script>alert('xss')</script>")
if [ "$RESP" -ne 403 ]; then
    echo -e "   ${GREEN}✓✓✓ SUCCESS! Whitelist bypassed WAF (HTTP $RESP)${NC}"
else
    echo -e "   ${RED}✗ FAILED - Still blocked (HTTP $RESP)${NC}"
fi
echo ""

echo -e "${BLUE}8. Testing 100 rapid requests (rate limit bypass)${NC}"
SUCCESS=0
for i in {1..100}; do
    R=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/?i=$i")
    [ "$R" -ne 403 ] && [ "$R" -ne 429 ] && ((SUCCESS++))
done
echo -e "   Success rate: ${GREEN}${SUCCESS}/100${NC}"
if [ "$SUCCESS" -gt 95 ]; then
    echo -e "   ${GREEN}✓✓✓ Whitelist bypassed rate limiting!${NC}"
else
    echo -e "   ${YELLOW}⚠ Some requests blocked: $((100-SUCCESS))${NC}"
fi
echo ""

# ==================== PRIORITY TEST ====================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}         PRIORITY TEST                    ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

echo -e "${BLUE}9. Adding to BOTH whitelist AND blacklist${NC}"
curl -s -X POST "${API_URL}/blacklist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" > /dev/null
echo "   IP now in BOTH lists"
echo ""

echo -e "${BLUE}10. Testing priority (blacklist should win)${NC}"
RESP=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/?test=priority")
if [ "$RESP" -eq 403 ]; then
    echo -e "   ${GREEN}✓✓✓ SUCCESS! Blacklist has priority (HTTP $RESP)${NC}"
else
    echo -e "   ${RED}✗ FAILED - Expected 403, got HTTP $RESP${NC}"
fi
echo ""

# ==================== CLEANUP ====================
echo -e "${BLUE}Cleanup...${NC}"
curl -s -X DELETE "${API_URL}/blacklist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" > /dev/null
curl -s -X DELETE "${API_URL}/whitelist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" > /dev/null
echo ""

# ==================== FINAL STATS ====================
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}         FINAL STATS                      ${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
curl -s "${API_URL}/stats/overview" | jq '.'
echo ""

echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Test Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

rm -f /tmp/block.html
