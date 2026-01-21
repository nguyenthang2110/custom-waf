#!/bin/bash

# Test blacklist/whitelist with NON-bypass endpoints
# The /health and /api/* endpoints bypass WAF, so we need to test with the proxy

BASE_URL="http://localhost:8080"
API_URL="${BASE_URL}/api"

echo "=============================================="
echo "WAF Blacklist/Whitelist BLOCKING Test v2"
echo "(Using proxy endpoint instead of /health)"
echo "=============================================="
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get our IP
echo -e "${BLUE}Step 1: Getting our IP address...${NC}"
curl -s "${BASE_URL}/health" > /dev/null
sleep 1
OUR_IP=$(curl -s "${API_URL}/ips" | jq -r '.[0].ip' 2>/dev/null)
echo -e "Our IP: ${YELLOW}${OUR_IP}${NC}"
echo ""

# Test endpoint that goes through WAF (root proxy path)
TEST_ENDPOINT="${BASE_URL}/"

# Test 1: Normal request
echo -e "${BLUE}Step 2: Testing normal proxied request (should succeed or fail due to backend)...${NC}"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TEST_ENDPOINT}")
echo -e "Response: ${YELLOW}HTTP $RESPONSE${NC}"
echo ""

# Test 2: Blacklist our IP
echo -e "${BLUE}Step 3: Adding our IP to BLACKLIST...${NC}"
curl -s -X POST "${API_URL}/blacklist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${OUR_IP}\"}" | jq '.'
echo ""

# Verify blacklist
echo -e "${BLUE}Step 4: Verifying blacklist...${NC}"
curl -s "${API_URL}/blacklist" | jq '.ips[]'
echo ""

# Test 3: Try proxied request while blacklisted
echo -e "${BLUE}Step 5: Testing proxied request while BLACKLISTED (should be 403)...${NC}"
RESPONSE=$(curl -s -o /tmp/waf_block.html -w "%{http_code}" "${TEST_ENDPOINT}")
if [ "$RESPONSE" -eq 403 ]; then
    echo -e "${GREEN}✓✓✓ SUCCESS! Request BLOCKED (HTTP $RESPONSE)${NC}"
    echo -e "${YELLOW}Block page preview:${NC}"
    cat /tmp/waf_block.html | grep -i "access denied\|blocked" | head -2
else
    echo -e "${RED}✗ Request NOT blocked (HTTP $RESPONSE) - Expected 403${NC}"
fi
echo ""

# Test 4: Check stats
echo -e "${BLUE}Step 6: Checking stats for blocks...${NC}"
STATS=$(curl -s "${API_URL}/stats/overview")
BLOCKED=$(echo $STATS | jq -r '.blocked')
echo -e "Total blocked: ${YELLOW}${BLOCKED}${NC}"
echo "Full stats:"
echo $STATS | jq '.'
echo ""

# Test 5: Remove from blacklist
echo -e "${BLUE}Step 7: Removing from blacklist...${NC}"
curl -s -X DELETE "${API_URL}/blacklist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${OUR_IP}\"}" | jq '.'
echo ""

# Test 6: Verify requests work now
echo -e "${BLUE}Step 8: Testing after removing from blacklist...${NC}"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TEST_ENDPOINT}")
echo -e "Response: ${YELLOW}HTTP $RESPONSE${NC}"
if [ "$RESPONSE" -ne 403 ]; then
    echo -e "${GREEN}✓ Request is no longer blocked${NC}"
fi
echo ""

# Test 7: Test WHITELIST
echo -e "${BLUE}Step 9: Adding to WHITELIST...${NC}"
curl -s -X POST "${API_URL}/whitelist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${OUR_IP}\"}" | jq '.'
echo ""

# Test 8: Make requests that would normally be rate limited
echo -e "${BLUE}Step 10: Testing whitelist with 50 rapid requests (checking rate limit bypass)...${NC}"
SUCCESS=0
BLOCKED=0
for i in {1..50}; do
    RESP=$(curl -s -o /dev/null -w "%{http_code}" "${TEST_ENDPOINT}")
    if [ "$RESP" -eq 429 ] || [ "$RESP" -eq 403 ]; then
        ((BLOCKED++))
    else
        ((SUCCESS++))
    fi
done
echo -e "Success: ${GREEN}${SUCCESS}${NC}, Blocked: ${RED}${BLOCKED}${NC}"
if [ "$BLOCKED" -eq 0 ]; then
    echo -e "${GREEN}✓✓✓ Whitelist working - no rate limiting!${NC}"
else
    echo -e "${YELLOW}⚠ Some requests were blocked despite whitelist${NC}"
fi
echo ""

# Test 9: Priority test - add to BOTH
echo -e "${BLUE}Step 11: Testing PRIORITY - adding to both whitelist AND blacklist...${NC}"
curl -s -X POST "${API_URL}/blacklist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${OUR_IP}\"}" > /dev/null
echo "IP is now in BOTH whitelist and blacklist"
echo ""

echo -e "${BLUE}Step 12: Making request (blacklist has higher priority, should be BLOCKED)...${NC}"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${TEST_ENDPOINT}")
if [ "$RESPONSE" -eq 403 ]; then
    echo -e "${GREEN}✓✓✓ CORRECT! Blacklist has priority (HTTP $RESPONSE)${NC}"
else
    echo -e "${RED}✗ Expected 403, got HTTP $RESPONSE${NC}"
fi
echo ""

# Cleanup
echo -e "${BLUE}Cleanup: Removing from both lists...${NC}"
curl -s -X DELETE "${API_URL}/blacklist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" > /dev/null
curl -s -X DELETE "${API_URL}/whitelist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" > /dev/null
echo -e "${GREEN}Done!${NC}"
echo ""

echo -e "${GREEN}=============================================="
echo "Test Complete!"
echo "==============================================\${NC}"

rm -f /tmp/waf_block.html
