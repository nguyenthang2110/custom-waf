#!/bin/bash

# Test whitelist with actual attack patterns (SQL injection, XSS)
BASE_URL="http://localhost:8080"
API_URL="${BASE_URL}/api"

echo "=============================================="
echo "Whitelist Test with Attack Patterns"
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
echo -e "Our IP: ${YELLOW}${OUR_IP}${NC}"
echo ""

# Test 1: Send SQL injection WITHOUT whitelist
echo -e "${BLUE}Test 1: SQL Injection attack WITHOUT whitelist (should be blocked)${NC}"
RESPONSE=$(curl -s -o /tmp/response.txt -w "%{http_code}" "${BASE_URL}/?id=1' OR '1'='1")
echo -e "Response code: ${YELLOW}${RESPONSE}${NC}"
if [ "$RESPONSE" -eq 403 ]; then
    echo -e "${GREEN}✓ Attack blocked!${NC}"
else
    echo -e "${YELLOW}Response: ${RESPONSE} (might not be blocked due to low score)${NC}"
fi
echo ""

# Test 2: Send XSS attack WITHOUT whitelist
echo -e "${BLUE}Test 2: XSS attack WITHOUT whitelist (should be blocked)${NC}"
RESPONSE=$(curl -s -o /tmp/response.txt -w "%{http_code}" "${BASE_URL}/?q=<script>alert('xss')</script>")
echo -e "Response code: ${YELLOW}${RESPONSE}${NC}"
if [ "$RESPONSE" -eq 403 ]; then
    echo -e "${GREEN}✓ Attack blocked!${NC}"
else
    echo -e "${YELLOW}Response: ${RESPONSE}${NC}"
fi
echo ""

# Check stats
echo -e "${BLUE}Current block stats:${NC}"
curl -s "${API_URL}/stats/overview" | jq '{blocked, total_requests, block_rate}'
echo ""

# Test 3: Add to whitelist
echo -e "${BLUE}Test 3: Adding our IP to WHITELIST...${NC}"
curl -s -X POST "${API_URL}/whitelist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" | jq '.'
echo ""

# Test 4: Try same attacks WITH whitelist
echo -e "${BLUE}Test 4: SQL Injection WITH whitelist (should bypass WAF)${NC}"
RESPONSE=$(curl -s -o /tmp/response.txt -w "%{http_code}" "${BASE_URL}/?id=1' OR '1'='1")
echo -e "Response code: ${YELLOW}${RESPONSE}${NC}"
if [ "$RESPONSE" -ne 403 ]; then
    echo -e "${GREEN}✓ Whitelist working - attack bypassed WAF!${NC}"
else
    echo -e "${RED}✗ Still blocked despite whitelist${NC}"
fi
echo ""

echo -e "${BLUE}Test 5: XSS WITH whitelist (should bypass WAF)${NC}"
RESPONSE=$(curl -s -o /tmp/response.txt -w "%{http_code}" "${BASE_URL}/?q=<script>alert('xss')</script>")
echo -e "Response code: ${YELLOW}${RESPONSE}${NC}"
if [ "$RESPONSE" -ne 403 ]; then
    echo -e "${GREEN}✓ Whitelist working - attack bypassed WAF!${NC}"
else
    echo -e "${RED}✗ Still blocked despite whitelist${NC}"
fi
echo ""

# Cleanup
echo -e "${BLUE}Cleanup: Removing from whitelist...${NC}"
curl -s -X DELETE "${API_URL}/whitelist" -H "Content-Type: application/json" -d "{\"ip\":\"${OUR_IP}\"}" | jq '.'
echo ""

echo -e "${GREEN}Test Complete!${NC}"
rm -f /tmp/response.txt
