#!/bin/bash

# Test script for WAF whitelist/blacklist functionality
# Make sure the WAF is running on localhost:8080

BASE_URL="http://localhost:8080"
API_URL="${BASE_URL}/api"

echo "==================================="
echo "WAF Whitelist/Blacklist Test Script"
echo "==================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test 1: Get current whitelist
echo -e "${YELLOW}1. Getting current whitelist...${NC}"
curl -s "${API_URL}/whitelist" | jq '.'
echo ""

# Test 2: Get current blacklist  
echo -e "${YELLOW}2. Getting current blacklist...${NC}"
curl -s "${API_URL}/blacklist" | jq '.'
echo ""

# Test 3: Add IP to whitelist
TEST_WHITELIST_IP="192.168.1.100"
echo -e "${YELLOW}3. Adding ${TEST_WHITELIST_IP} to whitelist...${NC}"
curl -s -X POST "${API_URL}/whitelist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_WHITELIST_IP}\"}" | jq '.'
echo ""

# Test 4: Verify whitelist
echo -e "${YELLOW}4. Verifying whitelist now contains ${TEST_WHITELIST_IP}...${NC}"
curl -s "${API_URL}/whitelist" | jq '.'
echo ""

# Test 5: Add IP to blacklist
TEST_BLACKLIST_IP="10.0.0.5"
echo -e "${YELLOW}5. Adding ${TEST_BLACKLIST_IP} to blacklist...${NC}"
curl -s -X POST "${API_URL}/blacklist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_BLACKLIST_IP}\"}" | jq '.'
echo ""

# Test 6: Verify blacklist
echo -e "${YELLOW}6. Verifying blacklist now contains ${TEST_BLACKLIST_IP}...${NC}"
curl -s "${API_URL}/blacklist" | jq '.'
echo ""

# Test 7: Make a test request (normal)
echo -e "${YELLOW}7. Testing normal request...${NC}"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "${BASE_URL}/dashboard")
if [ "$RESPONSE" -eq 200 ]; then
    echo -e "${GREEN}✓ Normal request successful (HTTP $RESPONSE)${NC}"
else
    echo -e "${RED}✗ Normal request failed (HTTP $RESPONSE)${NC}"
fi
echo ""

# Test 8: Check stats
echo -e "${YELLOW}8. Checking WAF stats...${NC}"
curl -s "${API_URL}/stats/overview" | jq '.'
echo ""

# Test 9: Remove from whitelist
echo -e "${YELLOW}9. Removing ${TEST_WHITELIST_IP} from whitelist...${NC}"
curl -s -X DELETE "${API_URL}/whitelist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_WHITELIST_IP}\"}" | jq '.'
echo ""

# Test 10: Remove from blacklist
echo -e "${YELLOW}10. Removing ${TEST_BLACKLIST_IP} from blacklist...${NC}"
curl -s -X DELETE "${API_URL}/blacklist" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"${TEST_BLACKLIST_IP}\"}" | jq '.'
echo ""

# Final verification
echo -e "${YELLOW}11. Final verification - both lists should be empty:${NC}"
echo "Whitelist:"
curl -s "${API_URL}/whitelist" | jq '.'
echo "Blacklist:"
curl -s "${API_URL}/blacklist" | jq '.'
echo ""

echo -e "${GREEN}==================================="
echo "Test completed!"
echo "===================================${NC}"
