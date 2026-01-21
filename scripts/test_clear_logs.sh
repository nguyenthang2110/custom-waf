#!/bin/bash

# Test script for the "Clear All Logs" functionality

set -e

echo "========================================="
echo "Testing WAF Clear All Logs Functionality"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_BASE="http://localhost:8080"

# Function to print test results
print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ PASSED${NC}: $2"
    else
        echo -e "${RED}✗ FAILED${NC}: $2"
        exit 1
    fi
}

echo "Step 1: Checking if WAF server is running..."
if curl -s "${API_BASE}/health" > /dev/null 2>&1; then
    print_result 0 "WAF server is running"
else
    print_result 1 "WAF server is not running. Please start it first."
fi

echo ""
echo "Step 2: Generating test traffic to create logs..."
# Generate some test requests
for i in {1..5}; do
    curl -s "${API_BASE}/test-endpoint-${i}" > /dev/null 2>&1
done
sleep 1
print_result 0 "Generated 5 test requests"

echo ""
echo "Step 3: Checking initial log count..."
INITIAL_COUNT=$(curl -s "${API_BASE}/api/logs" | jq '.metadata.total')
echo "   Current log count: ${INITIAL_COUNT}"
if [ "$INITIAL_COUNT" -gt 0 ]; then
    print_result 0 "Logs are present (count: ${INITIAL_COUNT})"
else
    print_result 1 "No logs found. Expected at least 5 logs."
fi

echo ""
echo "Step 4: Testing Clear Logs API endpoint..."
CLEAR_RESPONSE=$(curl -s -X POST "${API_BASE}/api/logs/clear" -H "Content-Type: application/json")
SUCCESS=$(echo "$CLEAR_RESPONSE" | jq -r '.success')
MESSAGE=$(echo "$CLEAR_RESPONSE" | jq -r '.message')

if [ "$SUCCESS" = "true" ]; then
    print_result 0 "Clear logs API returned success: ${MESSAGE}"
else
    print_result 1 "Clear logs API failed: ${MESSAGE}"
fi

echo ""
echo "Step 5: Verifying logs were cleared..."
sleep 1
FINAL_COUNT=$(curl -s "${API_BASE}/api/logs" | jq '.metadata.total')
echo "   Final log count: ${FINAL_COUNT}"

# Note: There might be new logs from the requests we just made
if [ "$FINAL_COUNT" -lt "$INITIAL_COUNT" ]; then
    print_result 0 "Logs were cleared successfully (count reduced from ${INITIAL_COUNT} to ${FINAL_COUNT})"
else
    print_result 1 "Logs were not cleared properly (count: ${INITIAL_COUNT} -> ${FINAL_COUNT})"
fi

echo ""
echo "Step 6: Checking audit log for clear event..."
if grep -q "LOGS_CLEARED" /Users/nguyenthang/waf-project/logs/waf/audit.log; then
    print_result 0 "Clear event was logged in audit.log"
else
    print_result 1 "Clear event was not found in audit.log"
fi

echo ""
echo "========================================="
echo -e "${GREEN}All tests passed!${NC}"
echo "========================================="
echo ""
echo "To test the UI Button:"
echo "1. Open http://localhost:8080/dashboard in your browser"
echo "2. Navigate to the 'Live Logs' tab"
echo "3. Generate some traffic to create logs"
echo "4. Click the red 'Clear All Logs' button"
echo "5. Confirm the action in the dialog"
echo "6. Verify that:"
echo "   - A success notification appears"
echo "   - The logs table is cleared/refreshed"
echo "   - The log count shows 0 (or only new logs)"
echo ""
