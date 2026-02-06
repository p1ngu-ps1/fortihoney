#!/bin/bash
#
# FortiHoney Test Script
# Runs comprehensive tests on the honeypot
#

set -e

echo "=============================================="
echo "🧪 FortiHoney Test Suite"
echo "=============================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

API_KEY=$(grep FORTIHONEY_API_KEY .env 2>/dev/null | cut -d'=' -f2 || echo "")
BASE_URL="http://localhost:3000"

test_count=0
pass_count=0
fail_count=0

run_test() {
    test_count=$((test_count + 1))
    echo -n "Test $test_count: $1... "
}

test_pass() {
    pass_count=$((pass_count + 1))
    echo -e "${GREEN}✓ PASS${NC}"
}

test_fail() {
    fail_count=$((fail_count + 1))
    echo -e "${RED}✗ FAIL${NC}"
    if [ ! -z "$1" ]; then
        echo "  Error: $1"
    fi
}

# Test 1: Server is running
run_test "Server is running"
if curl -s -o /dev/null -w "%{http_code}" $BASE_URL/ | grep -q "307"; then
    test_pass
else
    test_fail "Server not responding"
    exit 1
fi

# Test 2: Root redirects to login
run_test "Root redirects to /remote/login"
if curl -s -I $BASE_URL/ | grep -q "Location.*login"; then
    test_pass
else
    test_fail
fi

# Test 3: Login page loads
run_test "Login page loads"
if curl -s $BASE_URL/remote/login | grep -q "Please Login"; then
    test_pass
else
    test_fail
fi

# Test 4: Static files load
run_test "CSS file loads"
if curl -s -o /dev/null -w "%{http_code}" $BASE_URL/css/legacy-main.css | grep -q "200"; then
    test_pass
else
    test_fail
fi

# Test 5: Login attempt logs correctly
run_test "Login attempt is logged"
curl -s -X POST $BASE_URL/remote/logincheck \
    -d "username=testuser&credential=testpass" \
    > /dev/null 2>&1
sleep 1
if grep -q "testuser" logs/fortihoney.json 2>/dev/null; then
    test_pass
else
    test_fail "Login not logged"
fi

# Test 6: Security headers present
run_test "Security headers present"
headers=$(curl -s -I $BASE_URL/remote/login)
if echo "$headers" | grep -q "X-Frame-Options" && \
   echo "$headers" | grep -q "X-Content-Type-Options" && \
   echo "$headers" | grep -q "Content-Security-Policy"; then
    test_pass
else
    test_fail "Missing security headers"
fi

# Test 7: Rate limiting works
run_test "Rate limiting works"
for i in {1..25}; do
    curl -s $BASE_URL/ > /dev/null 2>&1
done
if grep -q "rate_limit_exceeded" logs/fortihoney.json 2>/dev/null; then
    test_pass
else
    test_fail "Rate limiting not working"
fi

# Wait for rate limit to reset
echo "  Waiting 60s for rate limit reset..."
sleep 60

# Test 8: API requires authentication
run_test "API requires authentication"
response=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/api/v1/logs)
if [ "$response" == "401" ]; then
    test_pass
else
    test_fail "Expected 401, got $response"
fi

# Test 9: API rejects wrong key
run_test "API rejects invalid key"
response=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer wrongkey" \
    $BASE_URL/api/v1/logs)
if [ "$response" == "403" ]; then
    test_pass
else
    test_fail "Expected 403, got $response"
fi

# Test 10: API accepts valid key
if [ ! -z "$API_KEY" ]; then
    run_test "API accepts valid key"
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $API_KEY" \
        $BASE_URL/api/v1/logs)
    if [ "$response" == "200" ]; then
        test_pass
    else
        test_fail "Expected 200, got $response"
    fi
else
    run_test "API key configured"
    test_fail "No API key in .env"
fi

# Test 11: Stats endpoint works
if [ ! -z "$API_KEY" ]; then
    run_test "Stats endpoint works"
    response=$(curl -s -H "Authorization: Bearer $API_KEY" \
        $BASE_URL/api/v1/stats)
    if echo "$response" | grep -q "total_events"; then
        test_pass
    else
        test_fail
    fi
fi

# Test 12: Suspicious request detection
run_test "Suspicious request flagged"
curl -s "$BASE_URL/../etc/passwd" > /dev/null 2>&1
sleep 1
if grep -q '"suspicious": true' logs/fortihoney.json 2>/dev/null; then
    test_pass
else
    test_fail "Suspicious pattern not detected"
fi

# Test 13: GeoIP lookup works
run_test "GeoIP enrichment works"
if grep -q '"country"' logs/fortihoney.json 2>/dev/null; then
    test_pass
else
    test_fail "No country data in logs"
fi

# Summary
echo ""
echo "=============================================="
echo "📊 Test Results"
echo "=============================================="
echo "Total tests: $test_count"
echo -e "${GREEN}Passed: $pass_count${NC}"
if [ $fail_count -gt 0 ]; then
    echo -e "${RED}Failed: $fail_count${NC}"
else
    echo -e "${GREEN}Failed: $fail_count${NC}"
fi
echo "=============================================="
echo ""

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed${NC}"
    exit 1
fi
