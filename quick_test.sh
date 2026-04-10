#!/bin/bash
TARGET="malikes-zone.tappi.ke"

echo "Quick Security Test - $TARGET"
echo "=============================="

# 1. Check if site is up
echo -e "\n[1] Site Status:"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" "https://$TARGET"

# 2. Get headers
echo -e "\n[2] Security Headers:"
curl -sI "https://$TARGET" | grep -E "(Server|X-|Content-Security|Strict-Transport)"

# 3. Quick XSS test
echo -e "\n[3] Quick XSS Check:"
dalfox url "https://$TARGET" --silence --no-color | head -5

# 4. Open ports
echo -e "\n[4] Open Ports:"
timeout 10 nc -zv "$TARGET" 80 443 8080 8443 2>&1

echo -e "\n=============================="
echo "Test Complete!"
