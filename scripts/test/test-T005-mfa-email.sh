#!/bin/bash
# Test T005: MFA email notification sends successfully
# Sends a test email with number "42" and verifies no errors.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"

echo "=== T005: Test MFA email notification ==="

# Verify msgraph-lib is reachable
if ! python -c "
import sys, os
sys.path.insert(0, os.path.expanduser('~/Documents/ProjectsCL1/_tmemu/msgraph-lib'))
from token_manager import graph_post
print('OK: msgraph-lib loaded')
" 2>&1; then
  echo "FAIL: Cannot import msgraph-lib/token_manager"
  echo "  Check ~/Documents/ProjectsCL1/_tmemu/msgraph-lib/ exists"
  exit 1
fi

# Send test email via --test-email flag
OUTPUT=$(cd "$SCRIPT_DIR" && python vpn_reconnect.py --test-email 2>&1)
EXIT_CODE=$?

echo "$OUTPUT"

if [ $EXIT_CODE -ne 0 ]; then
  echo "FAIL: --test-email exited with code $EXIT_CODE"
  exit 1
fi

if echo "$OUTPUT" | grep -q "Test email sent successfully"; then
  # Verify subject is just the number (no "VPN MFA:" prefix for security)
  if echo "$OUTPUT" | grep -q "VPN MFA:"; then
    echo "FAIL: Subject still contains 'VPN MFA:' — should be just the number"
    exit 1
  fi
  echo "=== T005: PASS ==="
  exit 0
else
  echo "FAIL: Expected 'Test email sent successfully' in output"
  exit 1
fi
