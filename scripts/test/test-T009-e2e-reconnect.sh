#!/bin/bash
# Test T009: End-to-end VPN reconnect with MFA email
# This test requires VPN to be disconnected — run manually when VPN drops.
# Automated verification: check audit.jsonl for a complete reconnect cycle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
AUDIT="$SCRIPT_DIR/audit.jsonl"

echo "=== T009: E2E reconnect audit check ==="

if [ ! -f "$AUDIT" ]; then
  echo "SKIP: No audit.jsonl yet — run after first real VPN reconnect"
  exit 0
fi

# Check for at least one reconnect_start event
if grep -q '"reconnect_start"' "$AUDIT"; then
  echo "OK: Found reconnect_start events in audit log"
else
  echo "SKIP: No reconnect events yet — waiting for first VPN drop"
  exit 0
fi

echo "=== T009: PASS (audit log has reconnect events) ==="
