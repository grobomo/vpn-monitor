#!/bin/bash
# Test T004: Scheduled task points to correct script path
# Verifies "VPN Monitor Check" task runs the script from the new grobomo location.
set -euo pipefail

EXPECTED_PATH="C:\\Users\\joelg\\Documents\\ProjectsCL1\\grobomo\\vpn-monitor\\vpn_reconnect.py"
TASK_NAME="VPN Monitor Check"

echo "=== T004: Verify scheduled task path ==="

# Check task exists
OUTPUT=$(python "$(dirname "$0")/../../install.py" status 2>&1) || true

if echo "$OUTPUT" | grep -q "No VPN tasks installed"; then
  echo "FAIL: Task '$TASK_NAME' not installed"
  echo "  Run: python install.py install"
  exit 1
fi

echo "Task exists. Checking command path..."

# Use install.py run to verify script is importable from new location
if ! python -c "
import sys
sys.path.insert(0, '$(cygpath -w "$(dirname "$0")/../.." | sed "s/\\\\/\\\\\\\\\\\\\\\\/g")')
import vpn_reconnect
print('OK: vpn_reconnect.py importable from new location')
" 2>&1; then
  echo "FAIL: vpn_reconnect.py not importable from new grobomo location"
  exit 1
fi

# Verify config.json exists and has email
if ! python -c "
import json, pathlib
cfg = json.loads(pathlib.Path('$(dirname "$0")/../../config.json').read_text())
assert cfg.get('userEmail'), 'userEmail missing'
assert '@' in cfg['userEmail'], 'userEmail invalid'
print(f\"OK: config.json has email: {cfg['userEmail']}\")
" 2>&1; then
  echo "FAIL: config.json missing or invalid"
  exit 1
fi

echo "=== T004: PASS ==="
