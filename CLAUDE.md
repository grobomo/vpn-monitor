# VPN Monitor

> **GitHub:** grobomo (public) | **Status:** Windows production, macOS untested

Auto-reconnects F5 BIG-IP Edge Client VPN with MFA email notification.

## How It Works

1. Scheduled task checks VPN status every 15 min
2. If disconnected: kill stale F5 → countdown warning → start VPN → automate SSO login
3. After clicking "Use an app instead": extract 2-digit MFA number via pywinauto
4. Email the number (subject only, canary in body) → user approves on phone → VPN up

## Key Files

- `vpn_reconnect.py` — main script (all logic)
- `install.py` — cross-platform installer (schtasks/launchd)
- `config.json` — user config (gitignored, has email + canary token)
- `audit.jsonl` — tamper-evident audit log with chained hashes
- `scripts/test/` — test scripts for each task

## Security Model

- **Canary token**: config.json `canaryToken` (emoji) in email body — attacker can't replicate
- **Obscure subject**: just the 2-digit number, no "VPN MFA" label
- **Audit log**: every MFA email send is logged with timestamp, hostname, PID, chained SHA-256
- **No PII in repo**: all employer/user references in gitignored config.json

## Commands

```bash
python install.py install --email you@example.com   # Install (requires UAC)
python install.py status                             # Check scheduled tasks
python install.py run                                # Run once (testing)
python vpn_reconnect.py --test-email                 # Test email sending
python vpn_reconnect.py --stats                      # Show metrics
python vpn_reconnect.py --reset                      # Clear backoff/stopped state
```

## Dependencies

- msgraph-lib (token_manager.py) — for sending email via MS Graph API
- pywinauto, pyautogui, pyperclip, pywin32 — Windows UI automation
- claude CLI — fallback MFA number extraction via screenshot (slow path)
