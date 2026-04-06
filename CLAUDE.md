# VPN Monitor

Auto-reconnects F5 BIG-IP Edge Client VPN with MFA email notification.

## Quick Reference

```bash
python install.py install    # Install scheduled tasks (needs UAC)
python install.py status     # Show task status + command path
python install.py run        # Run reconnect once (testing)
python vpn_reconnect.py --stats       # Show metrics
python vpn_reconnect.py --test-email  # Send test MFA email
python vpn_reconnect.py --reset       # Clear backoff/stopped state
python vpn_reconnect.py --debug       # Run with per-second screenshots
```

## Architecture

Single script (`vpn_reconnect.py`) with platform-specific login flows.
Scheduled task runs every 15 min via `pythonw.exe` (silent, no console).

## Security Model

- **Email subject**: just the 2-digit MFA number (no label)
- **Email body**: canary token from `config.json` (gitignored) — anti-spoof
- **Audit log**: `audit.jsonl` with chained SHA-256 hashes (tamper-evident)
- **No secrets in code**: email, canary, VPN host all in gitignored `config.json`
- **saveToSentItems**: false — no trace in sent folder

## Key Files

| File | Purpose |
|------|---------|
| `vpn_reconnect.py` | Main reconnect script |
| `install.py` | Cross-platform installer (schtasks / launchd) |
| `config.json` | Runtime config (gitignored) |
| `config.json.example` | Template for new installs |
| `audit.jsonl` | Tamper-evident security audit log |
| `vpn-state.json` | Backoff state + metrics |

## Dependencies

- **Windows**: pywinauto, pyautogui, pyperclip, pywin32
- **macOS**: pyautogui, pyperclip
- **Shared**: msgraph-lib (token_manager.py) for email

## GitHub

- Account: grobomo (public)
- No PII, no customer data, no internal infra details
