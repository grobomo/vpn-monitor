# VPN Monitor — TODO

## Problem
VPN drops → teams-agent (RONE K8s) stops polling → no messages processed.
Reconnecting requires MFA approval on phone, but user doesn't know VPN dropped
until they notice things aren't working. Current flow requires manual intervention.

## Goal: Fully autonomous VPN reconnect
Scheduled task detects VPN down → reconnects → extracts MFA number → emails it
to user → user taps approve on phone → VPN up → teams-agent resumes.
Zero Claude Code involvement. Zero manual SSH/RDP.

## Architecture
```
Windows Task Scheduler (every 15 min)
  │
  ▼
vpn_reconnect.py
  ├── Check f5fpc status
  ├── If connected → exit
  ├── If disconnected:
  │   ├── Kill stale F5 processes
  │   ├── Show 3s countdown (user can snooze)
  │   ├── Start f5fpc -start
  │   ├── Automate SSO login (pywinauto)
  │   ├── Click "Use an app instead"
  │   ├── Extract 2-digit MFA number ← NEW
  │   ├── Email MFA number to user   ← NEW (msgraph-lib)
  │   ├── Wait for approval (120s)
  │   └── Verify connected
  └── Adaptive backoff on repeated failures
```

## Spec: MFA Email Notification

### Extract MFA number (T001)
- After clicking "Use an app instead", Microsoft shows a 2-digit number (10-99)
- **Windows**: pywinauto `win.descendants(control_type="Text")`, match `\d{2}`
- **macOS**: `_mac_get_browser_text()` → regex `\b\d{2}\b`
- **Fallback**: screenshot → claude -p multimodal (only if pywinauto/browser fails)
- Timeout: 5 seconds. If no number found, log warning and continue (don't block)

### Send email (T002)
- Use `msgraph-lib/token_manager.py` → `graph_post('/me/sendMail')`
- Subject: `VPN MFA: NN` (visible in phone notification without opening)
- Body: `Enter NN in Microsoft Authenticator to approve VPN login.`
- To: self (config.json userEmail)
- saveToSentItems: false (don't clutter sent folder)
- Fail silently (log warning, don't block reconnect flow)

### Wire into login flows (T003)
- Windows `_login_flow_windows()`: after link.click_input(), before minimize
- macOS `_login_flow_mac()`: after _mac_click_link(), before stage="wait"
- Both: extract → email → continue (non-blocking)

### Verify scheduled task is active (T004)
- Check `schtasks /query /tn "VPN Monitor Check"` status
- Enable if disabled
- Confirm interval and script path are correct

## Completed
- [x] T001: Extract MFA number from SSO window
- [x] T002: Send MFA number via email using msgraph-lib
- [x] T003: Wire into both Windows and macOS login flows

## Remaining
- [ ] T004: Fix scheduled task path — currently points to OLD location:
  `C:\Users\joelg\OneDrive - TrendMicro\Documents\ProjectsCL\vpn-monitor\vpn_reconnect.py`
  Must update to: `C:\Users\joelg\Documents\ProjectsCL1\grobomo\vpn-monitor\vpn_reconnect.py`
  Command: `schtasks /change /tn "VPN Monitor Check" /tr "pythonw.exe <new_path>"`
- [ ] T005: Test end-to-end: disconnect VPN → task fires → email received → approve → connected
