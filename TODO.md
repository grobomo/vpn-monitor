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
- Subject: just `NN` (no label — security through obscurity)
- Body: canary token from config.json (anti-spoof verification)
- To: self (config.json userEmail)
- saveToSentItems: false (don't clutter sent folder)
- Fail silently (log warning, don't block reconnect flow)
- Audit logged to `audit.jsonl` with chained hashes

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
- [x] T004: Migrate script to grobomo path, update scheduled task via install.py
- [x] T005: Test email sends successfully (subject: just number, body: canary emoji)
- [x] T006: Fast pywinauto text extraction (replaces slow screenshot+claude-p)
- [x] T007: Anti-spoof canary token in email body (config.json, gitignored)
- [x] T008: Tamper-evident audit log (audit.jsonl with chained hashes)

## Remaining
- [ ] T009: Full end-to-end test: VPN drops → task fires → email with canary → approve → connected
  - Waiting for next natural VPN drop. Scheduled task active every 15 min.
  - Verify: audit.jsonl gets reconnect_start + mfa_email_sent + vpn_connected chain
- [ ] T010: Daily audit log analysis via claude -p (offsite backup + anomaly detection)
  - claude-scheduler skill to run daily at 8am
  - Back up audit.jsonl to S3/offsite before analysis
  - claude -p analyzes for anomalies: unexpected hosts, rapid-fire sends, missing chain links
- [ ] T011: system-monitor umbrella project with modules: vpn-monitor, disk-monitor, ioc-monitor
  - New project: grobomo/system-monitor
  - Each module: check script + health status + audit log
  - Central daily digest email with all module reports
- [ ] T012: ioc-monitor: Windows Event Log scanning for IOCs (failed logins, new services, suspicious processes)
  - New module in system-monitor
  - python-evtx or wevtutil for Event Log parsing
  - Patterns: 4625 (failed login), 7045 (new service), 4688 (process creation)
  - Daily report + real-time alerting for critical IOCs
- [ ] T013: Merge PR 001-T004-fix-mfa-email-and-task-path → main
- [ ] T014: Create CLAUDE.md for this project (architecture, security model, test instructions)
- [ ] T015: Publish to grobomo GitHub (secret scan, sanitize any PII in code/docs)
