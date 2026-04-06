#!/usr/bin/env python3
"""VPN Reconnect - Unified F5 VPN reconnection"""
import subprocess, time, sys, json, os, re, threading, hashlib
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CONFIG_PATH = SCRIPT_DIR / "config.json"
SCREENSHOT_DIR = SCRIPT_DIR / "screenshots"
DEBUG_SCREENSHOT_DIR = SCRIPT_DIR / "screenshots-debug"
LOG_FILE = SCRIPT_DIR / "vpn-reconnect.log"
AUDIT_LOG = SCRIPT_DIR / "audit.jsonl"
STATE_FILE = SCRIPT_DIR / "vpn-state.json"
LOCK_FILE = SCRIPT_DIR / "vpn-reconnect.lock"
DEBUG_MODE = "--debug" in sys.argv

# f5fpc status code meanings
STATUS_NAMES = {
    1: "Connected", 2: "Logon in progress", 16: "User attention required",
    64: "Logged out", 0: "No session", -1: "Unknown", -2: "Timeout", -3: "Error"
}

import platform
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

# Default f5fpc path per platform
_F5_DEFAULT = r"C:\Program Files (x86)\F5 VPN\f5fpc.exe" if IS_WINDOWS else "/usr/local/bin/f5fpc"

try:
    with open(CONFIG_PATH) as f:
        config = json.load(f)
    F5_PATH = config.get("f5Path", _F5_DEFAULT)
    VPN_HOST = config.get("vpnHost", "vpn.example.com")
    EMAIL = config.get("userEmail", "")
    CANARY = config.get("canaryToken", "")
except Exception as e:
    print(f"Config error: {e}")
    config = {}
    F5_PATH = _F5_DEFAULT
    VPN_HOST = "vpn.example.com"
    EMAIL = ""
    CANARY = ""

# Suppress console windows from subprocess calls (Windows only)
NOWIN = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WINDOWS else {}

SCREENSHOT_DIR.mkdir(exist_ok=True)

def log(msg, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except: pass

def audit(event, **data):
    """Append a tamper-evident audit entry. Each line includes a hash of the
    previous line so deletions/modifications are detectable."""
    import socket
    entry = {
        "ts": datetime.now().isoformat(),
        "event": event,
        "host": socket.gethostname(),
        "pid": os.getpid(),
        **data,
    }
    # Chain hash: hash of previous last line (or seed)
    prev_hash = "GENESIS"
    try:
        if AUDIT_LOG.exists():
            with open(AUDIT_LOG, "rb") as f:
                for line in f:
                    pass  # seek to last line
                prev_hash = hashlib.sha256(line.strip()).hexdigest()[:16]
    except Exception:
        pass
    entry["prev"] = prev_hash
    line = json.dumps(entry, ensure_ascii=False)
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def take_screenshot(label=""):
    """Take screenshot in background thread to avoid blocking main flow."""
    def _snap():
        import pyautogui
        timestamp = datetime.now().strftime("%H%M%S")
        filename = f"{timestamp}_{label}.png" if label else f"{timestamp}.png"
        path = SCREENSHOT_DIR / filename
        try:
            pyautogui.screenshot(str(path))
            log(f"Screenshot: {filename}")
        except Exception as e: log(f"Screenshot failed: {e}", "WARN")
    t = threading.Thread(target=_snap, daemon=True)
    t.start()

def debug_screenshots(label="debug", duration=15):
    """Take a screenshot every second in a background thread (--debug only)."""
    if not DEBUG_MODE:
        return None
    def _capture():
        import pyautogui
        for i in range(duration):
            timestamp = datetime.now().strftime("%H%M%S")
            path = DEBUG_SCREENSHOT_DIR / f"{timestamp}_{label}_{i}s.png"
            try:
                pyautogui.screenshot(str(path))
                log(f"Debug screenshot: {label}_{i}s")
            except: pass
            time.sleep(1)
    t = threading.Thread(target=_capture, daemon=True)
    t.start()
    return t


def load_state():
    """Load persistent state for backoff and metrics tracking."""
    defaults = {
        "consecutive_timeouts": 0,
        "consecutive_errors": 0,
        "first_timeout_at": None,
        "backoff_until": None,
        "stopped": False,
        "stopped_reason": None,
        "last_run": None,
        "last_result": None,
        "total_successes": 0,
        "total_timeouts": 0,
        "total_errors": 0,
        "total_skips": 0,
        "history": [],
    }
    try:
        with open(STATE_FILE) as f:
            state = json.load(f)
            for k, v in defaults.items():
                if k not in state:
                    state[k] = v
            return state
    except:
        return defaults

def save_state(state):
    """Save persistent state."""
    state["last_run"] = datetime.now().isoformat()
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        log(f"Failed to save state: {e}", "WARN")

def record_event(state, result):
    """Append to history for metrics. Keep last 100 entries."""
    entry = {"time": datetime.now().isoformat(), "result": result}
    state["history"].append(entry)
    if len(state["history"]) > 100:
        state["history"] = state["history"][-100:]

def should_skip(state):
    """Check if this run should be skipped due to backoff or stopped state."""
    if state["stopped"]:
        log(f"VPN monitor stopped: {state.get('stopped_reason', 'unknown')}")
        log("Run: python vpn_reconnect.py --reset")
        state["total_skips"] += 1
        save_state(state)
        return True
    if state["backoff_until"]:
        backoff_time = datetime.fromisoformat(state["backoff_until"])
        if datetime.now() < backoff_time:
            remaining = (backoff_time - datetime.now()).total_seconds() / 60
            log(f"Backoff active - skipping ({remaining:.0f} min remaining)")
            state["total_skips"] += 1
            save_state(state)
            return True
        else:
            state["backoff_until"] = None
    return False

def handle_timeout(state):
    """Handle 2FA timeout with adaptive backoff."""
    from datetime import timedelta
    state["consecutive_timeouts"] += 1
    state["consecutive_errors"] = 0
    state["last_result"] = "timeout"
    state["total_timeouts"] += 1
    record_event(state, "timeout")
    n = state["consecutive_timeouts"]
    log(f"Timeout #{n}")

    if state["first_timeout_at"] is None:
        state["first_timeout_at"] = datetime.now().isoformat()

    hours_since_first = 0
    if state["first_timeout_at"]:
        first = datetime.fromisoformat(state["first_timeout_at"])
        hours_since_first = (datetime.now() - first).total_seconds() / 3600

    if hours_since_first >= 3 and state["backoff_until"]:
        # Already backed off to 8am once and still timing out -> stop
        state["stopped"] = True
        state["stopped_reason"] = "8am retry timed out"
        log("8am retry timed out - stopping VPN monitor", "WARN")
        log("Run: python vpn_reconnect.py --reset", "WARN")
    elif hours_since_first >= 3:
        # 3+ hours of timeouts -> wait until 8am next day (local time)
        backoff = datetime.now().replace(hour=8, minute=0, second=0, microsecond=0)
        if backoff <= datetime.now():
            backoff += timedelta(days=1)
        state["backoff_until"] = backoff.isoformat()
        log(f"6h+ of timeouts - next attempt at {backoff.strftime('%Y-%m-%d %H:%M')}", "WARN")
    elif n >= 2:
        # 2+ timeouts -> skip 3 cycles (run hourly)
        state["backoff_until"] = (datetime.now() + timedelta(minutes=45)).isoformat()
        log(f"{n} consecutive timeouts - backing off to hourly", "WARN")

    save_state(state)

def handle_error(state):
    """Handle actual errors (not timeouts). After 3: screenshot, open, keep F5."""
    state["consecutive_errors"] += 1
    state["consecutive_timeouts"] = 0
    state["last_result"] = "error"
    state["total_errors"] += 1
    record_event(state, "error")
    n = state["consecutive_errors"]
    log(f"Error #{n}")

    if n >= 3:
        import pyautogui
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        error_shot = SCREENSHOT_DIR / f"error_{timestamp}.png"
        try:
            pyautogui.screenshot(str(error_shot))
            log(f"Error screenshot: {error_shot}")
            os.startfile(str(error_shot))
            log("Opened screenshot for troubleshooting")
        except Exception as e:
            log(f"Screenshot failed: {e}", "WARN")
        state["stopped"] = True
        state["stopped_reason"] = f"3 consecutive errors - see {error_shot.name}"
        log("3 consecutive errors - stopping VPN monitor", "ERROR")
        log("Run: python vpn_reconnect.py --reset", "ERROR")
        save_state(state)
        return True  # Don't kill F5
    save_state(state)
    return False  # OK to kill F5

def handle_success(state):
    """Reset all counters on successful connection."""
    state["consecutive_timeouts"] = 0
    state["consecutive_errors"] = 0
    state["first_timeout_at"] = None
    state["backoff_until"] = None
    state["stopped"] = False
    state["stopped_reason"] = None
    state["last_result"] = "success"
    state["total_successes"] += 1
    record_event(state, "success")
    audit("vpn_connected", total=state["total_successes"])
    save_state(state)

def show_stats():
    """Show metrics summary."""
    state = load_state()
    print("=" * 40)
    print("  VPN Monitor Stats")
    print("=" * 40)
    print(f"  Successful reconnects: {state['total_successes']}")
    print(f"  Timeouts (2FA):       {state['total_timeouts']}")
    print(f"  Errors:               {state['total_errors']}")
    print(f"  Skipped runs:         {state['total_skips']}")
    print(f"  Last run:             {state.get('last_run', 'never')}")
    print(f"  Last result:          {state.get('last_result', 'none')}")
    if state["stopped"]:
        print(f"  STATUS: STOPPED - {state['stopped_reason']}")
    elif state["backoff_until"]:
        print(f"  STATUS: BACKOFF until {state['backoff_until']}")
    else:
        print(f"  STATUS: ACTIVE")
    if state.get("consecutive_timeouts"):
        print(f"  Consecutive timeouts: {state['consecutive_timeouts']}")
    if state.get("consecutive_errors"):
        print(f"  Consecutive errors:   {state['consecutive_errors']}")
    # Recent history
    history = state.get("history", [])
    if history:
        print(f"\n  Recent ({len(history)} entries):")
        for entry in history[-10:]:
            t = entry["time"][:16].replace("T", " ")
            print(f"    {t}  {entry['result']}")
    print("=" * 40)

def get_vpn_status():
    # Retry with increasing timeouts: f5fpc -info can hang briefly while
    # VPN is connected (seen in production: 10s timeout -> false disconnect
    # -> script kills working VPN). Three attempts before giving up.
    timeouts = [10, 15, 20]
    for attempt, t in enumerate(timeouts):
        try:
            result = subprocess.run([F5_PATH, "-info"], capture_output=True, text=True, timeout=t, **NOWIN)
            output = result.stdout + result.stderr
            if "session established" in output.lower():
                return {"connected": True, "code": 1, "message": "Session established"}
            match = re.search(r"(\d{4,})\s+(\d+)\s+(.+)", output)
            if match:
                code = int(match.group(2))
                return {"connected": code == 1, "code": code, "message": match.group(3).strip()}
            if "no active session" in output.lower():
                return {"connected": False, "code": 0, "message": "No active session"}
            return {"connected": False, "code": -1, "message": f"Unknown: {output[:100]}"}
        except subprocess.TimeoutExpired:
            if attempt < len(timeouts) - 1:
                log(f"f5fpc -info timeout ({t}s), retry {attempt+2}/{len(timeouts)}...", "WARN")
                time.sleep(1)
                continue
            return {"connected": False, "code": -2, "message": "Timeout"}
        except Exception as e:
            return {"connected": False, "code": -3, "message": str(e)}

def show_countdown(message="VPN Auto-Login", seconds=3):
    import tkinter as tk
    import ctypes
    log(f"Showing {seconds}s countdown warning...")
    result = ["proceed"]
    warning_shown = [False]
    warning_title = "VPN Monitor Warning"
    font_family = "Segoe UI" if IS_WINDOWS else "Helvetica"
    try:
        root = tk.Tk()
        root.title(warning_title)
        root.attributes("-topmost", True)
        if IS_WINDOWS:
            root.attributes("-alpha", 0.95)
        root.resizable(False, False)
        screen_w = root.winfo_screenwidth()
        screen_h = root.winfo_screenheight()
        win_w, win_h = 400, 200
        x = (screen_w - win_w) // 2
        y = (screen_h - win_h) // 2
        root.geometry(f"{win_w}x{win_h}+{x}+{y}")
        root.configure(bg="#1a1a2e")
        frame = tk.Frame(root, bg="#1a1a2e", highlightbackground="#e94560", highlightthickness=3)
        frame.pack(fill="both", expand=True, padx=5, pady=5)
        tk.Label(frame, text=message, font=(font_family, 16, "bold"), fg="#e94560", bg="#1a1a2e").pack(pady=(15, 5))
        countdown_label = tk.Label(frame, text=f"{seconds}", font=(font_family, 36, "bold"), fg="#00fff5", bg="#1a1a2e")
        countdown_label.pack(pady=5)
        tk.Label(frame, text="Taking control of mouse/keyboard", font=(font_family, 10), fg="#888888", bg="#1a1a2e").pack()
        tk.Label(frame, text="[Esc] to snooze", font=(font_family, 10), fg="#aaaaaa", bg="#1a1a2e").pack()
        btn_frame = tk.Frame(frame, bg="#1a1a2e")
        btn_frame.pack(pady=15)
        def on_snooze(): result[0] = "snooze"; root.destroy()
        def on_snooze_1h(): result[0] = "snooze_1h"; root.destroy()
        def on_disable(): result[0] = "disable"; root.destroy()
        def on_cancel(): result[0] = "cancel"; root.destroy()
        row1 = tk.Frame(btn_frame, bg="#1a1a2e")
        row1.pack(pady=2)
        snooze_btn = tk.Button(row1, text="Snooze 5min", command=on_snooze, width=12, bg="#0066aa", fg="white", font=(font_family, 10, "bold"))
        snooze_btn.pack(side="left", padx=5)
        snooze_1h_btn = tk.Button(row1, text="Snooze 1hr", command=on_snooze_1h, width=12, bg="#0066aa", fg="white", font=(font_family, 10))
        snooze_1h_btn.pack(side="left", padx=5)
        row2 = tk.Frame(btn_frame, bg="#1a1a2e")
        row2.pack(pady=2)
        cancel_btn = tk.Button(row2, text="Cancel", command=on_cancel, width=12, bg="#aa3333", fg="white", font=(font_family, 10))
        cancel_btn.pack(side="left", padx=5)
        disable_btn = tk.Button(row2, text="Disable Task", command=on_disable, width=12, bg="#666666", fg="white", font=(font_family, 10))
        disable_btn.pack(side="left", padx=5)
        countdown = [seconds]
        def verify_visible():
            root.update(); root.lift(); root.focus_force(); snooze_btn.focus_set()
            if IS_WINDOWS:
                import win32gui, win32con, win32process
                hwnd = win32gui.FindWindow(None, warning_title)
                if hwnd:
                    try:
                        fg_hwnd = win32gui.GetForegroundWindow()
                        fg_thread = win32process.GetWindowThreadProcessId(fg_hwnd)[0]
                        cur_thread = win32process.GetWindowThreadProcessId(hwnd)[0]
                        ctypes.windll.user32.AttachThreadInput(fg_thread, cur_thread, True)
                        win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE | win32con.SWP_NOSIZE | win32con.SWP_SHOWWINDOW)
                        win32gui.SetForegroundWindow(hwnd)
                        win32gui.BringWindowToTop(hwnd)
                        ctypes.windll.user32.AttachThreadInput(fg_thread, cur_thread, False)
                    except: pass
            warning_shown[0] = True
            log("Warning window verified visible")
        def update_countdown():
            countdown[0] -= 1
            if countdown[0] > 0: countdown_label.config(text=f"{countdown[0]}"); root.after(1000, update_countdown)
            else: root.destroy()
        root.bind("<Return>", lambda e: on_snooze())
        root.bind("<Escape>", lambda e: on_snooze())
        root.after(200, verify_visible)
        root.after(1000, update_countdown)
        root.mainloop()
        if not warning_shown[0]: log("WARNING FAILED TO DISPLAY", "ERROR"); return None
        log(f"User choice: {result[0]}")
        return result[0]
    except Exception as e: log(f"Warning display failed: {e}", "ERROR"); return None

def stop_f5_processes():
    log("Stopping F5 processes...")
    killed = []
    if IS_WINDOWS:
        processes = ["f5fpclientW.exe", "f5fpc.exe", "F5DialSrv.exe", "BIGIPEdgeClient.exe"]
        for proc in processes:
            try:
                result = subprocess.run(["taskkill", "/f", "/im", proc], capture_output=True, text=True, timeout=5, **NOWIN)
                if "SUCCESS" in result.stdout or result.returncode == 0: killed.append(proc)
            except: pass
    else:
        processes = ["f5fpc", "BIGIPEdgeClient", "F5 BIG-IP"]
        for proc in processes:
            try:
                result = subprocess.run(["pkill", "-f", proc], capture_output=True, text=True, timeout=5)
                if result.returncode == 0: killed.append(proc)
            except: pass
    if killed: log("Killed: " + ", ".join(killed))
    time.sleep(3)
    log("All F5 processes stopped")
    return True


def extract_mfa_number(win=None, page_text=None):
    """Extract the 2-digit MFA number from the SSO window.
    Fast path: pywinauto text extraction or browser page text (~instant).
    Fallback: screenshot + claude -p (~20s).
    Returns the number as a string, or None if not found."""

    # Fast path (macOS): regex on browser page text
    if page_text:
        for m in re.finditer(r'\b(\d{2})\b', page_text):
            n = int(m.group(1))
            if 10 <= n <= 99:
                log(f"MFA number detected via page text: {m.group(1)}")
                return m.group(1)

    # Fast path (Windows): read text elements from pywinauto window object
    if win is not None:
        try:
            texts = [c.window_text() for c in win.descendants(control_type="Text")]
            for t in texts:
                m = re.match(r'^\s*(\d{2})\s*$', t.strip())
                if m and 10 <= int(m.group(1)) <= 99:
                    log(f"MFA number detected via pywinauto: {m.group(1)}")
                    return m.group(1)
            log(f"pywinauto texts (no match): {[t for t in texts if t.strip()]}", "WARN")
        except Exception as e:
            log(f"pywinauto text extraction failed: {e}", "WARN")

    # Fallback: screenshot + claude -p (slow but works if window object unavailable)
    import pyautogui
    timestamp = datetime.now().strftime("%H%M%S")
    screenshot_path = str(SCREENSHOT_DIR / f"{timestamp}_mfa_number.png")
    try:
        pyautogui.screenshot(screenshot_path)
        log(f"MFA screenshot: {screenshot_path}")
    except Exception as e:
        log(f"MFA screenshot failed: {e}", "WARN")
        return None

    try:
        prompt = "What is the 2-digit number shown? Reply with ONLY the number."
        result = subprocess.run(
            ["claude", "-p", prompt, screenshot_path],
            capture_output=True, text=True, timeout=30, **NOWIN,
        )
        output = result.stdout.strip()
        candidates = re.findall(r'\b(\d{2})\b', output)
        for c in candidates:
            n = int(c)
            if 10 <= n <= 99:
                log(f"MFA number detected via screenshot: {c}")
                return c
        log(f"claude -p returned: {output[:100]}", "WARN")
    except subprocess.TimeoutExpired:
        log("claude -p timed out reading MFA number", "WARN")
    except FileNotFoundError:
        log("claude CLI not found -- cannot read MFA number", "WARN")
    except Exception as e:
        log(f"claude -p failed: {e}", "WARN")
    return None


def email_mfa_info(number):
    """Email the MFA number to the user via MS Graph API.
    Subject: just the number. Body: canary token (anti-spoof verification)."""
    if not number:
        log("No MFA number to email", "WARN")
        return False
    try:
        msgraph_path = config.get("msgraphLibPath", "")
        if not msgraph_path:
            # Search common locations
            for candidate in [
                os.path.expanduser("~/Documents/ProjectsCL1/_tmemu/msgraph-lib"),
                os.path.expanduser("~/Documents/ProjectsCL1/msgraph-lib"),
                str(SCRIPT_DIR.parent / "msgraph-lib"),
            ]:
                if os.path.isdir(candidate):
                    msgraph_path = candidate
                    break
        if msgraph_path:
            sys.path.insert(0, msgraph_path)
        from token_manager import graph_post
    except Exception as e:
        log(f"Cannot load msgraph-lib: {e}", "WARN")
        return False

    payload = {
        "message": {
            "subject": f"{number}",
            "body": {"contentType": "Text", "content": CANARY},
            "toRecipients": [{"emailAddress": {"address": EMAIL}}],
        },
        "saveToSentItems": False,
    }

    try:
        graph_post("/me/sendMail", payload)
        log(f"MFA number {number} emailed to {EMAIL}")
        audit("mfa_email_sent", number=number, to=EMAIL, canary=bool(CANARY))
        return True
    except Exception as e:
        log(f"MFA email failed: {e}", "ERROR")
        audit("mfa_email_failed", number=number, error=str(e))
        return False


def close_f5_window():
    """Close the BIG-IP Edge Client GUI window without killing the VPN tunnel.
    The tunnel is maintained by the background service, not the GUI."""
    if IS_WINDOWS:
        import ctypes
        user32 = ctypes.windll.user32
        WM_CLOSE = 0x0010

        def _close_callback(hwnd, _):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if "BIG-IP" in buf.value:
                    user32.PostMessageW(hwnd, WM_CLOSE, 0, 0)
                    log(f"Closed F5 window: {buf.value}")
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        user32.EnumWindows(WNDENUMPROC(_close_callback), 0)

def minimize_f5_window():
    """Minimize the BIG-IP Edge Client GUI window so user can resume working
    while waiting for 2FA approval."""
    if IS_WINDOWS:
        import ctypes
        user32 = ctypes.windll.user32
        SW_MINIMIZE = 6

        def _minimize_callback(hwnd, _):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if "BIG-IP" in buf.value:
                    user32.ShowWindow(hwnd, SW_MINIMIZE)
                    log(f"Minimized F5 window: {buf.value}")
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        user32.EnumWindows(WNDENUMPROC(_minimize_callback), 0)

def start_vpn_connection():
    """Fire-and-forget: f5fpc -start runs async, login window appears separately."""
    log(f"Initiating VPN connection to {VPN_HOST}...")
    try:
        if IS_WINDOWS:
            cmd = [F5_PATH, "-start", "/h", VPN_HOST, "/nb"]
        else:
            cmd = [F5_PATH, "-start", "-h", VPN_HOST, "-nb"]
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **NOWIN)
        log("VPN connection command sent")
        return True
    except Exception as e: log(f"Failed to start VPN connection: {e}", "ERROR"); return False

def disable_scheduled_task():
    log("Disabling VPN Monitor scheduled task...")
    try:
        if IS_WINDOWS:
            result = subprocess.run(["schtasks", "/change", "/tn", "VPN Monitor Check", "/disable"], capture_output=True, text=True, timeout=10, **NOWIN)
        else:
            plist = os.path.expanduser("~/Library/LaunchAgents/com.vpnmonitor.check.plist")
            result = subprocess.run(["launchctl", "unload", plist], capture_output=True, text=True, timeout=10)
        if result.returncode == 0: log("Scheduled task disabled", "OK"); return True
        else: log(f"Failed to disable task: {result.stderr}", "WARN"); return False
    except Exception as e: log(f"Error disabling task: {e}", "ERROR"); return False

def _wait_for_window_event(title_match, timeout):
    """Use SetWinEventHook for near-instant window detection by title substring.
    WHY: Polling every 300ms adds up to 300ms latency. WinEvent hooks fire within
    ~10ms of window creation, making the login flow noticeably snappier."""
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.windll.user32
    found_event = threading.Event()
    found_hwnd = [None]

    WINEVENTPROC = ctypes.WINFUNCTYPE(
        None, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p,
        ctypes.c_long, ctypes.c_long, ctypes.c_uint, ctypes.c_uint,
    )

    EVENT_OBJECT_CREATE = 0x8000
    EVENT_OBJECT_NAMECHANGE = 0x800C
    EVENT_SYSTEM_FOREGROUND = 0x0003
    WINEVENT_OUTOFCONTEXT = 0x0000
    WINEVENT_SKIPOWNPROCESS = 0x0002
    OBJID_WINDOW = 0

    def on_event(hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime):
        if found_event.is_set() or not hwnd:
            return
        try:
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if title_match in buf.value:
                    found_hwnd[0] = int(hwnd)
                    found_event.set()
        except:
            pass

    callback = WINEVENTPROC(on_event)  # prevent GC

    def event_loop():
        hooks = []
        for evt in [EVENT_OBJECT_CREATE, EVENT_OBJECT_NAMECHANGE, EVENT_SYSTEM_FOREGROUND]:
            h = user32.SetWinEventHook(evt, evt, None, callback, 0, 0,
                                        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS)
            if h:
                hooks.append(h)
        # Pump messages until window found (required for event delivery)
        msg = wintypes.MSG()
        while not found_event.is_set():
            while user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 1):
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
            time.sleep(0.01)  # 10ms pump interval
        for h in hooks:
            user32.UnhookWinEvent(h)

    t = threading.Thread(target=event_loop, daemon=True)
    t.start()
    found_event.wait(timeout=timeout)
    found_event.set()  # signal loop to stop on timeout
    return found_hwnd[0]


def wait_for_connection(timeout=120):
    log(f"Waiting for connection (up to {timeout}s)...")
    start = time.time()
    while time.time() - start < timeout:
        status = get_vpn_status()
        if status["connected"]: log("VPN CONNECTED!", "OK"); return True
        time.sleep(5)
    log("Connection timeout", "WARN"); return False

def main():
    # Handle CLI flags
    if "--reset" in sys.argv:
        state = load_state()
        state["stopped"] = False
        state["stopped_reason"] = None
        state["consecutive_timeouts"] = 0
        state["consecutive_errors"] = 0
        state["first_timeout_at"] = None
        state["backoff_until"] = None
        save_state(state)
        log("State reset - VPN monitor re-enabled")
        return 0

    if "--stats" in sys.argv:
        show_stats()
        return 0

    if "--test-email" in sys.argv:
        log("Testing MFA email notification...")
        result = email_mfa_info("42")
        if result:
            log("Test email sent successfully — check inbox for subject '42'")
        else:
            log("Test email FAILED — check msgraph-lib token", "ERROR")
        return 0 if result else 1

    # Load state and check backoff/stopped
    state = load_state()
    if should_skip(state):
        return 0

    log("=" * 50)
    log("VPN Reconnect Starting")
    audit("reconnect_start", host=VPN_HOST)
    if DEBUG_MODE:
        DEBUG_SCREENSHOT_DIR.mkdir(exist_ok=True)
        for f in DEBUG_SCREENSHOT_DIR.glob("*.png"):
            try: f.unlink()
            except: pass
        log("Debug mode ON - screenshots in screenshots-debug/")
    log(f"Host: {VPN_HOST}")
    log(f"User: {EMAIL}")
    log("=" * 50)

    # Step 1: Check current VPN status (confirm twice to avoid transient f5fpc glitches)
    status = get_vpn_status()
    code_name = STATUS_NAMES.get(status["code"], "Unknown")
    log(f"VPN check: {code_name} (code={status['code']}) - {status['message']}")
    if status["connected"]:
        log("VPN already connected - nothing to do")
        return 0
    # f5fpc -info can return stale/transient results - confirm disconnect before proceeding
    time.sleep(1)
    status2 = get_vpn_status()
    if status2["connected"]:
        log(f"VPN connected on recheck (first check was transient {code_name}) - nothing to do")
        return 0

    # Step 2: Stop F5 processes (background, no windows yet)
    log("Stopping F5 services...")
    if not stop_f5_processes():
        log("Failed to stop F5 processes", "ERROR")
        return 1

    # Step 3: Show 3s countdown BEFORE any F5 window can steal focus
    warning_result = show_countdown("VPN Auto-Login", seconds=3)
    if warning_result is None:
        log("ABORTING: Warning was not displayed", "ERROR")
        return 2
    if warning_result == "snooze":
        log("User requested 5 minute snooze")
        return 3
    if warning_result == "cancel":
        log("User cancelled")
        return 4
    if warning_result == "snooze_1h":
        log("User requested 1 hour snooze")
        return 5
    if warning_result == "disable":
        disable_scheduled_task()
        log("VPN Monitor disabled")
        return 6

    # Step 4: Initiate VPN connection directly (f5fpc -start handles everything)
    # Skip start_f5_client() — it creates a connection panel window that
    # immediately gets torn down by f5fpc -start, causing a visible flash.
    if not start_vpn_connection():
        log("Failed to initiate VPN connection", "ERROR")
        return 1

    # Step 5-7: Platform-specific login flow
    if IS_WINDOWS:
        result = _login_flow_windows()
    elif IS_MAC:
        result = _login_flow_mac()
    else:
        log("Unsupported platform", "ERROR")
        return 1
    if result is not None:
        return result

    # Wait for phone approval
    if wait_for_connection(timeout=120):
        log("=" * 50)
        log("VPN Reconnection SUCCESSFUL", "OK")
        log("=" * 50)
        take_screenshot("connected")
        close_f5_window()
        return 0
    else:
        log("Connection timed out waiting for approval", "WARN")
        return 7  # Timeout (2FA not approved)



def _login_flow_windows():
    """Windows login flow: WinEvent + pywinauto element detection + keyboard paste.
    Returns exit code or None to continue to wait_for_connection."""
    from pywinauto import Application
    import pyautogui, pyperclip
    import ctypes

    debug_thread = debug_screenshots("login_flow", duration=15)
    start = time.time()

    # Step 5: Detect window via WinEvent (~10ms latency)
    hwnd = _wait_for_window_event("BIG-IP", 30)
    if not hwnd:
        status = get_vpn_status()
        if status["connected"]:
            log("VPN connected without login!", "OK")
            close_f5_window()
            return 0
        log("Login window did not appear", "ERROR")
        return 1
    log(f"Window detected via WinEvent ({time.time()-start:.1f}s)")

    # Step 6: Connect pywinauto ONCE (pay ~300ms cost once, not per iteration)
    win = None
    try:
        app = Application(backend="uia").connect(handle=hwnd)
        win = app.window(handle=hwnd)
    except:
        try:
            app = Application(backend="uia").connect(title_re=".*BIG-IP.*", timeout=1)
            win = app.window(title_re=".*BIG-IP.*")
        except Exception as e:
            log(f"Failed to connect to window: {e}", "ERROR")
            return 1
    log(f"pywinauto connected ({time.time()-start:.1f}s)")

    # Step 7: Stage-based login — wait for element, act, verify
    stage = "email"
    stall_count = 0
    window_gone_count = 0

    while time.time() - start < 60:
        if stage == "email":
            # Step 1: Check if element exists (window-level check)
            try:
                el = win.child_window(auto_id="i0116", control_type="Edit")
                if not el.exists(timeout=0.02):
                    stall_count += 1
                    time.sleep(0.05)
                    continue
            except Exception:
                window_gone_count += 1
                if window_gone_count > 30:
                    log("SSO window closed by user")
                    return 4
                time.sleep(0.05)
                continue
            # Step 2: Element exists - interact with it
            window_gone_count = 0
            try:
                try:
                    win.set_focus()
                except Exception:
                    pass
                # Move mouse away from corners to prevent pyautogui fail-safe
                pyautogui.moveTo(960, 540, _pause=False)
                log(f"Email field found ({time.time()-start:.1f}s)")
                el.click_input()
                pyperclip.copy(EMAIL)
                pyautogui.hotkey("ctrl", "a")
                pyautogui.hotkey("ctrl", "v")
                # Verify email was entered
                time.sleep(0.1)
                try:
                    val = el.get_value()
                    if val and EMAIL.lower() in val.lower():
                        log(f"Email verified in field ({time.time()-start:.1f}s)")
                    else:
                        log(f"Email field value: '{val}' - retrying", "WARN")
                        el.click_input()
                        el.type_keys("^a^v", with_spaces=True)
                except:
                    pass
                pyautogui.press("enter")
                log(f"Email submitted ({time.time()-start:.1f}s)")
                take_screenshot("email_submitted")
                stage = "password"
                stall_count = 0
                continue
            except Exception as e:
                log(f"Email interaction failed: {e}", "WARN")
                stall_count += 1
                time.sleep(0.5)
                continue

        elif stage == "password":
            # Step 1: Check if link exists
            try:
                link = win.child_window(title="Use an app instead", control_type="Hyperlink")
                if not link.exists(timeout=0.05):
                    stall_count += 1  # fall through to stall/status checks below
                else:
                    # Step 2: Link exists - interact
                    try:
                        win.set_focus()
                    except Exception:
                        pass
                    pyautogui.moveTo(960, 540, _pause=False)
                    try:
                        link.click_input()
                        log(f"Clicked 'Use an app instead' ({time.time()-start:.1f}s)")
                        take_screenshot("use_app")
                        time.sleep(1)  # brief wait for MFA number to render
                        # Read MFA number from window and email it
                        mfa_num = extract_mfa_number(win=win)
                        if mfa_num:
                            email_mfa_info(mfa_num)
                        minimize_f5_window()
                        return None  # proceed to wait_for_connection
                    except Exception as e:
                        log(f"Link click failed: {e}", "WARN")
                        stall_count += 1
                        time.sleep(0.5)
                        continue
            except Exception:
                window_gone_count += 1
                if window_gone_count > 30:
                    log("SSO window closed by user")
                    return 4
                time.sleep(0.05)
                continue
            window_gone_count = 0
            status = get_vpn_status()
            if status["connected"]:
                log(f"VPN CONNECTED ({time.time()-start:.1f}s)", "OK")
                close_f5_window()
                return 0
            if status["code"] == 2:
                log(f"Logon in progress ({time.time()-start:.1f}s)")
                return None
            stall_count += 1

        elif stage == "wait":
            return None

        if stall_count % 10 == 0 and stall_count > 0:
            status = get_vpn_status()
            if status["connected"]:
                log(f"VPN CONNECTED ({time.time()-start:.1f}s)", "OK")
                close_f5_window()
                return 0

        if stall_count > 50:
            log(f"Stalled in {stage} after {time.time()-start:.1f}s", "WARN")
            take_screenshot(f"stalled_{stage}")
            stop_f5_processes()
            return 1

        time.sleep(0.05)

    log("Login flow timed out", "WARN")
    return 1


def _login_flow_mac():
    """macOS login flow: AppleScript window detection + pyautogui keyboard input.
    F5 BIG-IP on macOS opens SSO login in the default browser.
    Returns exit code or None to continue to wait_for_connection."""
    import pyautogui, pyperclip

    debug_thread = debug_screenshots("login_flow", duration=15)
    start = time.time()
    mod = "command"  # macOS uses Cmd instead of Ctrl

    # Step 5: Wait for browser SSO window (Microsoft login page)
    log("Waiting for SSO login in browser...")
    browser_app = None
    for _ in range(60):  # 30s at 0.5s intervals
        browser_app = _mac_find_sso_browser()
        if browser_app:
            break
        status = get_vpn_status()
        if status["connected"]:
            log("VPN connected without login!", "OK")
            return 0
        time.sleep(0.5)

    if not browser_app:
        log("SSO login page did not appear in browser", "ERROR")
        return 1
    log(f"Found SSO in {browser_app} ({time.time()-start:.1f}s)")

    # Step 6: Activate browser window
    _mac_activate_app(browser_app)
    time.sleep(0.5)

    # Step 7: Stage-based login via keyboard automation
    stage = "email"
    stall_count = 0

    while time.time() - start < 60:
        if stage == "email":
            # Check if email field is visible (page has "Sign in" or similar)
            page_text = _mac_get_browser_text(browser_app)
            if not page_text:
                stall_count += 1
                if stall_count > 20:
                    log("SSO window closed by user")
                    return 4
                time.sleep(0.3)
                continue
            if "sign in" in page_text.lower() or "@" in page_text.lower() or "email" in page_text.lower():
                # Tab to email field and type (browser SSO typically has focus on email)
                pyperclip.copy(EMAIL)
                pyautogui.hotkey(mod, "a")
                pyautogui.hotkey(mod, "v")
                pyautogui.press("enter")
                log(f"Email submitted ({time.time()-start:.1f}s)")
                take_screenshot("email_submitted")
                stage = "password"
                stall_count = 0
                time.sleep(2)
                continue
            stall_count += 1

        elif stage == "password":
            page_text = _mac_get_browser_text(browser_app)
            if not page_text:
                stall_count += 1
                if stall_count > 20:
                    log("SSO window closed by user")
                    return 4
                time.sleep(0.3)
                continue
            if "use an app" in page_text.lower() or "app instead" in page_text.lower():
                # Click "Use an app instead" via accessibility or keyboard
                # AppleScript click on the link text
                _mac_click_link(browser_app, "Use an app instead")
                log(f"Clicked 'Use an app instead' ({time.time()-start:.1f}s)")
                take_screenshot("use_app")
                time.sleep(1)  # brief wait for MFA number to render
                # Read MFA number from browser text and email it
                mfa_text = _mac_get_browser_text(browser_app)
                mfa_num = extract_mfa_number(page_text=mfa_text)
                if mfa_num:
                    email_mfa_info(mfa_num)
                stage = "wait"
                stall_count = 0
                continue
            if "approve" in page_text.lower() or "authenticator" in page_text.lower():
                stage = "wait"
                continue
            status = get_vpn_status()
            if status["code"] == 2:
                log(f"Logon in progress ({time.time()-start:.1f}s)")
                stage = "wait"
                continue
            stall_count += 1

        elif stage == "wait":
            return None  # proceed to wait_for_connection

        if stall_count % 5 == 0 and stall_count > 0:
            status = get_vpn_status()
            if status["connected"]:
                log(f"VPN CONNECTED ({time.time()-start:.1f}s)", "OK")
                return 0

        if stall_count > 50:
            log(f"Stalled in {stage} stage after {time.time()-start:.1f}s", "WARN")
            stop_f5_processes()
            return 1

        time.sleep(0.3)

    log("Login flow timed out", "WARN")
    return 1


def _mac_find_sso_browser():
    """Find browser with Microsoft SSO login page open. Returns app name or None."""
    for browser in ["Safari", "Google Chrome", "Microsoft Edge"]:
        try:
            if browser == "Safari":
                script = '''tell application "Safari"
                    repeat with w in windows
                        repeat with t in tabs of w
                            if URL of t contains "microsoftonline" or URL of t contains "login.microsoft" then
                                return "Safari"
                            end if
                        end repeat
                    end repeat
                end tell'''
            else:
                script = f'''tell application "{browser}"
                    repeat with w in windows
                        repeat with t in tabs of w
                            if URL of t contains "microsoftonline" or URL of t contains "login.microsoft" then
                                return "{browser}"
                            end if
                        end repeat
                    end repeat
                end tell'''
            result = subprocess.run(["osascript", "-e", script],
                                    capture_output=True, text=True, timeout=3)
            if result.stdout.strip():
                return result.stdout.strip()
        except:
            pass
    return None


def _mac_activate_app(app_name):
    """Bring browser app to foreground."""
    try:
        subprocess.run(["osascript", "-e",
                         f'tell application "{app_name}" to activate'],
                        capture_output=True, timeout=3)
    except:
        pass


def _mac_get_browser_text(app_name):
    """Get visible text from the active browser tab via accessibility."""
    try:
        if app_name == "Safari":
            script = '''tell application "Safari"
                set pageText to do JavaScript "document.body.innerText.substring(0, 500)" in current tab of front window
                return pageText
            end tell'''
        else:
            script = f'''tell application "{app_name}"
                set pageText to execute front window's active tab javascript "document.body.innerText.substring(0, 500)"
                return pageText
            end tell'''
        result = subprocess.run(["osascript", "-e", script],
                                capture_output=True, text=True, timeout=3)
        return result.stdout.strip() if result.returncode == 0 else None
    except:
        return None


def _mac_click_link(app_name, link_text):
    """Click a link by text content in the browser via JavaScript."""
    js = f'''
        var links = document.querySelectorAll('a');
        for (var i = 0; i < links.length; i++) {{
            if (links[i].textContent.trim() === '{link_text}') {{
                links[i].click(); break;
            }}
        }}'''
    try:
        if app_name == "Safari":
            script = f'''tell application "Safari"
                do JavaScript "{js.replace(chr(10), ' ')}" in current tab of front window
            end tell'''
        else:
            script = f'''tell application "{app_name}"
                execute front window's active tab javascript "{js.replace(chr(10), ' ')}"
            end tell'''
        subprocess.run(["osascript", "-e", script],
                        capture_output=True, timeout=3)
    except:
        pass

def acquire_lock():
    """Prevent concurrent runs. Returns True if lock acquired.
    Uses PID + timestamp. Lock is stale if older than 5 min or PID is dead."""
    pid = os.getpid()
    max_age = 300  # 5 minutes - longest possible run is ~3min login + 2min wait
    if LOCK_FILE.exists():
        try:
            parts = LOCK_FILE.read_text().strip().split(":")
            old_pid = int(parts[0])
            lock_time = float(parts[1]) if len(parts) > 1 else 0
            age = time.time() - lock_time
            # Age-based: any lock older than 5 min is stale regardless
            if age > max_age:
                log(f"Removing stale lock (PID {old_pid}, age {age:.0f}s)")
            else:
                # Fresh lock - check if PID is alive
                if platform.system() == "Windows":
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    handle = kernel32.OpenProcess(0x1000, False, old_pid)
                    if handle:
                        kernel32.CloseHandle(handle)
                        log(f"Another instance running (PID {old_pid}, age {age:.0f}s), exiting")
                        return False
                else:
                    try:
                        os.kill(old_pid, 0)  # signal 0 = check if alive
                        log(f"Another instance running (PID {old_pid}, age {age:.0f}s), exiting")
                        return False
                    except OSError:
                        pass
                log(f"Removing stale lock (PID {old_pid} dead)")
        except:
            pass
    LOCK_FILE.write_text(f"{pid}:{time.time()}")
    return True

def release_lock():
    """Remove lock file."""
    try:
        LOCK_FILE.unlink(missing_ok=True)
    except:
        pass

if __name__ == "__main__":
    _info_flags = {"--reset", "--stats", "--test-email"}
    if not _info_flags.intersection(sys.argv):
        if not acquire_lock():
            sys.exit(0)
    try:
        exit_code = main()
        if "--test-email" in sys.argv:
            sys.exit(exit_code)
        state = load_state()
        if exit_code == 0:
            handle_success(state)
        elif exit_code == 7:
            # 2FA timeout - adaptive backoff, then cleanup
            handle_timeout(state)
            log("Cleaning up F5 processes...")
            stop_f5_processes()
        elif exit_code == 1:
            # Actual error - keep F5 running after 3 consecutive
            keep_f5 = handle_error(state)
            if not keep_f5:
                log("Cleaning up F5 processes...")
                stop_f5_processes()
            else:
                log("Keeping F5 running for troubleshooting")
        # Codes 2-6 are user actions (snooze/cancel/disable), no state change
        sys.exit(exit_code)
    except Exception as e:
        log(f"Unhandled exception: {e}", "ERROR")
        import traceback; traceback.print_exc()
        state = load_state()
        handle_error(state)
        sys.exit(1)
    finally:
        release_lock()
