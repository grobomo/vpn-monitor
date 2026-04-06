#!/usr/bin/env python3
"""Cross-platform VPN Monitor installer. One command does everything.

Usage:
    python install.py install                # Install deps + config + scheduled task
    python install.py install --email you@trendmicro.com  # Provide email (skips manual config edit)
    python install.py install --headless     # Auto-approve all prompts (UAC still required)
    python install.py install --headless-safe  # Skip warnings entirely (CI/scripted use)
    python install.py uninstall              # Remove scheduled task
    python install.py status                 # Show current task status
    python install.py run                    # Run vpn_reconnect.py once (for testing)
"""
import subprocess, sys, os, platform, json
from pathlib import Path

HEADLESS = "--headless" in sys.argv
HEADLESS_SAFE = "--headless-safe" in sys.argv

# Parse --email flag: --email user@example.com
EMAIL_FLAG = None
for i, arg in enumerate(sys.argv):
    if arg == "--email" and i + 1 < len(sys.argv):
        EMAIL_FLAG = sys.argv[i + 1]
        break

SCRIPT_DIR = Path(__file__).parent.resolve()
RECONNECT_SCRIPT = SCRIPT_DIR / "vpn_reconnect.py"
CONFIG_PATH = SCRIPT_DIR / "config.json"
CONFIG_EXAMPLE = SCRIPT_DIR / "config.json.example"
IS_WINDOWS = platform.system() == "Windows"
IS_MAC = platform.system() == "Darwin"

# ── Windows ─────────────────────────────────────────────────────────
TASK_NAME = "VPN Monitor Check"
TASK_NAME_LOGIN = "VPN Monitor Start at Login"
# Old task names to clean up
OLD_TASKS = ["VPN-Monitor", "VPN-Monitor-AutoStart", "VPN 24h Review"]

def win_is_admin():
    """Check if running with admin privileges."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def win_elevate():
    """Re-run this script with UAC elevation."""
    import ctypes
    script = str(Path(__file__).resolve())
    args = " ".join(f'"{a}"' for a in sys.argv[1:])
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {args}', None, 1
    )
    if ret <= 32:
        print(f"[FAIL] UAC elevation failed (code {ret}). Run from an interactive terminal.", flush=True)
        sys.exit(1)
    sys.exit(0)

def win_find_pythonw():
    """Find pythonw.exe next to current python."""
    base = Path(sys.executable).parent
    pythonw = base / "pythonw.exe"
    if pythonw.exists():
        return str(pythonw)
    return "pythonw.exe"

def win_install():
    # Setup BEFORE elevating (elevation opens new console)
    install_deps()
    ensure_config()

    if not win_is_admin():
        print("[..] Requesting admin privileges...", flush=True)
        win_elevate()
        return

    pythonw = win_find_pythonw()

    # Remove old tasks
    for old in OLD_TASKS + [TASK_NAME, TASK_NAME_LOGIN]:
        subprocess.run(
            ["schtasks", "/delete", "/tn", old, "/f"],
            capture_output=True
        )

    # Create task: run every 15 min, pythonw = no console flash
    cmd = f'"{pythonw}" "{RECONNECT_SCRIPT}"'
    result = subprocess.run([
        "schtasks", "/create",
        "/tn", TASK_NAME,
        "/tr", cmd,
        "/sc", "minute", "/mo", "15",
        "/f"
    ], capture_output=True, text=True)

    if result.returncode == 0:
        print(f"[OK] Task '{TASK_NAME}' created (every 15 min)")
        print(f"     Runs: {cmd}")
        # Clean up old tasks report
        for old in OLD_TASKS:
            print(f"[OK] Removed old task: {old}")
        # Verify task was created with correct command
        verify = subprocess.run(
            ["schtasks", "/query", "/tn", TASK_NAME, "/v", "/fo", "LIST"],
            capture_output=True, text=True
        )
        if verify.returncode == 0:
            for line in verify.stdout.split("\n"):
                if "Task To Run:" in line:
                    actual_cmd = line.split("Task To Run:", 1)[1].strip()
                    if "pythonw" in actual_cmd.lower() and "vpn_reconnect.py" in actual_cmd:
                        print(f"[OK] Verified: {actual_cmd}")
                    else:
                        print(f"[WARN] Task command unexpected: {actual_cmd}")
                        print(f"       Expected pythonw.exe + vpn_reconnect.py")
                    break
        # Start it now
        subprocess.run(["schtasks", "/run", "/tn", TASK_NAME], capture_output=True)
        print("[OK] Task started")
    else:
        print(f"[FAIL] {result.stderr.strip()}")
        sys.exit(1)

    # Create login task: run once at user logon with 45s delay for desktop readiness
    result2 = subprocess.run([
        "schtasks", "/create",
        "/tn", TASK_NAME_LOGIN,
        "/tr", cmd,
        "/sc", "onlogon",
        "/delay", "0000:45",
        "/f"
    ], capture_output=True, text=True)

    if result2.returncode == 0:
        print(f"[OK] Task '{TASK_NAME_LOGIN}' created (on logon, 45s delay)")
    else:
        print(f"[WARN] Login task failed: {result2.stderr.strip()}")

    if HEADLESS or HEADLESS_SAFE or not sys.stdin.isatty():
        return
    input("\nPress Enter to close...")

def win_uninstall():
    if not win_is_admin():
        print("[..] Requesting admin privileges...", flush=True)
        win_elevate()
        return

    for name in [TASK_NAME, TASK_NAME_LOGIN] + OLD_TASKS:
        result = subprocess.run(
            ["schtasks", "/delete", "/tn", name, "/f"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"[OK] Removed: {name}")

    if HEADLESS or HEADLESS_SAFE or not sys.stdin.isatty():
        return
    input("\nPress Enter to close...")

def win_status():
    # No admin needed for query
    found = False
    for name in [TASK_NAME, TASK_NAME_LOGIN] + OLD_TASKS:
        result = subprocess.run(
            ["schtasks", "/query", "/tn", name, "/fo", "LIST"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            found = True
            print(f"=== {name} ===")
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if any(k in line for k in ["Status:", "Last Run", "Next Run"]):
                    print(f"  {line}")
            print()

    if not found:
        print("[--] No VPN tasks installed")
        print("     Run: python install.py install")

# ── macOS ───────────────────────────────────────────────────────────
PLIST_LABEL = "com.vpnmonitor.check"
PLIST_PATH = Path.home() / "Library" / "LaunchAgents" / f"{PLIST_LABEL}.plist"

def mac_make_plist():
    python = sys.executable
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{PLIST_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{RECONNECT_SCRIPT}</string>
    </array>
    <key>StartInterval</key>
    <integer>900</integer>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/vpnmonitor.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/vpnmonitor.err</string>
</dict>
</plist>"""

def mac_install():
    install_deps()
    ensure_config()
    PLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["launchctl", "unload", str(PLIST_PATH)], capture_output=True)
    PLIST_PATH.write_text(mac_make_plist())
    result = subprocess.run(["launchctl", "load", str(PLIST_PATH)], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"[OK] LaunchAgent '{PLIST_LABEL}' installed (every 15 min)")
        print(f"     Plist: {PLIST_PATH}")
    else:
        print(f"[FAIL] {result.stderr.strip()}")
        sys.exit(1)

def mac_uninstall():
    if PLIST_PATH.exists():
        subprocess.run(["launchctl", "unload", str(PLIST_PATH)], capture_output=True)
        PLIST_PATH.unlink()
        print(f"[OK] LaunchAgent '{PLIST_LABEL}' removed")
    else:
        print(f"[--] LaunchAgent not found")

def mac_status():
    result = subprocess.run(["launchctl", "list"], capture_output=True, text=True)
    for line in result.stdout.split("\n"):
        if PLIST_LABEL in line:
            parts = line.split()
            pid = parts[0] if parts[0] != "-" else "not running"
            print(f"=== {PLIST_LABEL} ===")
            print(f"  PID: {pid}")
            print(f"  Plist: {PLIST_PATH}")
            return
    print(f"[--] LaunchAgent '{PLIST_LABEL}' not installed")
    print(f"     Run: python install.py install")

# ── Setup ──────────────────────────────────────────────────────────
# pip name -> import name (when they differ)
IMPORT_MAP = {"pywin32": "win32api"}
WIN_DEPS = ["pywinauto", "pyautogui", "pyperclip", "pywin32"]
MAC_DEPS = ["pyautogui", "pyperclip"]

def install_deps():
    """Auto-install pip dependencies for the current platform."""
    deps = WIN_DEPS if IS_WINDOWS else MAC_DEPS
    missing = []
    for pkg in deps:
        mod = IMPORT_MAP.get(pkg, pkg.replace("-", "_").split("[")[0])
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)

    if not missing:
        print(f"[OK] Dependencies: all {len(deps)} installed")
        return

    print(f"[..] Installing {len(missing)} missing: {', '.join(missing)}")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[FAIL] pip install failed: {result.stderr.strip()}")
        sys.exit(1)
    print(f"[OK] Dependencies installed")

def _detect_email():
    """Auto-detect corporate email from OS directory or git config."""
    if IS_WINDOWS:
        # Windows AD: UPN is the user's email on domain-joined machines
        try:
            r = subprocess.run(["whoami", "/upn"], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and "@" in r.stdout:
                email = r.stdout.strip()
                print(f"[OK] Auto-detected email from AD: {email}")
                return email
        except Exception:
            pass
    elif IS_MAC:
        # macOS directory services (AD/Azure AD bound machines)
        import getpass
        user = getpass.getuser()
        try:
            r = subprocess.run(["dscl", ".", "-read", f"/Users/{user}", "EMailAddress"],
                               capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and "@" in r.stdout:
                email = r.stdout.split(":", 1)[-1].strip()
                print(f"[OK] Auto-detected email from directory: {email}")
                return email
        except Exception:
            pass
    # Fallback: git config (cross-platform)
    try:
        r = subprocess.run(["git", "config", "user.email"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0 and "@" in r.stdout:
            email = r.stdout.strip()
            print(f"[OK] Auto-detected email from git: {email}")
            return email
    except Exception:
        pass
    return ""

def ensure_config():
    """Ensure config.json exists with a valid email. Fail fast if not.

    Email resolution priority: --email flag > VPN_USER_EMAIL env > config.json value.
    """
    # Step 1: ensure config.json exists (copy from example if needed)
    if not CONFIG_PATH.exists():
        if CONFIG_EXAMPLE.exists():
            import shutil
            shutil.copy2(CONFIG_EXAMPLE, CONFIG_PATH)
            print(f"[OK] Created {CONFIG_PATH.name} from example")
        else:
            print(f"[FAIL] {CONFIG_PATH.name} not found and no example to copy from")
            sys.exit(1)

    with open(CONFIG_PATH) as f:
        config = json.load(f)

    # Step 2: resolve email (flag > env > config > AD auto-detect)
    email = (
        EMAIL_FLAG
        or os.environ.get("VPN_USER_EMAIL", "")
        or config.get("userEmail", "")
        or _detect_email()
    )

    if not email or email == "you@trendmicro.com":
        print(f"[FAIL] No email provided. Use one of:")
        print(f"       --email you@trendmicro.com")
        print(f"       VPN_USER_EMAIL=you@trendmicro.com")
        print(f"       Edit {CONFIG_PATH.name} and set userEmail")
        sys.exit(1)

    # Step 3: write resolved email into config (may have come from flag/env)
    if config.get("userEmail") != email:
        config["userEmail"] = email
        with open(CONFIG_PATH, "w") as f:
            json.dump(config, f, indent=2)
        print(f"[OK] Set email in {CONFIG_PATH.name}")

    print(f"[OK] Config: {config.get('vpnHost')} / {email}")

# ── Shared ──────────────────────────────────────────────────────────
def run_once():
    print(f"Running: {RECONNECT_SCRIPT}")
    result = subprocess.run([sys.executable, str(RECONNECT_SCRIPT)])
    sys.exit(result.returncode)

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    action = sys.argv[1].lower()

    if action == "run":
        run_once()
        return

    if not IS_WINDOWS and not IS_MAC:
        print(f"[FAIL] Unsupported platform: {platform.system()}")
        print("       Supported: Windows, macOS")
        sys.exit(1)

    dispatch = {
        "install":   win_install   if IS_WINDOWS else mac_install,
        "uninstall": win_uninstall if IS_WINDOWS else mac_uninstall,
        "status":    win_status    if IS_WINDOWS else mac_status,
    }

    if action in dispatch:
        dispatch[action]()
    else:
        print(f"Unknown action: {action}")
        print(__doc__)
        sys.exit(1)

if __name__ == "__main__":
    main()
