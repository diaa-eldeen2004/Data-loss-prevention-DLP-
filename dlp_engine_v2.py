#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║     DLP ENGINE v2  --  Banking Card Data Protection         ║
║     FIXED for Python 3.14 + Windows                        ║
║     Project 3: Data Loss Prevention                         ║
╚══════════════════════════════════════════════════════════════╝

CLIPBOARD METHOD:
  Python 3.14 has a known ctypes threading issue with WM_CLIPBOARDUPDATE.
  This version uses a fast 0.3-second poll via PowerShell which is stable
  on all Python versions and still clears the clipboard before a human
  can realistically paste anything.

COPY/MOVE PREVENTION (P6) -- HARDENED v2:
  Three-layer defence so that even a direct  cp / xcopy / robocopy
  command cannot exfiltrate a sensitive file:

  Layer 1 -- icacls FILE LOCK (PROACTIVE):
    As soon as a file is identified as sensitive, icacls strips the
    Read permission from Everyone except the SYSTEM account.
    This means  cp, xcopy, robocopy, Explorer drag-copy ALL fail at
    the OS level with "Access is denied" -- before any bytes leave
    the monitored folder.

  Layer 2 -- watchdog on_moved (REACTIVE -- instant):
    Catches any rename / move out of the monitored folder and
    restores the file immediately.

  Layer 3 -- hash-registry copy scanner (REACTIVE -- 2 s):
    Walks every relevant directory (including all OneDrive paths and
    every drive letter present on the machine) for files whose
    SHA-256 matches a registered sensitive file. Deletes rogue copies
    and raises an alert.
"""

import re
import os
import sys
import time
import shutil
import hashlib
import threading
import subprocess
import string
from datetime import datetime
from pathlib import Path

# ── Windows check ─────────────────────────────────────────────
if sys.platform != "win32":
    print("[ERROR] This script requires Windows.")
    sys.exit(1)

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    from colorama import init, Fore, Back
    init(autoreset=True)
except ImportError:
    print("Run first:  pip install watchdog colorama")
    sys.exit(1)

# ─────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────
BASE_PATH         = r"C:\Users\hp\Desktop\Cyber_Gaurd_Projects\Project_3_(DLP_Implementation)"
MONITORED_FOLDER  = os.path.join(BASE_PATH, "monitored_folder")
QUARANTINE_FOLDER = os.path.join(BASE_PATH, "quarantine")
LOG_FILE          = os.path.join(BASE_PATH, "logs", "dlp_audit.log")
ALERT_FILE        = os.path.join(BASE_PATH, "logs", "dlp_alerts.log")

POLICIES = {
    "P1_FILE_SCAN":         True,
    "P2_CLIPBOARD_PREVENT": True,
    "P3_PRINT_BLOCK":       True,
    "P4_QUARANTINE":        True,
    "P5_ALERT_SOC":         True,
    "P6_COPY_MOVE_PREVENT": True,
}

# ─────────────────────────────────────────────────────────────
#  DYNAMIC SCAN ROOTS
#  Builds the list at runtime: every local drive + every OneDrive
#  variant found under the current user's profile.
# ─────────────────────────────────────────────────────────────
def _build_scan_roots() -> list[str]:
    roots = []

    # 1. All local drive letters that exist
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            roots.append(drive)

    # 2. Common user folders (covers OneDrive, Desktop, Documents, Downloads)
    user_profile = os.environ.get("USERPROFILE", "")
    if user_profile:
        for sub in [
            "Desktop", "Documents", "Downloads", "Pictures",
            "OneDrive", "OneDrive - Personal",
        ]:
            candidate = os.path.join(user_profile, sub)
            if os.path.exists(candidate):
                roots.append(candidate)

        # Any folder starting with "OneDrive" directly under the profile
        try:
            for entry in os.listdir(user_profile):
                if entry.lower().startswith("onedrive"):
                    full = os.path.join(user_profile, entry)
                    if os.path.isdir(full) and full not in roots:
                        roots.append(full)
        except Exception:
            pass

    # Deduplicate while preserving order
    seen = set()
    deduped = []
    for r in roots:
        key = r.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(r)
    return deduped

SCAN_ROOTS: list[str] = _build_scan_roots()

# ─────────────────────────────────────────────────────────────
#  CARD DETECTION  --  Regex + Luhn Algorithm
# ─────────────────────────────────────────────────────────────
CARD_PATTERNS = {
    "VISA": re.compile(
        r'\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
    ),
    "MASTERCARD": re.compile(
        r'\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
    ),
    "MASTERCARD_NEW": re.compile(
        r'\b2[2-7][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b'
    ),
    "CVV": re.compile(
        r'\b(CVV|cvv|CVC|cvc)[\s:\-]*([0-9]{3,4})\b'
    ),
}

def luhn_check(card_number: str) -> bool:
    digits = re.sub(r'\D', '', card_number)
    if not (13 <= len(digits) <= 19):
        return False
    total = 0
    for i, d in enumerate(digits[::-1]):
        n = int(d)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0

def mask_card(s: str) -> str:
    d = re.sub(r'\D', '', s)
    return (d[:4] + " **** **** " + d[-4:]) if len(d) >= 12 else "****"

def detect_card_numbers(text: str) -> list:
    findings = []
    for card_type, pattern in CARD_PATTERNS.items():
        for match in pattern.finditer(text):
            raw = match.group()
            if card_type in ("VISA", "MASTERCARD", "MASTERCARD_NEW"):
                findings.append({
                    "type":    card_type,
                    "value":   raw,
                    "masked":  mask_card(raw),
                    "luhn_ok": luhn_check(raw),
                })
            else:
                findings.append({
                    "type":    card_type,
                    "value":   raw,
                    "masked":  "****",
                    "luhn_ok": None,
                })
    return findings

# ─────────────────────────────────────────────────────────────
#  LOGGING & ALERTING
# ─────────────────────────────────────────────────────────────
violation_count = 0
alert_count     = 0
print_lock      = threading.Lock()

def log_event(level: str, msg: str, detail: str = ""):
    ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{ts}] [{level}] {msg}"
    if detail:
        entry += f"\n           DETAILS: {detail}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass

def raise_alert(policy: str, source: str, findings: list, action: str):
    global violation_count, alert_count
    violation_count += 1
    alert_count     += 1
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    severity = "HIGH" if len(findings) > 2 else "MEDIUM"

    lines = [
        "",
        "=" * 56,
        f"  DLP ALERT #{alert_count:03d}  --  {severity} SEVERITY",
        "=" * 56,
        f"  Time     : {ts}",
        f"  Policy   : {policy}",
        f"  Source   : {source}",
        f"  Action   : {action}",
        f"  Findings : {len(findings)} sensitive item(s)",
        "-" * 56,
    ]
    for fi in findings[:5]:
        lines.append(f"  [{fi['type']}]  {fi['masked']}  Luhn={fi['luhn_ok']}")
    lines.append("=" * 56)

    alert_text = "\n".join(lines)

    try:
        with open(ALERT_FILE, "a", encoding="utf-8") as f:
            f.write(alert_text + "\n")
    except Exception:
        pass

    with print_lock:
        print(Fore.RED + alert_text)

    log_event("ALERT", f"Policy {policy} violated",
              f"Source={source}, Findings={len(findings)}, Action={action}")

# ─────────────────────────────────────────────────────────────
#  POLICY 1  --  FILE WATCHER (Watchdog)
# ─────────────────────────────────────────────────────────────
def scan_file(path: str):
    skip = {'.exe', '.dll', '.jpg', '.png', '.mp4', '.zip', '.pdf'}
    if Path(path).suffix.lower() in skip:
        return
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        findings = detect_card_numbers(content)

        if findings:
            with print_lock:
                print(Fore.YELLOW +
                      f"\n[FILE DLP]  Card data detected in: {os.path.basename(path)}")

            # P6: Lock the file BEFORE quarantine so no race-condition copy escapes
            if POLICIES["P6_COPY_MOVE_PREVENT"]:
                lock_file_permissions(path)
                register_sensitive_file(path)

            action = "FILE QUARANTINED" if POLICIES["P4_QUARANTINE"] else "ALERT ONLY"
            if POLICIES["P4_QUARANTINE"]:
                quarantine_file(path)
            if POLICIES["P5_ALERT_SOC"]:
                raise_alert(
                    "P1: File Scan + P4: Quarantine",
                    path, findings, action
                )
        else:
            with print_lock:
                print(Fore.GREEN +
                      f"[FILE DLP]  Clean: {os.path.basename(path)}")
            log_event("INFO", "File scanned CLEAN", path)

    except PermissionError:
        pass
    except Exception as e:
        log_event("ERROR", f"Scan error: {path}", str(e))

def quarantine_file(path: str):
    try:
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        name = os.path.basename(path)
        dest = os.path.join(QUARANTINE_FOLDER, f"QUARANTINE_{ts}_{name}")
        # Restore full permissions so WE can move it, then move it
        unlock_file_permissions(path)
        shutil.move(path, dest)
        # Re-lock at the quarantine destination
        lock_file_permissions(dest)
        with print_lock:
            print(Fore.RED + f"[QUARANTINE] File moved --> quarantine folder")
        log_event("ACTION", "File quarantined", f"{path} -> {dest}")
    except Exception as e:
        log_event("ERROR", "Quarantine failed", str(e))

class DLPFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.5)
            scan_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            time.sleep(0.5)
            scan_file(event.src_path)

    def on_moved(self, event):
        """Layer 2: intercept any move/rename out of the monitored folder."""
        if event.is_directory:
            return
        src  = event.src_path
        dest = event.dest_path

        src_inside  = str(src).lower().startswith(MONITORED_FOLDER.lower())
        dest_inside = str(dest).lower().startswith(MONITORED_FOLDER.lower())

        if src_inside and not dest_inside and POLICIES["P6_COPY_MOVE_PREVENT"]:
            block_move(src, dest)

# ─────────────────────────────────────────────────────────────
#  POLICY 2  --  CLIPBOARD MONITOR
# ─────────────────────────────────────────────────────────────
def get_clipboard():
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", "Get-Clipboard"],
            capture_output=True, text=True, timeout=2
        )
        return result.stdout.strip()
    except Exception:
        return ""

def clear_clipboard():
    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Set-Clipboard -Value $null; [System.Windows.Forms.Clipboard]::Clear()"],
            capture_output=True, timeout=2
        )
    except Exception:
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Add-Type -AssemblyName System.Windows.Forms; "
                 "[System.Windows.Forms.Clipboard]::Clear()"],
                capture_output=True, timeout=2
            )
        except Exception:
            pass

def monitor_clipboard():
    last = ""
    with print_lock:
        print(Fore.GREEN +
              "[CLIPBOARD] Monitor ACTIVE -- polling every 0.3 seconds")
    log_event("SYSTEM", "Clipboard monitor started")

    while True:
        try:
            current = get_clipboard()
            if current and current != last:
                last = current
                findings = detect_card_numbers(current)
                if findings:
                    clear_clipboard()
                    last = ""
                    with print_lock:
                        print(Fore.RED + Back.BLACK +
                              "\n[CLIPBOARD] BLOCKED -- Card data prevented!"
                              "\n[CLIPBOARD] Clipboard cleared. Ctrl+V will paste nothing.")
                    if POLICIES["P5_ALERT_SOC"]:
                        raise_alert(
                            "P2: Clipboard Prevention",
                            "CLIPBOARD -- User copy action",
                            findings,
                            "CLIPBOARD CLEARED -- PASTE BLOCKED"
                        )
        except Exception:
            pass
        time.sleep(0.3)

# ─────────────────────────────────────────────────────────────
#  POLICY 3  --  PRINT BLOCK (simulated)
# ─────────────────────────────────────────────────────────────
def simulate_print_block(content: str, printer: str = "BANK_PRINTER_01"):
    with print_lock:
        print(Fore.YELLOW + f"\n[PRINT DLP] Print job intercepted --> {printer}")
    findings = detect_card_numbers(content)
    if findings:
        with print_lock:
            print(Fore.RED +
                  f"[PRINT DLP] BLOCKED -- {len(findings)} card number(s) found")
        raise_alert(
            "P3: Print Block",
            f"PRINT JOB --> {printer}",
            findings,
            "PRINT JOB CANCELLED"
        )
        return False
    with print_lock:
        print(Fore.GREEN + "[PRINT DLP] Approved -- no sensitive data found")
    log_event("INFO", f"Print approved for {printer}")
    return True

# ─────────────────────────────────────────────────────────────
#  POLICY 6  --  COPY / MOVE PREVENTION  (HARDENED v2)
# ─────────────────────────────────────────────────────────────

# Thread-safe hash registry: { sha256_hex -> original_path }
sensitive_hash_registry: dict[str, str] = {}
registry_lock = threading.Lock()


# ── Layer 1: icacls file locking ──────────────────────────────

def lock_file_permissions(path: str):
    """
    Strip Read permission for all non-SYSTEM users via icacls.
    After this, cp / xcopy / Explorer copy will fail with Access Denied.
    The DLP process (running as the same user) re-grants itself access
    via unlock_file_permissions() when it needs to move/quarantine the file.
    """
    try:
        # Remove inherited permissions and deny Read to Everyone
        subprocess.run(
            ["icacls", path, "/inheritance:d"],
            capture_output=True, check=False
        )
        subprocess.run(
            ["icacls", path, "/deny", "Everyone:(R,RX)"],
            capture_output=True, check=False
        )
        with print_lock:
            print(Fore.RED +
                  f"[P6-LOCK]   Read access DENIED on: {os.path.basename(path)}")
        log_event("P6", "File locked -- Read denied to Everyone", path)
    except Exception as e:
        log_event("ERROR", "lock_file_permissions failed", str(e))


def unlock_file_permissions(path: str):
    """
    Restore normal permissions so the DLP engine can move/quarantine the file.
    Called internally only -- never exposed to end users.
    """
    try:
        subprocess.run(
            ["icacls", path, "/remove:d", "Everyone"],
            capture_output=True, check=False
        )
        subprocess.run(
            ["icacls", path, "/inheritance:e"],
            capture_output=True, check=False
        )
        log_event("P6", "File unlocked for internal DLP operation", path)
    except Exception as e:
        log_event("ERROR", "unlock_file_permissions failed", str(e))


# ── Layer 2: watchdog move blocker ────────────────────────────

def block_move(original_src: str, attempted_dest: str):
    """Called by on_moved when a sensitive file leaves the monitored folder."""
    try:
        if os.path.exists(attempted_dest):
            unlock_file_permissions(attempted_dest)
            shutil.move(attempted_dest, original_src)
            lock_file_permissions(original_src)
            restored = True
        else:
            restored = False

        with print_lock:
            print(Fore.RED + Back.BLACK +
                  f"\n[MOVE BLOCK] BLOCKED -- Attempted move of sensitive file!"
                  f"\n[MOVE BLOCK] From : {original_src}"
                  f"\n[MOVE BLOCK] To   : {attempted_dest}"
                  f"\n[MOVE BLOCK] {'File restored and re-locked.' if restored else 'WARNING: Could not restore file.'}")

        try:
            unlock_file_permissions(original_src)
            with open(original_src, "r", encoding="utf-8", errors="ignore") as f:
                findings = detect_card_numbers(f.read())
            lock_file_permissions(original_src)
        except Exception:
            findings = [{"type": "UNKNOWN", "masked": "****", "luhn_ok": None}]

        if POLICIES["P5_ALERT_SOC"]:
            raise_alert(
                "P6: Copy/Move Prevention",
                original_src,
                findings,
                f"MOVE BLOCKED & FILE RESTORED  -->  {attempted_dest}"
            )
        log_event("ACTION", "Move blocked and file restored",
                  f"Attempted destination: {attempted_dest}")

    except Exception as e:
        log_event("ERROR", "block_move failed", str(e))


# ── Layer 3: hash-registry copy scanner ──────────────────────

def _file_sha256(path: str) -> str | None:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def register_sensitive_file(path: str):
    digest = _file_sha256(path)
    if digest:
        with registry_lock:
            sensitive_hash_registry[digest] = path
        log_event("P6", "Sensitive file registered for copy-watch",
                  f"SHA256={digest[:16]}…  PATH={path}")


def deregister_sensitive_file(path: str):
    digest = _file_sha256(path)
    if digest:
        with registry_lock:
            sensitive_hash_registry.pop(digest, None)


def _scan_for_escaped_copies():
    """
    Background thread: walks ALL drives + OneDrive paths every 2 seconds.
    Deletes any file whose SHA-256 matches a registered sensitive file
    but lives outside the monitored folder.
    """
    skip_ext = {'.exe', '.dll', '.sys', '.lnk', '.ico',
                '.jpg', '.png', '.mp4', '.zip'}
    log_event("SYSTEM", "P6 copy-detection scanner started",
              f"Roots: {', '.join(SCAN_ROOTS)}")

    with print_lock:
        print(Fore.CYAN + f"[P6-SCAN]   Watching {len(SCAN_ROOTS)} root(s) for escaped copies")

    while True:
        time.sleep(2)

        with registry_lock:
            snapshot = dict(sensitive_hash_registry)

        if not snapshot:
            continue

        for root in SCAN_ROOTS:
            if not os.path.exists(root):
                continue
            try:
                for dirpath, dirs, filenames in os.walk(root, topdown=True):
                    # Skip monitored + quarantine folders
                    norm = dirpath.lower()
                    if (norm.startswith(MONITORED_FOLDER.lower()) or
                            norm.startswith(QUARANTINE_FOLDER.lower())):
                        dirs.clear()
                        continue
                    # Skip Windows system dirs to avoid permission storms
                    skip_dirs = {"windows", "program files", "program files (x86)",
                                 "$recycle.bin", "system volume information"}
                    dirs[:] = [d for d in dirs
                               if d.lower() not in skip_dirs]

                    for fname in filenames:
                        if Path(fname).suffix.lower() in skip_ext:
                            continue
                        fpath = os.path.join(dirpath, fname)
                        digest = _file_sha256(fpath)
                        if digest and digest in snapshot:
                            _handle_rogue_copy(fpath, snapshot[digest], digest)
            except PermissionError:
                continue
            except Exception:
                continue


def _handle_rogue_copy(rogue_path: str, original_path: str, digest: str):
    try:
        os.remove(rogue_path)
        deleted = True
    except Exception:
        deleted = False

    with print_lock:
        print(Fore.RED + Back.BLACK +
              f"\n[COPY BLOCK] BLOCKED -- Unauthorised copy detected!"
              f"\n[COPY BLOCK] Rogue copy : {rogue_path}"
              f"\n[COPY BLOCK] Original   : {original_path}"
              f"\n[COPY BLOCK] {'Rogue copy DELETED.' if deleted else 'WARNING: Could not delete rogue copy.'}")

    try:
        unlock_file_permissions(original_path)
        with open(original_path, "r", encoding="utf-8", errors="ignore") as f:
            findings = detect_card_numbers(f.read())
        lock_file_permissions(original_path)
    except Exception:
        findings = [{"type": "UNKNOWN", "masked": "****", "luhn_ok": None}]

    if POLICIES["P5_ALERT_SOC"]:
        raise_alert(
            "P6: Copy/Move Prevention",
            original_path,
            findings,
            f"COPY DETECTED & DELETED  -->  {rogue_path}"
        )
    log_event("ACTION", "Rogue copy deleted",
              f"Copy at: {rogue_path}  |  SHA256={digest[:16]}…")


# ─────────────────────────────────────────────────────────────
#  DASHBOARD
# ─────────────────────────────────────────────────────────────
def run_dashboard():
    while True:
        time.sleep(30)
        with print_lock:
            print(Fore.CYAN +
                  f"\n[DASHBOARD] {datetime.now().strftime('%H:%M:%S')}"
                  f"  |  Total violations: {violation_count}"
                  f"  |  Status: ACTIVE")

# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
def main():
    os.makedirs(MONITORED_FOLDER,  exist_ok=True)
    os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    print(Fore.GREEN + """
╔════════════════════════════════════════════════════════════════╗
║   BANK DLP ENGINE v2  --  Starting Up                         ║
║   VISA / MasterCard Data Protection                           ║
╠════════════════════════════════════════════════════════════════╣
║   P1: File System Scan        ON   Watchdog real-time         ║
║   P2: Clipboard Prevention    ON   0.3s polling (stable)      ║
║   P3: Print Job Block         ON   Pre-spooler check          ║
║   P4: Auto-Quarantine         ON   Instant file removal       ║
║   P5: SOC Alerting            ON   Structured logs            ║
║   P6: Copy/Move Prevention    ON   icacls lock + hash scan    ║
╚════════════════════════════════════════════════════════════════╝
""")

    log_event("SYSTEM", "DLP Engine v2 started", "All 6 policies active")

    # P1 + P6 Layer 2: File watcher
    observer = Observer()
    observer.schedule(DLPFileHandler(), MONITORED_FOLDER, recursive=True)
    observer.start()
    print(Fore.GREEN + f"[FILE]      Watching: {MONITORED_FOLDER}")

    # P2: Clipboard monitor
    if POLICIES["P2_CLIPBOARD_PREVENT"]:
        threading.Thread(
            target=monitor_clipboard,
            daemon=True,
            name="DLP-Clipboard"
        ).start()

    # P6 Layer 3: Background copy-scanner
    if POLICIES["P6_COPY_MOVE_PREVENT"]:
        threading.Thread(
            target=_scan_for_escaped_copies,
            daemon=True,
            name="DLP-CopyScanner"
        ).start()
        print(Fore.GREEN + "[P6]        Copy/Move prevention ACTIVE  (3 layers)")
        print(Fore.GREEN + f"[P6]        Scan roots detected: {len(SCAN_ROOTS)}")
        for r in SCAN_ROOTS:
            print(Fore.GREEN + f"            --> {r}")

    # Dashboard
    threading.Thread(target=run_dashboard, daemon=True).start()

    # P3: Demo print block
    time.sleep(1)
    print(Fore.YELLOW + "\n[DEMO] Running print block test...")
    simulate_print_block(
        "Customer: Ahmed Hassan\nCard: 4532 1234 5678 9012\nBalance: $12,000",
        "BANK_PRINTER_01"
    )

    print(Fore.GREEN + "\n[DLP v2] All systems active.")
    print(Fore.WHITE + f"  1. Drop files into  --> {MONITORED_FOLDER}")
    print(Fore.WHITE +  "  2. Try  cp test_customers.txt C:\\Users\\hp\\OneDrive\\Documents")
    print(Fore.WHITE +  "     --> Access is denied  (icacls lock)")
    print(Fore.WHITE +  "  3. Try moving a sensitive file out  --> snaps back instantly")
    print(Fore.WHITE +  "  4. Copy this number -> 4532 1234 5678 9012")
    print(Fore.WHITE +  "     Then Ctrl+V     -> Nothing will paste")
    print(Fore.WHITE +  "\n  Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log_event("SYSTEM", "DLP Engine v2 stopped")
        print(Fore.YELLOW + f"\n[DLP] Stopped. Violations: {violation_count}")
        print(Fore.GREEN  + f"[DLP] Audit log --> {LOG_FILE}")
        print(Fore.GREEN  + f"[DLP] Alerts    --> {ALERT_FILE}")

    observer.join()

if __name__ == "__main__":
    main()