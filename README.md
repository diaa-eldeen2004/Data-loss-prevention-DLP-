# 🔏 Project 3 — DLP Implementation
## Banking Card Data Protection (VISA / MasterCard)

**Presented by:** Diaa El-deen  
**Organization:** CyberGuard X  
**Date:** June 2026  
**Diploma:** Cybersecurity

---

## 📋 Project Overview

This project implements a **Data Loss Prevention (DLP) system** designed to protect sensitive banking card data inside a simulated corporate environment. The system detects, blocks, and alerts on any attempt to leak **VISA or MasterCard** numbers through multiple channels — files, clipboard, and print jobs.

The DLP engine was built in **Python** and runs on **Windows**, simulating the kind of protection that real banks deploy to comply with **PCI-DSS** (Payment Card Industry Data Security Standard).

---

## 🎯 Objective

Build a working DLP system that:
- Detects real VISA and MasterCard numbers using pattern matching and mathematical validation
- Monitors multiple data exfiltration channels simultaneously
- Blocks sensitive data **before** it can be leaked
- Generates structured audit logs and SOC alerts
- Simulates a real banking environment scenario

---

## 🏦 Scenario

```
A bank employee's workstation has access to customer card records.

The DLP system monitors everything the employee does:

  Saves a file with card numbers?   → File quarantined automatically
  Copies a card number (Ctrl+C)?    → Clipboard cleared instantly
  Tries to print card data?         → Print job cancelled
  Any violation?                    → SOC alert generated + audit log written
```

---

## 🗂️ Project Folder Structure

```
Project_3_(DLP_Implementation)\
│
├── dlp_engine_v2.py              ← Main DLP engine (the brain)
│
├── test_customers.txt            ← Fake bank data used for testing
│
├── monitored_folder\             ← WATCHED ZONE
│   └── (drop any file here to trigger DLP scan)
│
├── quarantine\                   ← JAIL FOR VIOLATING FILES
│   └── QUARANTINE_[timestamp]_[filename]
│
└── logs\
    ├── dlp_audit.log             ← Full activity log (every event)
    └── dlp_alerts.log            ← SOC alerts only (violations)
```

### What Each Folder Means

| Folder / File | Purpose |
|---------------|---------|
| `dlp_engine_v2.py` | The complete DLP engine. Contains all 5 policies, card detection, file watcher, clipboard monitor, print blocker, quarantine, and alerting system |
| `test_customers.txt` | Simulated bank customer records containing VISA and MasterCard numbers. Used as the test payload to trigger the DLP |
| `monitored_folder\` | The "sensitive documents area" — represents a bank's shared drive. Every file saved here is scanned instantly |
| `quarantine\` | Files that failed the DLP scan are automatically moved here. The SOC analyst can review them safely. Filenames get a timestamp prefix |
| `logs\dlp_audit.log` | Timestamped log of every event — clean scans, violations, quarantine actions, system start/stop. Required for PCI-DSS compliance |
| `logs\dlp_alerts.log` | Structured SOC alerts only. Contains severity level, policy ID, masked card number, and action taken. Ready to feed into a SIEM |

---

## ⚙️ How the DLP Engine Works

### Card Detection — Two Layers

The engine uses **two methods together** to detect card numbers with near-zero false positives:

#### Layer 1 — Regex Pattern Matching
```
VISA        starts with 4 + 15 more digits  →  4xxx xxxx xxxx xxxx
MasterCard  starts with 51-55 + 14 digits   →  5xxx xxxx xxxx xxxx
MasterCard  new range starts with 2221-2720 →  2xxx xxxx xxxx xxxx
CVV         keyword + 3-4 digits            →  CVV: 123
```

#### Layer 2 — Luhn Algorithm Validation
After a regex match is found, the number is validated using the **Luhn Algorithm** — the same mathematical check that banks and payment processors use on every real card:

```
Step 1: Reverse the digits
Step 2: Double every second digit from the right
Step 3: If the doubled digit is > 9, subtract 9
Step 4: Sum all digits
Step 5: If total % 10 == 0 → the card number is VALID
```

> Without the Luhn check, the system would generate false positives on any random 16-digit number. With it, only mathematically valid card numbers trigger alerts.

---

## 🛡️ The 5 DLP Policies

### Policy 1 — File System Scan (Real-Time)

```
How it works:
  Watchdog library monitors the monitored_folder\ in real-time
  Any file created or modified → immediately scanned
  Card data found → Policy 4 (quarantine) + Policy 5 (alert) triggered
  No card data → green checkmark, file stays

Why it matters:
  Employees often save card data to shared drives or USB-destined folders
  Real-time scanning catches it the moment the file is saved
  This is Zero Trust for files — every file is scanned, no exceptions
```

### Policy 2 — Clipboard Prevention (Real-Time)

```
How it works:
  A background thread polls the clipboard every 0.3 seconds
  User copies text containing a card number (Ctrl+C)
  DLP detects it within 0.3 seconds
  Clipboard is cleared immediately using PowerShell
  User presses Ctrl+V → nothing pastes

Why it matters:
  Clipboard is the most common unmonitored exfiltration path
  Employees copy card numbers to paste into emails, chat apps, web forms
  The data is GONE before it can be pasted anywhere
```

### Policy 3 — Print Job Blocking (Simulated)

```
How it works:
  The engine intercepts print job content before it reaches the spooler
  Content is scanned for card numbers
  Card data found → print job cancelled, alert raised
  Clean content → print job approved and logged

Why it matters:
  Physical printing is the #1 unmonitored channel in most organisations
  A card number printed on paper walks out of the building undetected
  Real DLP tools (Symantec, Forcepoint) hook directly into Windows Print Spooler
  This project simulates that interception logic
```

### Policy 4 — Auto-Quarantine

```
How it works:
  Triggered automatically when Policy 1 finds card data in a file
  File is MOVED (not deleted) to the quarantine\ folder
  Filename gets timestamp prefix: QUARANTINE_20260610_143022_filename.txt
  Original location is now empty — file cannot be accessed or sent

Why it matters:
  Quarantine preserves the file for forensic investigation
  The SOC analyst can review it safely without risk of further leakage
  Timestamped naming creates a clear evidence trail
```

### Policy 5 — SOC Alerting

```
How it works:
  Every violation triggers a structured alert written to dlp_alerts.log
  Alert contains: timestamp, severity (HIGH/MEDIUM), policy ID,
  source (file path / clipboard / printer), masked card number, action taken
  All events also written to dlp_audit.log for compliance

Alert format example:
  ========================================================
  DLP ALERT #001  --  MEDIUM SEVERITY
  ========================================================
  Time     : 2026-06-10 14:49:41
  Policy   : P1: File Scan + P4: Quarantine
  Source   : C:\...\monitored_folder\test_customers.txt
  Action   : FILE QUARANTINED
  Findings : 3 sensitive item(s)
  --------------------------------------------------------
  [VISA]        4532 **** **** 9012  Luhn=True
  [MASTERCARD]  5412 **** **** 9876  Luhn=True
  [CVV]         ****                 Luhn=None
  ========================================================
```

---

## 🧪 Test Cases

### Test 1 — File with Card Data (Should be Quarantined)

```powershell
copy "...\test_customers.txt" "...\monitored_folder\"
```

| Expected Result | |
|---|---|
| DLP terminal | Shows yellow warning + red quarantine message + alert |
| monitored_folder\ | File is GONE (moved to quarantine) |
| quarantine\ | Shows QUARANTINE_[timestamp]_test_customers.txt |
| dlp_alerts.log | Alert #001 written with card details masked |

---

### Test 2 — Clean File (Should Pass)

```powershell
echo "Team meeting at 9am tomorrow" > "...\monitored_folder\memo.txt"
```

| Expected Result | |
|---|---|
| DLP terminal | Shows green checkmark — Clean: memo.txt |
| monitored_folder\ | File stays — not quarantined |
| dlp_alerts.log | No new entry |
| dlp_audit.log | INFO entry: File scanned CLEAN |

---

### Test 3 — Clipboard Copy (Should be Blocked)

```
1. Open Notepad
2. Type:   4532 1234 5678 9012
3. Select → Ctrl+C
4. Open anything → Ctrl+V
5. Result: Nothing pastes
```

| Expected Result | |
|---|---|
| DLP terminal | BLOCKED -- Card data prevented! Clipboard cleared. |
| Clipboard | Empty — paste returns nothing |
| dlp_alerts.log | Alert written: CLIPBOARD CLEARED -- PASTE BLOCKED |

---

### Test 4 — Print Block (Auto-runs at Startup)

Runs automatically when the engine starts as a demonstration.

| Expected Result | |
|---|---|
| DLP terminal | Print job intercepted → BLOCKED -- 1 card number found |
| dlp_alerts.log | Alert: PRINT JOB CANCELLED |

---

### Test 5 — View All Logs

```powershell
# Full audit trail
type "...\logs\dlp_audit.log"

# SOC alerts only
type "...\logs\dlp_alerts.log"

# Quarantined files
dir "...\quarantine\"
```

---

## 📊 DLP Coverage Summary

| Exfiltration Channel | Monitored | Blocked | Method |
|----------------------|-----------|---------|--------|
| File saved to disk | ✅ Yes | ✅ Yes | Watchdog + quarantine |
| Copy to clipboard | ✅ Yes | ✅ Yes | 0.3s poll + clear |
| Print job | ✅ Yes | ✅ Yes (simulated) | Content scan pre-spooler |
| Email attachment | ⚠️ Partial | ⚠️ Alert only | Log-based detection |
| USB transfer | ❌ Not implemented | ❌ | Needs OS-level agent |
| Network upload | ❌ Not implemented | ❌ | Needs network DLP |

---

## 🔍 What the SOC Analyst Gets

| Output | Location | Used For |
|--------|----------|----------|
| Real-time terminal alerts | PowerShell window | Immediate awareness |
| Structured alert log | logs\dlp_alerts.log | SIEM ingestion · Incident tickets |
| Full audit log | logs\dlp_audit.log | PCI-DSS compliance · Forensics |
| Quarantined files | quarantine\ | Evidence · Investigation |
| Masked card numbers | All logs | Safe logging without exposing real data |

---

## 🏛️ PCI-DSS Alignment

This project aligns with the following PCI-DSS 3.2.1 requirements:

| PCI-DSS Requirement | How This Project Meets It |
|---------------------|---------------------------|
| Req 3 — Protect stored cardholder data | Files with card data are quarantined immediately |
| Req 7 — Restrict access to cardholder data | Clipboard and print channels blocked |
| Req 10 — Track and monitor all access | Every event logged with timestamp in audit log |
| Req 10.2 — Audit logs for all access | dlp_audit.log records every scan and action |
| Req 12.10 — Incident response | Alerts formatted for SOC triage and response |

---

## 🛠️ Technologies & Libraries Used

| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.14 | Core engine language |
| watchdog | Latest | Real-time file system monitoring |
| colorama | Latest | Colored terminal output |
| subprocess / PowerShell | Built-in | Clipboard read and clear operations |
| re (regex) | Built-in | Card number pattern matching |
| threading | Built-in | Concurrent policy execution |
| shutil | Built-in | File quarantine (move operation) |

---

## 🚀 How to Run

### Prerequisites
```powershell
pip install watchdog colorama
```

### Run the Engine
```powershell
cd "C:\Users\hp\Desktop\Cyber_Gaurd_Projects\Project_3_(DLP_Implementation)"
python dlp_engine_v2.py
```

### Run Tests (second terminal)
```powershell
# Test 1 — File scan
copy test_customers.txt monitored_folder\

# Test 2 — Clean file
echo "clean text" > monitored_folder\memo.txt

# Test 3 — Clipboard (manual)
# Open Notepad → type 4532 1234 5678 9012 → Ctrl+C → try Ctrl+V
```

---

## 🏢 Real-World Enterprise Equivalents

| Our Implementation | Enterprise Product | Key Enhancement Over Ours |
|--------------------|--------------------|--------------------------|
| File scan (Watchdog) | Microsoft Purview DLP | Covers SharePoint, OneDrive, Teams |
| Clipboard monitor | Symantec DLP Endpoint | Agent-level hook, zero polling delay |
| Print blocker | Forcepoint DLP | Direct Windows Print Spooler API hook |
| Card detection (Regex+Luhn) | Forcepoint / McAfee DLP | OCR to detect card numbers in images |
| Audit log | Splunk / QRadar SIEM | Automated correlation across all users |
| Quarantine | Digital Guardian | Full forensic capture + user notification |
| PCI-DSS logging | AWS Macie / Azure Purview | AI-powered cloud storage classification |

---

## 📚 Key Concepts Demonstrated

1. **Data at Rest Protection** — Files containing card data are quarantined the moment they are saved
2. **Data in Use Protection** — Clipboard is monitored and cleared in real-time
3. **Data in Motion Protection** — Print jobs intercepted before reaching physical output
4. **Luhn Algorithm** — Mathematical card validation that eliminates false positives
5. **PCI-DSS Compliance** — Audit logging and card masking aligned with payment security standards
6. **Card Masking** — Logs never store the full card number — only `4532 **** **** 9012` format
7. **Zero Trust for Data** — Every file scanned regardless of source or user

---

## ⚠️ Known Limitations

| Limitation | Reason | Real-World Fix |
|------------|--------|----------------|
| Print block is simulated | No direct Windows Spooler API hook | Symantec / Forcepoint spooler integration |
| Clipboard polling (0.3s) | Python 3.14 ctypes threading bug prevents instant hook | Downgrade to Python 3.11 or use C++ agent |
| No USB monitoring | Requires kernel-level driver | McAfee DLP Endpoint agent |
| No network DLP | No proxy hook implemented | Forcepoint Network DLP / Zscaler |
| No image/OCR scanning | Only scans text files | Forcepoint OCR engine |

---

## ✅ Conclusion

This project proved that **effective DLP is about content intelligence** — not just perimeter control. Traditional security tools like firewalls and antivirus cannot read file content. DLP fills that gap.

The key achievements of this project:

- **Card detection engine** built with Regex + Luhn — same validation banks use
- **3 exfiltration channels** monitored: files, clipboard, print
- **5 active policies** running simultaneously in real-time
- **PCI-DSS aligned** audit logs with masked card numbers
- **SOC-ready alerts** structured for SIEM ingestion
- **Auto-quarantine** preserves evidence for forensic review

The most important lesson: a card number in the wrong hands takes **seconds to copy and paste**. The DLP system's job is to make that window **zero seconds**.

---

*Diaa El-deen · CyberGuard X · June 2026*
