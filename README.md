# 🛡️ KernelModulesScanner.ps1  
**Advanced Windows Kernel Driver Scanner**

> Made by **NACIO** | Discord: [discord.gg/pcchecking](https://discord.gg/pcchecking)  
> Requires: **Run as Administrator**


## 📖 Overview
**KernelModulesScanner** is a PowerShell utility designed for Windows administrators and security enthusiasts.  
It performs a full scan of `.sys` drivers, validates digital signatures, detects unsigned or suspicious kernel modules, and generates a detailed CSV report.

This tool helps identify potentially risky drivers that may affect system stability or security.


## ⚙️ Features

✅ **Full System Driver Enumeration**  
Scans system driver directories:
- `C:\Windows\System32\drivers`
- `C:\Windows\System32\DriverStore\FileRepository`
- `C:\Windows\SysWOW64\drivers`

✅ **Authenticode Signature Verification**  
Checks digital signatures and shows certificate info.

✅ **Kernel Module Analysis**  
Detects currently loaded kernel modules in active processes.

✅ **Heuristic Risk Assessment**  
Flags drivers as **Low**, **Medium**, or **High Risk** based on:
- Missing/invalid signature  
- Suspicious file paths (Temp / AppData)  
- Missing company or description info  

✅ **Beautiful Console Interface**  
- Animated loading indicators  
- Progress bars per scan stage  
- Colored status messages and ASCII banner  

✅ **CSV Report Output**  
Exports results automatically to a timestamped `.csv` file.


## 🧩 Example Usage

### ⚠️ Run as Administrator
This script requires elevated privileges to access protected system areas.

#### Simple Launcher (Direct Download)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/Nacio78923/Kernel-Scanner/refs/heads/main/Nacio%20Kernel%20Scanner.ps1')

Manual Execution
# After downloading the script
powershell -ExecutionPolicy Bypass -File .\Nacio Kernel Scanner.ps1


# With optional parameters
.\KernelModulesScanner.ps1 -OutputPath "C:\Reports\KernelScan.csv" -DeepScan
📊 Output Example

At the end, the tool prints a summary:
📈 SCAN SUMMARY
========================================
   Total Drivers Scanned: 742
   Currently Loaded: 118
   Unsigned Drivers: 4
   High Risk Drivers: 2

⚠️  WARNING: High risk drivers detected!
   • testdriver.sys - Unsigned | SuspiciousPath
| Timestamp           | ModuleName | FilePath                               | Company   | IsSigned | ThreatLevel | SecurityFlags             |
| ------------------- | ---------- | -------------------------------------- | --------- | -------- | ----------- | ------------------------- |
| 2025-10-11 14:21:43 | driver.sys | C:\Windows\System32\drivers\driver.sys | Microsoft | True     | Low         |                           |
| 2025-10-11 14:22:11 | bad.sys    | C:\Users\User\AppData\Temp\bad.sys     | Unknown   | False    | High        | Unsigned | SuspiciousPath |


🧠 Technical Notes

Pure PowerShell implementation — no external dependencies.

Uses Get-AuthenticodeSignature for signature verification.

Outputs structured data as PowerShell objects and CSV.

Safe, read-only inspection — does not modify the system.

💡 Recommended Use

Ideal for:

Malware analysts and DFIR specialists

IT administrators auditing driver integrity

Windows security researchers

Incident response investigations
📦 Example Output File
KernelScan_20251011_142143.csv
🧾 License

Educational and diagnostic use only.
Do not use for unauthorized system analysis or malicious activity.

© 2025 NACIO — All rights reserved.
