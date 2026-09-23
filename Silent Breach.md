# CyberDefenders: Silent Breach — Windows Disk Forensics Writeup

* **Category:** Endpoint Forensics & Disk Analysis
* **Primary Tools:** FTK Imager, Eric Zimmerman Tools (PECmd, MFTECmd, Registry Explorer), Event Log Explorer
* **Primary Artifact:** Raw Windows Disk Image (`.E01` / `.dd` / `.raw`)

---

## 1. Scenario Overview
An enterprise endpoint was suspected of being compromised, but traditional perimeter defenses failed to generate high-fidelity alerts. A full forensic disk image was acquired to determine the scope of the "silent breach." The investigation focuses on mounting the image, extracting critical triage artifacts, tracing malicious execution, and identifying persistence mechanisms.

---

## 2. Investigation Steps

### Step 1: Image Mounting & Artifact Extraction
The raw Windows disk image was loaded into **FTK Imager** to safely browse the file system and extract locked forensic artifacts without altering timestamps:
* **Artifact Target Areas:** Navigated the directory tree within FTK Imager and exported the following high-value artifacts for offline parsing:
  * Master File Table (`$MFT`) from the volume root.
  * System Registry Hives (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`) from `C:\Windows\System32\config\`.
  * User Registry Hives (`NTUSER.DAT`, `UsrClass.dat`) from user profiles.
  * Prefetch files from `C:\Windows\Prefetch\`.
  * Windows Event Logs (`.evtx`) from `C:\Windows\System32\winevt\Logs\`.

### Step 2: Program Execution & Malware Discovery
Triaged execution artifacts to identify rogue binaries, LOLBin abuse, and payload staging:
* **Prefetch Analysis:** Processed the exported `.pf` files using Zimmerman's `PECmd`:
  ```bash
  PECmd.exe -d "C:\extracted_artifacts\Prefetch" --csv "C:\analysis\prefetch_output"
  ```
  * Filtered the CSV output by execution time and run counts to identify unauthorized executables operating from temporary directories (`AppData\Local\Temp`, `C:\ProgramData`).
  * Mapped referenced directories and loaded DLLs inside the prefetch files to trace staged payload locations.
* **Amcache & Shimcache (AppCompatCache):** Parsed `Amcache.hve` and the `SYSTEM` hive to find evidence of executed binaries that may have been deleted by the attacker post-compromise, identifying the initial malware dropper footprint.

### Step 3: Persistence Identification & Registry Triage
Loaded the extracted registry hives into **Registry Explorer** to hunt for adversary footholds:
* **Auto-Start Execution Points (ASEPs):** 
  * Checked `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`.
  * Examined user-specific persistence in `NTUSER.DAT` (`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`).
* **Malicious Services:** Inspected the `SYSTEM\CurrentControlSet\Services` key for newly created, unsigned, or disguised services pointing to adversary executables.
* **Scheduled Tasks:** Extracted XML task definitions from `C:\Windows\System32\Tasks` to identify recurring beacons or payload executions configured to run under `SYSTEM` privileges.

### Step 4: Lateral Movement & Event Log Timeline
Correlated the disk execution artifacts with Windows Event Logs to establish an intrusion timeline:
* **Account Compromise:** Parsed `Security.evtx` for Logon Type 3 (Network) and Logon Type 10 (Remote Interactive) events (Event ID 4624) to track lateral movement and unauthorized remote access.
* **Service Creation:** Examined `System.evtx` for Event ID 7045 (A service was installed in the system) to cross-verify the persistence mechanisms found in the registry.
* **File System Timeline:** Used `MFTECmd` to parse the `$MFT` and construct a timeline of file creation events, establishing exactly when the initial dropper and subsequent tools were written to disk.

---

## 3. Key Findings
* **Initial Access & Execution:** Traced the initial compromise to a staged executable, confirmed by Prefetch artifacts and MFT file-creation timestamps.
* **Persistence Mechanism:** Discovered hidden registry Run keys and unauthorized scheduled tasks designed to maintain the adversary's backdoor across system reboots.
* **Defense Evasion:** Documented the attacker's use of native Windows utilities (Living off the Land) to move laterally and disguise malicious activity among normal administrative traffic.
* **Forensic Value:** Demonstrated the necessity of dead-box disk forensics (FTK Imager + Zimmerman tools) to uncover historical execution and registry tampering that evaded live endpoint detection.
