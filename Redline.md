# CyberDefenders: Redline — Memory Forensics & Endpoint Triage Writeup

* **Category:** Memory Forensics & Endpoint Incident Response
* **Primary Tools:** Volatility 3 / Volatility 2, Mandiant Redline, Strings, FTK Imager
* **Primary Artifact:** Raw Memory Image (`.raw` / `.dmp` / `.vmem`) & Redline Analysis Session

---

## 1. Scenario Overview
An endpoint detection system raised high-priority alerts regarding unauthorized code execution, potential process tampering, and anomalous outbound network activity. The objective of this investigation is to perform deep-dive memory forensics alongside Mandiant Redline analysis to reconstruct process hierarchies, identify injected memory regions, detect persistence, and extract adversary indicators of compromise (IOCs).

---

## 2. Investigation Steps

### Step 1: Memory Image Ingestion & Process Lineage Triage
Volatility was initialized against the memory image to enumerate running processes and evaluate parent-child relationships:
```bash
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
```
* **Process Anomalies:** Inspected parent process IDs (PPIDs), session IDs, and command-line arguments. Flagged instances of system binaries executing out of uncharacteristic directories (e.g., `svchost.exe` running outside `C:\Windows\System32\` or without `-k` parameters).
* **Cross-Validation with Redline:** Imported the triage package/memory dump into Mandiant Redline:
  * Leveraged Redline's **Processes** tab to sort binaries by their **Malware Risk Index (MRI)** score.
  * Correlated unsigned binaries, mismatched digital signatures, and processes spawned without valid parent processes.

### Step 2: Injected Code & Memory Protection Violations
To isolate memory-injection techniques (such as DLL injection, process hollowing, or reflective loader activity), Volatility's memory-scanning plugins were deployed:
```bash
vol -f memory.raw windows.malfind
```
* **Memory Protection Flags:** Located memory segments configured with `PAGE_EXECUTE_READWRITE` (`0x40`) or `PAGE_EXECUTE_READ` (`0x20`) permissions that were not mapped to any known executable image or library on disk.
* **Header Inspection:** Discovered unbacked Virtual Address Descriptors (VAD) containing standard portable executable magic bytes (`MZ` / `0x5A4D`) and PE header structures.
* **Process Memory Dumping:** Extracted the suspicious injected regions and associated process memory:
```bash
vol -f memory.raw -o output/ windows.dumpfiles --pid <Target_PID>
vol -f memory.raw -o output/ windows.memmap --dump --pid <Target_PID>
```

### Step 3: Network Telemetry & Socket Analysis
Active and terminated network sockets were correlated with suspect process identifiers:
```bash
vol -f memory.raw windows.netscan
```
* **Network Sockets:** Mapped the rogue process ID to active `ESTABLISHED` or `SYN_SENT` TCP/UDP sockets.
* **C2 Identification:** Extracted remote IP addresses, outbound destination ports, and socket creation timestamps to establish the adversary's Command-and-Control infrastructure.
* **Redline Ports Verification:** Cross-referenced network connection findings within Redline's **Ports** view to confirm open listener sockets and historical endpoint associations.

### Step 4: Handles, Mutexes, and In-Memory Artifacts
To uniquely fingerprint the malware family and its operational footprint:
* **Handle Inspection:**
  ```bash
  vol -f memory.raw windows.handles --pid <Target_PID>
  ```
* **Mutex Discovery:** Extracted created synchronization mutexes used by the malware to ensure single-instance execution.
* **In-Memory Strings & Decryption:** Ran string analysis against the extracted process dump:
  ```bash
  strings -a -n 6 output/pid.<Target_PID>.dmp | grep -Ei 'http|c2|beacon|user-agent|cmd|powershell'
  ```
  * Uncovered hardcoded C2 URI paths, custom User-Agent strings, and staged command-line instructions.

---

## 3. Key Findings
* **Initial Detection:** Mandiant Redline's MRI scoring flagged an unauthorized process executing out of user-writable space.
* **Injection Mechanism:** Volatility `malfind` validated reflective memory injection / process hollowing into a legitimate Windows process context.
* **Command & Control:** Isolated active C2 callback channels and beaconing network sockets.
* **Forensic Synergy:** Combined high-level host triage scoring from Redline with byte-level forensic verification in Volatility.
  
