# CyberDefenders: Ramnit — Digital Forensics & Memory Analysis Writeup

* **Category:** Endpoint Forensics & Memory Analysis
* **Primary Tools:** Volatility 3, FTK Imager, VirusTotal
* **Primary Artifact:** Raw Memory Image (`.raw` / `.vmem`)

---

## 1. Scenario Overview
An endpoint exhibited anomalous network connections, unexpected child process spawning, and degraded system responsiveness. The investigation focuses on triaging a raw memory dump to identify the initial compromise, isolate injected processes, uncover persistence mechanisms, and extract malware command-and-control (C2) indicators.

---

## 2. Investigation Steps

### Step 1: Memory Image Identification & Process Lineage Triage
Volatility 3 was used to inspect running processes and trace process ancestry:
```bash
vol -f memory.raw windows.pslist
vol -f memory.raw windows.pstree
```
* **Process Lineage Anomaly:** Evaluated parent-child relationships across standard Windows system binaries. Identified abnormal instances of `svchost.exe` and `explorer.exe` spawned with illegitimate Parent Process IDs (PPIDs) or running outside default directories (`C:\Windows\System32\`).
* **Rogue Processes:** Located unauthorized executables operating out of user directories (`AppData\Local\Temp` and `AppData\Roaming`).

### Step 2: Injected Code & Memory Artifact Extraction
To detect process hollowing and memory-injection techniques:
```bash
vol -f memory.raw windows.malfind
```
* **Memory Protection Violations:** `windows.malfind` identified memory regions configured with `PAGE_EXECUTE_READWRITE` (`0x40`) permissions containing standard PE file signatures (`MZ` header / `0x5A4D`) unbacked by a mapped binary on disk.
* **VAD Dump:** Dumped suspicious memory sections for offline inspection:
```bash
vol -f memory.raw -o output/ windows.dumpfiles --pid <Injected_PID>
```

### Step 3: Network Telemetry & C2 Socket Isolation
Active and terminated network sockets were correlated using:
```bash
vol -f memory.raw windows.netscan
```
* **Network IOCs:** Correlated the malicious PIDs against open sockets to isolate external IP addresses, remote ports, and connection states (e.g., `ESTABLISHED` connections to non-standard HTTP/HTTPS ports).

### Step 4: Host Persistence & Registry Analysis
Investigated registry persistence mechanisms used by the worm/trojan:
```bash
vol -f memory.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```
* **Persistence Mechanism:** Located auto-start entries pointing to staged payloads dropped in the victim profile, ensuring survival across reboots.

---

## 3. Key Findings
* **Malware Family:** Ramnit Banking Trojan / Worm.
* **Infiltration Behavior:** Injected malicious payloads directly into standard Windows processes (`svchost.exe`, `explorer.exe`) via process hollowing.
* **Network Indicators:** Isolated active remote C2 servers maintaining periodic beacon intervals.
