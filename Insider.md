# CyberDefenders: Insider — Linux Disk Forensics Writeup

* **Category:** Endpoint Forensics & Linux Disk Analysis
* **Primary Tools:** Autopsy, FTK Imager, Sleuth Kit (`fls`, `icat`), grep / bash utilities
* **Primary Artifact:** Raw Linux Disk Image / File System Image (`.dd` / `.img` / `.raw`)

---

## 1. Scenario Overview
An internal corporate Linux workstation was flagged for suspected data exfiltration and intellectual property theft by an insider threat. The objective of this investigation is to mount and analyze the raw Linux disk image, evaluate user authentication and shell histories, reconstruct file system timelines, locate staged data, and trace network/exfiltration mechanisms.

---

## 2. Investigation Steps

### Step 1: Disk Ingestion & File System Mounting
The raw disk image was inspected and mounted read-only to preserve evidentiary integrity:
```bash
# Identify partitions and sector offsets
fdisk -l insider.img

# Calculate sector offset (e.g., sector size 512 * start sector)
mkdir -p /mnt/evidence
mount -o ro,loop,offset=$((START_SECTOR * 512)) insider.img /mnt/evidence
```
Alternatively, Sleuth Kit utilities and Autopsy were utilized to index the file system structure without altering access/inode metadata.

### Step 2: User Account & Authentication Log Triage
Triaged system authentication databases and service logs to identify active user sessions:
* **Account Enumeration:** Inspected `/etc/passwd`, `/etc/shadow`, and `/etc/group` to enumerate created users, administrative (`sudo`) group memberships, and home directory assignments.
* **Authentication Auditing:**
  * Triaged `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/CentOS) for login sessions, session opens/closes (`pam_unix`), and privilege escalation commands:
    ```bash
    grep "sudo:" /mnt/evidence/var/log/auth.log
    ```
* **Interactive Logins:** Parsed binary accounting files `/var/log/wtmp` and `/var/log/btmp` using `last -f` to corroborate login timestamps, session durations, and pseudo-terminal (`pts`) allocations.

### Step 3: Shell History & Command Execution Analysis
Triaged hidden dotfiles across all enumerated home directories (`/home/<user>/` and `/root/`):
* **Bash & Shell Histories:** Extracted `.bash_history`, `.zsh_history`, and `.bashrc` modifications:
  ```bash
  cat /mnt/evidence/home/<suspect>/.bash_history
  ```
* **Command Sequence Identification:** 
  * Reconstructed the sequence of interactive commands run by the user, uncovering directory reconnaissance, archive creation commands (`tar -czvf`, `zip`), and search commands targeting sensitive documents (`find`, `grep`).
  * Identified usage of external file transfer utilities, such as `scp`, `rsync`, `curl`, `wget`, or netcat (`nc`).

### Step 4: Staged Files, Deleted Inodes & Exfiltration Tracking
Investigated file system activity and residual artifacts:
* **File System Timeline:** Used `fls` and `mactime` from The Sleuth Kit to build a body file of file system creation, modification, and access timestamps:
  ```bash
  fls -r -m / /mnt/evidence > body.txt
  mactime -b body.txt -d > timeline.csv
  ```
* **Carving Staged Archives:** Searched common staging areas (`/tmp`, `/var/tmp`, `/dev/shm`) for hidden or deleted archives containing exfiltrated source code and proprietary documents.
* **SSH & Remote Persistence:** 
  * Inspected `/home/<suspect>/.ssh/authorized_keys` and `/home/<suspect>/.ssh/known_hosts` to identify remote endpoints accessed by the employee and persistent public keys configured for back-channel access.

---

## 3. Key Findings
* **Target Account:** Identified the specific insider user account responsible for malicious staging and exfiltration.
* **Unauthorized Data Collection:** Shell history and file system timelines confirmed execution of automated archive tools targeting intellectual property.
* **Staging Locations:** Discovered staged `.tar.gz` / `.zip` archives concealed inside non-standard temporary directories (`/dev/shm` / `/tmp`).
* **Exfiltration Route:** Traced outbound network commands and external SSH keys linked to the transfer of proprietary data off-premises.
