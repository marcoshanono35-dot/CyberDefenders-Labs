# CyberDefenders: The Crime — Mobile Forensics (ALEAPP) Writeup

* **Category:** Mobile Artifact Forensics & Android Analysis
* **Primary Tools:** ALEAPP (Android Logs Events And Protobuf Parser), DB Browser for SQLite, FTK Imager
* **Primary Artifact:** Android Physical / Logical Triage Extraction (`tar` / filesystem dump)

---

## 1. Scenario Overview
A mobile device was seized in connection with a suspected criminal investigation. The objective is to perform comprehensive mobile artifact triage on the Android file system extraction using **ALEAPP**, parse proprietary application databases, trace physical/network location history, reconstruct communications, and establish a timeline of suspect activity.

---

## 2. Investigation Steps

### Step 1: Evidence Ingestion & Parsing via ALEAPP
The extracted Android filesystem directory structure was ingested into ALEAPP:
```bash
python aleapp.py -t tar -i /path/to/android_dump.tar -o /path/to/aleapp_output/
```
* **Artifact Target Areas:** ALEAPP systematically processed:
  * Application databases (`/data/data/`)
  * Device usage history and usage stats (`/data/system/usagestats/`)
  * Telephony, messaging, and account profiles (`telephony.registry`, `accounts.db`)
  * Geolocation caches and Wi-Fi profiles (`com.google.android.gms`)
* **HTML Report Triage:** Reviewed the indexed ALEAPP HTML dashboard to prioritize key categories: *Device Info*, *Installed Applications*, *SMS/MMS*, *Call Logs*, *Chrome Web History*, and *App Interaction*.

### Step 2: Communication & Messaging Artifact Reversal
Examined internal SQLite databases for native and third-party messaging:
* **SMS/MMS Databases:** Triaged `/data/user_de/0/com.android.providers.telephony/databases/mmssms.db`:
  * Parsed the `sms` and `pdu` tables to extract outgoing and incoming text messages, associated timestamps (UTC epoch ms), thread IDs, and recipient phone numbers.
* **Call Logs:** Inspected `/data/data/com.android.providers.contacts/databases/calllog.db` to reconstruct incoming, outgoing, and missed call timelines, including call durations and caller identity markers.
* **Third-Party Messaging (WhatsApp / Telegram / Signal):** Located encrypted/unencrypted application databases under `/data/data/<package_name>/databases/`, querying chat tables (`messages`, `chat_list`) to recover uncommitted or staged communication records.

### Step 3: Web Browsing & Media Artifact Triage
Triaged user web activities and multimedia metadata:
* **Chrome Browsing Activity:** Analyzed `/data/data/com.android.chrome/app_chrome/Default/History`:
  * Queried the `urls` and `visits` tables to identify search queries related to the incident, visited URLs, page titles, and transition types.
* **Media & Camera Artifacts:** 
  * Extracted camera metadata from `/DCIM/Camera/` and analyzed EXIF tags within recovered `.jpg` / `.mp4` files using `exiftool`.
  * Recovered embedded GPS coordinates (Latitude, Longitude), camera model, and original hardware capture timestamps.

### Step 4: Geolocation & Wireless Network Mapping
Reconstructed the device’s physical presence around critical incident timestamps:
* **Wi-Fi Profiles:** Extracted configured access points from `/data/misc/wifi/WifiConfigStore.xml` to isolate connected SSIDs, BSSIDs, and pre-shared keys.
* **Cell Tower & Geolocation Caches:** Evaluated Google location caches and cell tower triangulation artifacts extracted by ALEAPP to correlate physical location data with communication events.

---

## 3. Key Findings
* **Device Identification:** Extracted IMEI, Android OS version, device model, and associated Google accounts.
* **Communication Timeline:** Reconstructed communications detailing criminal coordination and contact identities.
* **Location Correlation:** EXIF metadata and Wi-Fi connection histories mapped the suspect device directly to key physical locations during the incident window.
* **Forensic Value:** ALEAPP automated the parsing of complex Android protobufs and SQLite databases, enabling rapid evidence timeline building.
