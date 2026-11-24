# OSINT-DFIR-BRAHMASTRA

**OSINT-DFIR-BRAHMASTRA** is a modular Python framework for Digital Forensics (DFIR) and Open-Source Intelligence (OSINT) automation. It combines file artifact extraction, domain reconnaissance, identity OSINT (phone, email, username), an **Autonomous Gemini AI Pivot Brain**, and **Mini-Maltego Visual Link Analysis** into one SQLite-backed CLI tool.

It is built for easy development on **Windows** and smooth deployment on **Kali Linux**.

---

## Key Features

* **Phase 1 — DFIR Artifact Extractor:** Calculates MD5/SHA-256 hashes, extracts file metadata using ExifTool, and scans for leaked secrets, C2 tokens, and IOCs.
* **Phase 2 — Domain Reconnaissance:** Automates WHOIS, DNS records, `crt.sh` subdomain enumeration, VirusTotal checks, and Hunter.io corporate email discovery.
* **Phase 3 — Deep Identity OSINT:**
  * **Phone OSINT:** Offline and live telecom carrier lookup, VoIP/burner detection, timezone, WhatsApp/Telegram links, and Google Dorks.
  * **Email OSINT:** Disposable/MX checks, free data breach lookup (XposedOrNot), Gravatar profile recon, GitHub commit reverse-search, and Holehe registration scans.
  * **Username OSINT:** Fast multi-threaded scan across 18+ platforms, GitHub `.patch` hidden email/timezone carving, and optional Sherlock integration.
* **AI Phase — Autonomous AI Pivot Brain (Gemini):** Reads your SQLite case database, filters out noise, and automatically pivots to high-value domains, emails, usernames, and phone numbers up to 3 levels deep.
* **Phase 4 — Visual Graph & Court-Ready Reporting:** Generates an interactive dark-mode **Mini-Maltego HTML Graph** (`NetworkX` + `PyVis`) and a standalone **Forensic HTML Report** (with Print / Save-as-PDF support and full Chain of Custody audit logs).

---

## Requirements

### System Requirements
* **Python 3.10+**
* **Git**
* **ExifTool** (required for Phase 1 file metadata extraction)
  * Kali Linux: `sudo apt install libimage-exiftool-perl`

### Python Libraries
Installed automatically via `requirements.txt`:
* `typer`, `rich`, `pyyaml`, `requests`, `dnspython`, `python-whois`, `phonenumbers`, `google-genai`, `networkx`, `pyvis`

### Optional CLI Tools (for deeper OSINT on Kali Linux)
* **Holehe** (100+ site email registration check): `pip install holehe`
* **Sherlock** (300+ site username check): `sudo apt install sherlock`

### API Keys (Free Tiers Supported)
* **Google Gemini API** *(Required for `autopivot`)*
* **VirusTotal API** *(Optional — Domain reputation)*
* **Hunter.io API** *(Optional — Corporate emails)*
* **GitHub Personal Access Token** *(Optional — Higher rate limits)*
* **NumVerify API** *(Optional — Live phone carrier lookup)*

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/patharankit12-star/OSINT-DFIR-BRAHMASTRA.git](https://github.com/patharankit12-star/OSINT-DFIR-BRAHMASTRA.git)
cd OSINT-DFIR-BRAHMASTRA
```

### 2. Create a Virtual Environment & Install Dependencies

**On Kali Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 3. Configure API Keys
Create a `config.yaml` file in the project root folder (this file is git-ignored to keep your keys safe):

```yaml
api_keys:
  gemini: "YOUR_GEMINI_API_KEY"
  virustotal: "YOUR_VIRUSTOTAL_API_KEY"
  hunter_io: "YOUR_HUNTER_API_KEY"
  github: "YOUR_GITHUB_TOKEN"
  numverify: "YOUR_NUMVERIFY_API_KEY"
```

---

## How to Use (Command Reference)

> **Tip:** Use the **same `-c <case_name>`** across different commands to store all findings in one SQLite database (`cases/<case_name>.db`) and connect everything in one master graph. Use a **new `-c <case_name>`** if you want a separate investigation.

### Phase 1: DFIR File Analysis
Extract hashes, metadata, secrets, and IOCs from a suspicious file:
```bash
python3 main.py analyze -c <case_name> -f <file_path>
```
*Example:*
```bash
python3 main.py analyze -c case_01 -f suspicious_dropper.py
```

### Phase 2: Domain Reconnaissance
Run WHOIS, DNS, `crt.sh`, VirusTotal, and Hunter.io on a root domain *(always use the main domain, not a subdomain)*:
```bash
python3 main.py recon -c <case_name> -t <domain_name>
```
*Example:*
```bash
python3 main.py recon -c case_01 -t example.com
```

### Phase 3: Identity OSINT (Phone, Email, Username)

**3.1 Mobile Number OSINT** *(include country code for international numbers)*:
```bash
python3 main.py phone -c <case_name> -p "<+countrycode_number>"
```
*Example:*
```bash
python3 main.py phone -c case_01 -p "+919876543210"
```

**3.2 Email OSINT** *(Breaches, Gravatar, MX, GitHub, Holehe)*:
```bash
python3 main.py email -c <case_name> -e "<email_address>"
```
*Example:*
```bash
python3 main.py email -c case_01 -e "target@example.com"
```

**3.3 Username OSINT** *(18+ Platforms, GitHub `.patch` carving, Sherlock)*:
```bash
python3 main.py username -c <case_name> -u "<username>"
```
*Example:*
```bash
python3 main.py username -c case_01 -u "torvalds"
```

### AI Phase: Autonomous AI Auto-Pivot
Let the Gemini AI Brain analyze all collected evidence in your case database and automatically pivot to new targets (`--depth` can be `1`, `2`, or `3`):
```bash
python3 main.py autopivot -c <case_name> --depth 2
```

### Phase 4: Visual Graph & Forensic Report
Generate the interactive Mini-Maltego HTML graph and the court-ready HTML forensic report:
```bash
python3 main.py report -c <case_name>
```

**Open the Report in Your Browser (Kali Linux):**
```bash
xdg-open reports/<case_name>_report.html
```
*(Inside the report, click **"Open Interactive Graph"** to view the Mini-Maltego network graph, or **"Print / Save as PDF"** to export a clean white-background PDF).*

### Utility Command: List All Saved Cases
```bash
python3 main.py list-cases
```

---

## Project Structure

```text
OSINT-DFIR-BRAHMASTRA/
├── main.py                     # CLI entry point (Typer + Rich)
├── config.yaml                 # Local API keys (git-ignored)
├── requirements.txt            # Python dependencies
├── core/
│   ├── config.py               # Config loader
│   ├── database.py             # SQLite Case DB & Chain of Custody
│   ├── ai_brain.py             # Gemini Autonomous Pivot Engine
│   └── orchestrator.py         # Module routing & pivot loop
├── modules/
│   ├── dfir_extractor.py       # Phase 1: Hashes, ExifTool, Secrets, IOCs
│   ├── domain_recon.py         # Phase 2: WHOIS, DNS, crt.sh, VT, Hunter
│   ├── phone_osint.py          # Phase 3A: Phone & VoIP Intelligence
│   ├── email_osint.py          # Phase 3B: Email, Breaches, Gravatar, Holehe
│   ├── username_osint.py       # Phase 3C: Multi-platform & GitHub .patch
│   ├── graph_builder.py        # Phase 4A: NetworkX + PyVis HTML Graph
│   └── report_generator.py     # Phase 4B: Court-Ready HTML/PDF Report
├── cases/                      # Generated SQLite databases (git-ignored)
└── reports/                    # Generated HTML graphs & reports (git-ignored)
```

---

## Legal Disclaimer

This tool is built strictly for **educational purposes, defensive cybersecurity, authorized digital forensics (DFIR), and ethical OSINT investigations**. Only run this framework against files, domains, and targets you own or have explicit permission to investigate. The author is not responsible for any misuse.