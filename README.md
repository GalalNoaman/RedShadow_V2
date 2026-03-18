# 🕵️‍♂️ RedShadow V2 – Reconnaissance and CVE Analysis Tool

**RedShadow V2** is a red team automation tool for passive reconnaissance, DNS bruteforcing, port scanning, and CVE analysis. Built for bug bounty hunters and penetration testers, it fingerprints domains, detects technologies, maps them to known vulnerabilities, and generates professional reports — all from a single command.

> ⚠️ V2 focuses on reconnaissance and analysis only. No exploitation or payloads are included.

---

## 📦 Features

- ✅ **Auto pipeline** — one command runs the full recon chain end-to-end
- ✅ Subdomain enumeration via `crt.sh` (certificate transparency)
- ✅ DNS bruteforce with built-in wordlist + SecLists support
- ✅ Passive HTTP recon (headers, title, tech stack detection)
- ✅ Nmap-based port scanning with service/version detection
- ✅ CVE detection via service/version matching
- ✅ Markdown + **HTML report generation** (dark theme, CVSS colour-coded)

---

## 🛠️ Requirements

Install system dependencies:

```bash
sudo apt update
sudo apt install nmap python3-venv -y
```

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Or use the setup script:

```bash
chmod +x setup.sh
./setup.sh
```

---

## 🚀 Usage

### ⚡ Auto Mode (Recommended — runs everything automatically)

```bash
sudo venv/bin/python3 main.py auto --target hackerone.com
```

Optional flags:

```bash
--output-dir custom_folder        # Change output directory (default: outputs/)
--wordlist /path/to/wordlist.txt  # Use custom DNS wordlist (e.g. SecLists)
--no-bruteforce                   # Skip DNS bruteforce stage
--insecure                        # Disable TLS verification
--verbose                         # Show detailed error output
```

> ⚠️ `sudo` is required for Nmap SYN scanning (`-sS`). To run without sudo, change `nmap_args` in `config.yaml` from `-sS` to `-sT`.

---

### 🔧 Manual Mode (run stages individually)

#### 1. Subdomain Enumeration
```bash
python3 main.py domain --target hackerone.com --output outputs/subdomains.txt
```

#### 2. DNS Bruteforce
```bash
python3 main.py bruteforce --target hackerone.com --output outputs/subdomains.txt
```

#### 3. Passive Reconnaissance
```bash
python3 main.py passive --input outputs/subdomains.txt --output outputs/passive_results.json
```

#### 4. Port Scan
```bash
sudo venv/bin/python3 main.py scan --input outputs/subdomains.txt --output outputs/scan_results.json
```

#### 5. CVE Analysis
```bash
python3 main.py analyse --input outputs/scan_results.json --output outputs/analysis_results.json
```

#### 6. Generate Reports
```bash
python3 main.py report --input outputs/analysis_results.json --output outputs/redshadow_report.md --html outputs/redshadow_report.html
```

---

## 📁 Project Structure

```
RedShadow_V2/
├── .gitignore
├── LICENSE.txt
├── README.md
├── SECURITY.md
├── config.yaml
├── main.py
├── requirements.txt
├── setup.sh
├── data/
│   └── cve_map.json
├── modules/
│   ├── __init__.py
│   ├── analyse.py
│   ├── bruteforce.py       ← NEW in V2
│   ├── domain.py
│   ├── passive.py
│   ├── pipeline.py         ← NEW in V2
│   ├── report.py
│   ├── scan.py
│   └── utils.py
├── outputs/
│   ├── subdomains.txt
│   ├── passive_results.json
│   ├── scan_results.json
│   ├── analysis_results.json
│   ├── redshadow_report.md
│   └── redshadow_report.html   ← NEW in V2
└── venv/
```

---

## 🧠 Notes

- Passive-only recon — no exploitation, no shell generation, no payloads
- Uses DNS resolution via Google (8.8.8.8), Cloudflare (1.1.1.1), and Quad9 (9.9.9.9)
- Designed for authorised bug bounty targets and legal penetration testing only
- Auto pipeline skips failed stages rather than crashing — resilient by design
- HTML report opens directly in any browser — dark themed, CVSS colour-coded

---

## 🗺️ Roadmap

- [ ] Live CVE lookup via NVD API (replacing static cve_map.json)
- [ ] Nuclei-style active HTTP vulnerability probing
- [ ] Shodan/Censys API integration
- [ ] HTML report improvements (charts, filtering)
- [ ] Exploitation verification module (V3)

---

## 📌 License

Copyright © 2026 Galal Noaman. All rights reserved.

This project is for educational and non-commercial use only. You are not permitted to use, modify, rebrand, resell, or redistribute any part of this project without written permission. See `LICENSE.txt` for full terms.

Contact: Jalalnoaman@gmail.com