# 🛡️ Malware Analysis Tool

A modular malware analysis pipeline built with Python. It supports static and dynamic analysis, YARA signature generation, STIX reporting, firewall rule creation, and a simple web UI for interactive use.

## 📁 Project Structure

```
├── dynamic_analyzer.py        # Simulates sandbox execution based on static indicators
├── file_input_validator.py    # Validates and logs metadata of the input file
├── firewall_generator.py      # Generates iptables firewall rules
├── main.py                    # Orchestrates the full analysis pipeline
├── report_generator.py        # Generates PDF and STIX reports
├── reverse_engineer.py        # Performs static analysis using r2pipe and pefile
├── signature_generator.py     # Generates YARA signatures
├── ui.py                      # Flask-based frontend for uploads and results
├── ui/
│   ├── templates/             # HTML templates (index.html, upload.html, results.html)
│   └── static/                # Static files (CSS, JS, assets)
├── requirements.txt           # Python dependencies
└── README.md                  # This file
```

## ⚙️ Features

- 🧬 **Static Analysis**: Uses `r2pipe` and `pefile` to extract imports, strings, hashes, and IOCs.
- 🧪 **Dynamic Simulation**: Simulates execution behavior based on static findings.
- 🔥 **Firewall Rules**: Generates iptables rules for blocking known IOCs.
- 🧾 **Reports**: Creates STIX 2.1 JSON and styled PDF reports using WeasyPrint.
- 🔍 **YARA Signatures**: Detects indicators like Gh0st RAT with robust rule generation.
- 🌐 **Web Interface**: Easy file upload and result visualization via Flask UI.

## 🧰 Prerequisites

- Python 3.8+
- Linux (tested on Kali and Ubuntu)
- `radare2` (for r2pipe)
- `libcairo`, `pango`, and other system packages for PDF rendering

Install system dependencies:

```bash
# For Debian/Ubuntu
sudo apt update
sudo apt install -y radare2 libmagic1 python3-pip \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libgdk-pixbuf2.0-0 libffi-dev shared-mime-info
```

## 📦 Installation

1. Clone or download the repo.

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

## 🚀 Usage

### 🔧 CLI

Run the full pipeline on a sample executable:

```bash
python3 main.py
```

By default, the tool expects the file to be placed at:

```
~/Desktop/Tool/input/sample.exe
```

### 🌐 Web Interface

Run the Flask server:

```bash
python3 ui.py
```

Visit: [http://localhost:5000](http://localhost:5000)  
Upload a `.exe` file to start analysis.

## 📤 Outputs

- `~/Desktop/Tool/output/`: Static and dynamic analysis JSON
- `~/Desktop/Tool/signatures/sample.yara`: YARA signature file
- `~/Desktop/Tool/firewall_rules/sample_firewall_rules.txt`: iptables rules
- `~/Desktop/Tool/reports/`: PDF and STIX report files
- `~/Desktop/Tool/logs/analysis_log.db`: Logs and metadata SQLite database

## 🛡️ Detection Capabilities

The tool detects suspicious behavior based on:

- Known strings (e.g., `Gh0st`, `CreateRemoteThread`, `keylogger`)
- Network activity (IPs, domains)
- File operations
- Registry access
- Packing (UPX entropy detection)

## 📖 Credits

- [Radare2](https://github.com/radareorg/radare2)
- [pefile](https://github.com/erocarrera/pefile)
- [WeasyPrint](https://weasyprint.org/)
- [STIX 2.1](https://oasis-open.github.io/cti-documentation/stix/intro)

## 📝 License

MIT License – Use freely with attribution.
