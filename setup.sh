#!/bin/bash
echo -e "\e[34m🛠️  RedShadow V2 - Initial Setup\e[0m"

# Exit on any error
set -e

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo -e "\e[31m[!] Python3 is not installed. Install it and try again.\e[0m"
    exit 1
fi

# Check for pip
if ! command -v pip &> /dev/null; then
    echo -e "\e[31m[!] pip is not installed. Try: sudo apt install python3-pip\e[0m"
    exit 1
fi

# Create virtual environment if missing
if [ ! -d "venv" ]; then
    echo -e "\e[33m[+] Creating Python virtual environment...\e[0m"
    python3 -m venv venv
else
    echo -e "\e[32m[✓] Virtual environment already exists.\e[0m"
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
echo -e "\e[33m[+] Upgrading pip...\e[0m"
pip install --upgrade pip

# Install Python dependencies
echo -e "\e[33m[+] Installing Python packages from requirements.txt...\e[0m"
pip install -r requirements.txt

# Check for Nmap
if ! command -v nmap &> /dev/null; then
    echo -e "\e[33m[+] Installing Nmap...\e[0m"
    sudo apt update
    sudo apt install -y nmap
else
    echo -e "\e[32m[✓] Nmap is already installed.\e[0m"
fi

# Create outputs directory
if [ ! -d "outputs" ]; then
    echo -e "\e[33m[+] Creating outputs/ directory...\e[0m"
    mkdir -p outputs
else
    echo -e "\e[32m[✓] outputs/ directory already exists.\e[0m"
fi

# Verify key modules exist
echo -e "\e[33m[+] Checking module files...\e[0m"
MODULES=("modules/pipeline.py" "modules/bruteforce.py" "modules/domain.py" "modules/passive.py" "modules/scan.py" "modules/analyse.py" "modules/report.py" "modules/utils.py")
ALL_OK=true
for module in "${MODULES[@]}"; do
    if [ ! -f "$module" ]; then
        echo -e "\e[31m[!] Missing: $module\e[0m"
        ALL_OK=false
    else
        echo -e "\e[32m[✓] Found: $module\e[0m"
    fi
done

if [ "$ALL_OK" = false ]; then
    echo -e "\e[31m[!] One or more module files are missing. Please check your installation.\e[0m"
    exit 1
fi

# Verify data directory
if [ ! -f "data/cve_map.json" ]; then
    echo -e "\e[31m[!] Missing: data/cve_map.json — CVE analysis will not work.\e[0m"
else
    echo -e "\e[32m[✓] CVE map found.\e[0m"
fi

echo
echo -e "\e[32m╔══════════════════════════════════════════╗\e[0m"
echo -e "\e[32m║        ✅  Setup Complete — V2           ║\e[0m"
echo -e "\e[32m╚══════════════════════════════════════════╝\e[0m"
echo
echo -e "\e[34m👉 Quick start:\e[0m"
echo -e "\e[36m   sudo venv/bin/python3 main.py auto --target hackerone.com\e[0m"
echo
echo -e "\e[34m👉 Manual mode:\e[0m"
echo -e "\e[36m   source venv/bin/activate\e[0m"
echo -e "\e[36m   python3 main.py --help\e[0m"
echo
echo -e "\e[33m⚠️  Use responsibly. Only scan targets you have permission to test.\e[0m"