#!/bin/bash

echo -e "\033[92m[+] Installing Reconova...\033[0m"

# Ensure Python3 is installed
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 is not installed. Please install Python3 first."
    exit 1
fi

# Install required Python modules
pip3 install -r requirements.txt

# Make the script executable
chmod +x reconova.py

echo -e "\033[92m[✓] Installation complete! Run the tool using:\033[0m"
echo -e "\033[93mpython3 reconova.py\033[0m"
