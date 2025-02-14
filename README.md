# Reconova - Subdomain Enumeration Tool

A **powerful and easy-to-use** subdomain enumeration tool built in Python.

## Features
- **Passive Subdomain Enumeration**
- **Brute-force Subdomain Discovery**
- **Automatically Starts in a New Terminal**
- **Shows HTTP Status Codes (e.g., `200 OK`, `300 Redirect`)**
- **Stylized ASCII Banner for Tool Name**

## Installation

```bash
sudo apt update && sudo apt upgrade -y
git clone https://github.com/rohith-abr/reconova.git
cd reconova
pip3 install -r requirements.txt
python3 reconova.py
```

## Usage

Run the tool:

```bash
python3 reconova.py
```

Enter the domain when prompted.

To save results to a file:

```bash
python3 reconova.py targetwebsite.com -o results.txt
```
