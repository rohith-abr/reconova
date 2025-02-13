#!/usr/bin/env python3

import os
import argparse
import concurrent.futures
import requests
import subprocess
from pyfiglet import figlet_format
import re

# ANSI Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Regular Expression to Validate Domain Names
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

### 🔹 Check if Subfinder is Installed ###
def is_subfinder_installed():
    """Check if Subfinder is installed."""
    try:
        subprocess.run(["subfinder", "-h"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        return True  # Subfinder is installed
    except FileNotFoundError:
        return False  # Subfinder is NOT installed

### 🔹 Fetch Subdomains from APIs (if Subfinder is missing) ###
def fetch_certspotter_subdomains(domain):
    """Fetch subdomains from CertSpotter API."""
    url = f"https://certspotter.com/api/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data:
                for sub in entry.get("dns_names", []):
                    if DOMAIN_REGEX.match(sub.strip().lower()):
                        subdomains.add(sub.strip().lower())
    except requests.RequestException:
        pass  
    return subdomains

def fetch_bufferover_subdomains(domain):
    """Fetch subdomains from Bufferover API."""
    url = f"https://dns.bufferover.run/dns?q={domain}"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data.get("FDNS_A", []):
                sub = entry.split(",")[1].strip().lower()
                if DOMAIN_REGEX.match(sub):
                    subdomains.add(sub)
    except requests.RequestException:
        pass  
    return subdomains

def fetch_hackertarget_subdomains(domain):
    """Fetch subdomains from HackerTarget API."""
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            for line in response.text.split("\n"):
                sub = line.split(",")[0].strip().lower()
                if DOMAIN_REGEX.match(sub):
                    subdomains.add(sub)
    except requests.RequestException:
        pass  
    return subdomains

def fetch_rapiddns_subdomains(domain):
    """Fetch subdomains from RapidDNS API."""
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            for line in response.text.split("\n"):
                if domain in line:
                    subdomains.add(line.strip().split(",")[0].lower())
    except requests.RequestException:
        pass  
    return subdomains

def fetch_alienvault_subdomains(domain):
    """Fetch subdomains from AlienVault API."""
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for record in json_data.get("passive_dns", []):
                sub = record.get("hostname", "").strip().lower()
                if DOMAIN_REGEX.match(sub):
                    subdomains.add(sub)
    except requests.RequestException:
        pass  
    return subdomains

### 🔹 Get Subdomains Using Subfinder or API Replication ###
def get_subdomains(domain):
    """Uses Subfinder if available, otherwise replicates Subfinder using APIs."""
    print(f"{YELLOW}[+] Gathering subdomains for {domain}...{RESET}")

    subdomains = set()

    if is_subfinder_installed():
        try:
            output = subprocess.run(
                ["subfinder", "-d", domain],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )
            subdomains.update(output.stdout.strip().split("\n"))
        except FileNotFoundError:
            pass  

    # If Subfinder is missing or didn't return subdomains, use APIs to replicate its functionality
    if not subdomains:
        subdomains.update(fetch_certspotter_subdomains(domain))
        subdomains.update(fetch_bufferover_subdomains(domain))
        subdomains.update(fetch_hackertarget_subdomains(domain))
        subdomains.update(fetch_rapiddns_subdomains(domain))
        subdomains.update(fetch_alienvault_subdomains(domain))

    if not subdomains:
        print(f"{RED}[!] No subdomains found. Try again later.{RESET}")
        exit(1)

    unique_subdomains = sorted(set(subdomains))  
    print(f"{GREEN}[✓] Found {len(unique_subdomains)} unique subdomains.{RESET}")
    return unique_subdomains

### 🔹 Check HTTP Status Codes ###
def check_http_status(subdomain):
    """Check HTTP status code for each subdomain."""
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(f"https://{subdomain}", headers=headers, timeout=10, allow_redirects=True)
        status_chain = " → ".join([str(r.status_code) for r in response.history] + [str(response.status_code)])
        return subdomain, status_chain
    except requests.Timeout:
        return subdomain, "408 Timeout"
    except requests.ConnectionError:
        return subdomain, "503 Service Unavailable"
    except requests.RequestException:
        return subdomain, "000 Unknown Error"

### 🔹 Run Full Scan ###
def enumerate_subdomains(domain, output_file):
    """Run full subdomain enumeration + HTTP status scan."""
    print(f"\n{YELLOW}[+] Started Reconova...{RESET}\n")

    subdomains = get_subdomains(domain)

    print(f"\n{YELLOW}[+] Checking HTTP status codes...\n{RESET}")
    results_dict = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        for subdomain, status in executor.map(check_http_status, subdomains):
            results_dict[subdomain] = status

    sorted_results = sorted(results_dict.items())

    if output_file:
        with open(output_file, "w") as f:
            for subdomain, status in sorted_results:
                f.write(f"{subdomain} | {status}\n")

    for subdomain, status in sorted_results:
        print(f"{subdomain} | {status}")

### 🔹 Main Execution ###
if __name__ == "__main__":
    os.system("clear")

    print(f"{CYAN}")
    print(figlet_format("RECONOVA", font="slant"))
    print(figlet_format("  ROHITH_ABR", font="slant"))
    print(f"{RESET}")

    parser = argparse.ArgumentParser(description="Reconova - Subdomain Enumeration & HTTP Status Tool")
    parser.add_argument("domain", nargs="?", help="Enter the domain name")
    parser.add_argument("-o", "--output", help="Output file to save results")

    args = parser.parse_args()

    if not args.domain:
        args.domain = input(f"{YELLOW}Enter the domain name: {RESET}")

    enumerate_subdomains(args.domain, args.output)
