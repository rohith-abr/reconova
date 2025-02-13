#!/usr/bin/env python3

import os
import argparse
import concurrent.futures
import requests
import re
from pyfiglet import figlet_format

# ANSI Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

# Regex for validating domain names
DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

### 🔹 Validate a Subdomain ###
def is_valid_subdomain(subdomain, domain):
    """Checks if a subdomain is valid and belongs to the target domain."""
    return DOMAIN_REGEX.match(subdomain) and subdomain.endswith(domain)

### 🔹 Get Subdomains from Multiple APIs ###
def fetch_subdomains(domain):
    """Fetch subdomains from various APIs for comprehensive results."""
    print(f"{YELLOW}[+] Gathering subdomains for {domain}...{RESET}")
    
    subdomains = set()

    api_sources = [
        ("Bufferover", f"https://dns.bufferover.run/dns?q={domain}"),
        ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={domain}"),
        ("RapidDNS", f"https://rapiddns.io/subdomain/{domain}?full=1"),
        ("AlienVault", f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
    ]

    headers = {"User-Agent": "Mozilla/5.0"}

    for source, url in api_sources:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200 and "API count exceeded" not in response.text:
                if source == "Bufferover":
                    for entry in response.json().get("FDNS_A", []):
                        sub = entry.split(",")[1].strip().lower()
                        if is_valid_subdomain(sub, domain):
                            subdomains.add(sub)
                elif source == "HackerTarget":
                    for line in response.text.split("\n"):
                        sub = line.split(",")[0].strip().lower()
                        if is_valid_subdomain(sub, domain):
                            subdomains.add(sub)
                elif source == "RapidDNS":
                    for line in response.text.split("\n"):
                        if domain in line:
                            sub = line.strip().split(",")[0].lower()
                            if is_valid_subdomain(sub, domain):
                                subdomains.add(sub)
                elif source == "AlienVault":
                    for record in response.json().get("passive_dns", []):
                        sub = record.get("hostname", "").strip().lower()
                        if is_valid_subdomain(sub, domain):
                            subdomains.add(sub)
            else:
                print(f"{CYAN}[!] {source} API Error: {response.status_code}{RESET}")
        except requests.RequestException:
            pass  

    if not subdomains:
        print(f"{RED}[!] No subdomains found. Try again later.{RESET}")
        exit(1)

    unique_subdomains = sorted(subdomains)  
    print(f"{GREEN}[✓] Found {len(unique_subdomains)} unique subdomains.{RESET}")
    return unique_subdomains

### 🔹 Improved HTTP Status Code Checker ###
def check_http_status(subdomain):
    """Fetch HTTP status codes accurately using HEAD and GET requests."""
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        # Try HEAD request first
        response = requests.head(f"https://{subdomain}", headers=headers, timeout=5, allow_redirects=True)
        
        # If HEAD request fails or returns an error, try GET request
        if response.status_code in [405, 403, 400] or response.status_code >= 500:
            response = requests.get(f"https://{subdomain}", headers=headers, timeout=10, allow_redirects=True)

        # Follow all redirects
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

    subdomains = fetch_subdomains(domain)

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
