#!/usr/bin/env python3

import os
import argparse
import concurrent.futures
import requests
import socket
from pyfiglet import figlet_format

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
CYAN = "\033[96m"
RESET = "\033[0m"

def fetch_crtsh_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            json_data = response.json()
            for entry in json_data:
                subdomains.add(entry["name_value"].strip().lower())
    except requests.RequestException:
        pass
    return subdomains

def brute_force_subdomains(domain, wordlist="wordlists/common.txt"):
    subdomains = set()
    try:
        with open(wordlist, "r") as file:
            words = {line.strip().lower() for line in file if line.strip()}
        def resolve(sub):
            full_domain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(resolve, words)
            for result in results:
                if result:
                    subdomains.add(result)
    except FileNotFoundError:
        print(f"{RED}[!] Wordlist not found! Skipping brute-force.{RESET}")
    return subdomains

def get_subdomains(domain):
    print(f"{YELLOW}[+] Gathering subdomains for {domain}...{RESET}")
    crtsh_subdomains = fetch_crtsh_subdomains(domain)
    brute_force_results = brute_force_subdomains(domain)
    all_subdomains = sorted(set(crtsh_subdomains | brute_force_results))
    if not all_subdomains:
        print(f"{RED}[!] No subdomains found for {domain}. Exiting.{RESET}")
        exit(1)
    print(f"{GREEN}[✓] Found {len(all_subdomains)} subdomains.{RESET}")
    return all_subdomains

def check_http_status(subdomain):
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        response = requests.get(f"https://{subdomain}", headers=headers, timeout=10, allow_redirects=True)
        status_chain = " → ".join([str(r.status_code) for r in response.history] + [str(response.status_code)])
        return (subdomain, status_chain)
    except requests.Timeout:
        return (subdomain, "408 Timeout")
    except requests.ConnectionError:
        return (subdomain, "503 Service Unavailable")
    except requests.RequestException:
        return (subdomain, "000 Unknown Error")

def colorize_status(status):
    if "200" in status:
        return f"{GREEN}{status}{RESET}"
    elif "301" in status or "302" in status:
        return f"{YELLOW}{status}{RESET}"
    elif "400" in status or "404" in status:
        return f"{RED}{status}{RESET}"
    elif "500" in status or "503" in status:
        return f"{MAGENTA}{status}{RESET}"
    elif "408" in status:
        return f"{CYAN}{status}{RESET}"
    else:
        return f"{RED}{status}{RESET}"

def enumerate_subdomains(domain, output_file):
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
        print(f"{subdomain} | {colorize_status(status)}")
    if output_file:
        print(f"\n{GREEN}[\u2713] Results saved to {output_file}{RESET}")

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
