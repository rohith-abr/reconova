import os
import argparse
import concurrent.futures
import requests
import random
import re
from pyfiglet import figlet_format


GREEN = "\033[92m"      
YELLOW = "\033[93m"     
RED = "\033[91m"       
MAGENTA = "\033[95m"   
CYAN = "\033[96m"      
BLUE = "\033[94m"     
RESET = "\033[0m"      


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1"
]

DOMAIN_REGEX = re.compile(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")


def is_valid_subdomain(subdomain, domain):
    """Check if a subdomain is valid and belongs to the target domain."""
    return DOMAIN_REGEX.match(subdomain) and subdomain.endswith(domain)


def fetch_subdomains(domain):
    """Fetch subdomains from various APIs."""
    print(f"{YELLOW}[+] Gathering subdomains for {domain}...{RESET}")
    
    subdomains = set()

    api_sources = [
        ("Bufferover", f"https://dns.bufferover.run/dns?q={domain}"),
        ("HackerTarget", f"https://api.hackertarget.com/hostsearch/?q={domain}"),
        ("AlienVault", f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"),
        ("CertSpotter", f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names")
    ]

    headers = {"User-Agent": random.choice(USER_AGENTS)}

    for source, url in api_sources:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
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
                elif source == "AlienVault":
                    for record in response.json().get("passive_dns", []):
                        sub = record.get("hostname", "").strip().lower()
                        if is_valid_subdomain(sub, domain):
                            subdomains.add(sub)
                elif source == "CertSpotter":
                    for record in response.json():
                        for sub in record.get("dns_names", []):
                            sub = sub.lower()
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


def colorize_status(status):
    """Apply color coding to status codes."""
    if "200" in status:
        return f"{GREEN}{status}{RESET}"  
    elif "301" in status or "302" in status:
        return f"{YELLOW}{status}{RESET}"  
    elif "403" in status:
        return f"{BLUE}{status}{RESET}"  
    elif "404" in status:
        return f"{RED}{status}{RESET}" 
    elif "500" in status or "503" in status:
        return f"{MAGENTA}{status}{RESET}"  
    elif "408" in status or "000" in status:
        return f"{CYAN}{status}{RESET}" 
    else:
        return f"{RED}{status}{RESET}" 


def check_http_status(subdomain):
    """Fetch HTTP status codes accurately using HEAD and GET requests."""
    headers = {"User-Agent": random.choice(USER_AGENTS)}

    try:
        
        response = requests.head(f"https://{subdomain}", headers=headers, timeout=5, allow_redirects=True)
        
       
        if response.status_code in [405, 403, 400] or response.status_code >= 500:
            response = requests.get(f"https://{subdomain}", headers=headers, timeout=10, allow_redirects=True)

        
        status_chain = " → ".join([str(r.status_code) for r in response.history] + [str(response.status_code)])
        return subdomain, colorize_status(status_chain)

    except requests.Timeout:
        return subdomain, colorize_status("408 Timeout")
    except requests.ConnectionError:
        return subdomain, colorize_status("503 Service Unavailable")
    except requests.RequestException:
        return subdomain, colorize_status("000 Unknown Error")


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
