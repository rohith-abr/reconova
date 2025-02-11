import os
import subprocess
import argparse
import concurrent.futures
import requests
from pyfiglet import figlet_format


GREEN = "\033[92m"      
YELLOW = "\033[93m"     
RED = "\033[91m"        
MAGENTA = "\033[95m"    
CYAN = "\033[96m"       
RESET = "\033[0m"       


def get_subdomains(domain):
    print(f"{YELLOW}[+] Running Reconova to gather subdomains...{RESET}")
    try:
        output = subprocess.run(
            ["subfinder", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        subdomains = set(output.stdout.strip().split("\n")) 
        return subdomains
    except FileNotFoundError:
        exit(1)  

def check_http_status(subdomain):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }

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
    print(f"{GREEN}[✓] Found {len(subdomains)} subdomains.{RESET}")

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
