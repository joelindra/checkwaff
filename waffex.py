import subprocess
import os
import argparse
import sys
import re
from colorama import Fore, Style, init
from threading import Lock

# Initialize colorama
init()

# Create the results folder if it doesn't exist
if not os.path.exists("results"):
    os.makedirs("results")

# Initialize a file lock for thread safety
file_lock = Lock()

# Function to run subfinder for subdomain enumeration
def run_subfinder(domain):
    print(Fore.CYAN + f"[*] Running subfinder for {domain}..." + Style.RESET_ALL)
    result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True)
    subdomains = result.stdout.splitlines()
    print(Fore.GREEN + f"[*] Found {len(subdomains)} subdomains." + Style.RESET_ALL)
    return subdomains

# Function to run httprobe for validating subdomains
def run_httprobe(subdomains):
    print(Fore.CYAN + "[*] Running httprobe for subdomain validation..." + Style.RESET_ALL)
    try:
        # Run httprobe and capture output
        result = subprocess.run(['httprobe'], input='\n'.join(subdomains), capture_output=True, text=True)

        # Print the full output for debugging
        print(Fore.YELLOW + "[DEBUG] httprobe raw output:" + Style.RESET_ALL)
        print(result.stdout)

        # Split output into valid domains
        valid_domains = result.stdout.splitlines()
        print(Fore.GREEN + f"[*] {len(valid_domains)} subdomains passed httprobe validation." + Style.RESET_ALL)
        return valid_domains

    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[ERROR] httprobe failed with error: {e}" + Style.RESET_ALL)
        return []
    except Exception as e:
        print(Fore.RED + f"[ERROR] Unexpected error: {e}" + Style.RESET_ALL)
        return []


# Function to check WAF using wafw00f
def check_waf(domain):
    try:
        result = subprocess.run(['wafw00f', domain], capture_output=True, text=True)
        output = result.stdout
        print(Fore.YELLOW + f"[INFO] WAFw00f Output for {domain}:" + Style.RESET_ALL)
        print(output)

        # Check if the output contains "No WAF detected"
        if "No WAF detected" in output:
            return None  # Return None if no WAF is detected

        # WAF detection patterns
        waf_patterns = {
            "Cloudflare": "Cloudflare",
            "Akamai": "Akamai",
            "Incapsula": "Incapsula",
            "Sucuri": "Sucuri",
            "Fortinet": "Fortinet",
            "ModSecurity": "ModSecurity",
            "AWS WAF": "AWS WAF",
            "F5": "F5",
            "Imperva": "Imperva",
            "StackPath": "StackPath",
            "Barracuda": "Barracuda",
            "Radware": "Radware",
            "CloudFront": "CloudFront",
            "Nginx": "Nginx",
            "Citrix": "Citrix",
            "SonicWall": "SonicWall",
            "WebKnight": "WebKnight",
            "Trustwave": "Trustwave",
            "Quttera": "Quttera",
            "Websense": "Websense",
            "PerimeterX": "PerimeterX",
            "NetScaler": "NetScaler",
            "Shape Security": "Shape Security",
            "Armor": "Armor",
            "Secucloud": "Secucloud",
            "Securi": "Securi",
            "Fastly": "Fastly",
            "Azure Front Door": "Azure Front Door",
            "LiteSpeed": "LiteSpeed",
            "AWS Elastic Load Balancer (Amazon)": "AWS Elastic Load Balancer (Amazon)",
            "Telerik": "Telerik",
            "Web Application Firewall (WAF) by SAP": "Web Application Firewall (WAF) by SAP",
            "Kaspersky": "Kaspersky",
            "Symantec Web Security": "Symantec Web Security",
            "McAfee Web Gateway": "McAfee Web Gateway",
            "SonicWall Web Application Firewall": "SonicWall Web Application Firewall",
            "F5 BIG-IP Application Security Manager": "F5 BIG-IP Application Security Manager",
            "Centrify": "Centrify",
            "Sophos XG Firewall": "Sophos XG Firewall",
            "OpenResty": "OpenResty",
            "WAF Manager": "WAF Manager",
            "Reblaze": "Reblaze",
            "FortiWeb": "FortiWeb",
            "Web Application Firewall by NSFOCUS": "Web Application Firewall by NSFOCUS",
            "Bfore.AI": "Bfore.AI",
            "Snyk": "Snyk",
            "Snyk Application Security": "Snyk Application Security",
            "Luminate Security": "Luminate Security",
            "SiteLock": "SiteLock",
            "Threat Stack": "Threat Stack",
            "Darktrace": "Darktrace",
            "Wappalyzer": "Wappalyzer",
            "Palo Alto Networks": "Palo Alto Networks",
            "Perimeter 81": "Perimeter 81",
            "White Ops": "White Ops",
            "Snyk Container": "Snyk Container",
            "AppWall": "AppWall",
            "NSFOCUS WAF": "NSFOCUS WAF",
            "Azure Application Gateway": "Azure Application Gateway",
            "Rapid7": "Rapid7",
            "Imunify360": "Imunify360",
            "Bishop Fox": "Bishop Fox",
            "Ally Security": "Ally Security"
        }

        # Determine if the output contains any indication of WAF
        for pattern, name in waf_patterns.items():
            if pattern.lower() in output.lower():
                return name

        return None

    except Exception as e:
        print(Fore.RED + f"[ERROR] wafw00f failed: {e}" + Style.RESET_ALL)
        return None

# Function to append domain to waffed_domain.md
def append_to_waffed_domain(domain):
    with file_lock:
        try:
            with open("results/waffed_domain.md", "a") as f:
                f.write(f"{domain}\n")
            print(Fore.GREEN + f"[INFO] Domain {domain} appended to waffed_domain.md" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[ERROR] Failed to append domain: {e}" + Style.RESET_ALL)

# Function to check WAF for each domain
def check_waf_for_domain(domain):
    waf_name = check_waf(domain)

    # Save results to corresponding files
    if waf_name:
        with open("results/results_waffed.md", "a") as f:
            f.write(f"- {domain} is protected by WAF ({waf_name})\n")
        print(Fore.GREEN + f"[INFO] {domain} is protected by WAF ({waf_name}). Saved to results_waffed.md" + Style.RESET_ALL)
        # Append to waffed_domain.md
        append_to_waffed_domain(domain)
    else:
        with open("results/results_nowaff.md", "a") as f:
            f.write(f"- {domain} is not protected by WAF\n")
        print(Fore.RED + f"[INFO] {domain} is not protected by WAF. Saved to results_nowaff.md" + Style.RESET_ALL)

# Function to extract domains from results_waffed.md
def extract_domains():
    try:
        with open("results/results_waffed.md", "r") as f:
            lines = f.readlines()

        domains = set()
        for line in lines:
            match = re.search(r"- (https?://)?(www\.)?([a-zA-Z0-9.-]+)", line)
            if match:
                domain = match.group(3)
                domains.add(domain)

        with open("results/waffed_domain.md", "w") as f:
            for domain in sorted(domains):
                f.write(f"{domain}\n")

        print(Fore.GREEN + "[INFO] Extracted domains saved to waffed_domain.md" + Style.RESET_ALL)

    except Exception as e:
        print(Fore.RED + f"[ERROR] Failed to extract domains: {e}" + Style.RESET_ALL)

# Main function
def main():
    parser = argparse.ArgumentParser(description="WAF Detection Automation")
    parser.add_argument("--single", help="Single target for WAF detection")
    parser.add_argument("--mass", help="File containing list of targets for subdomain enumeration and WAF detection")
    args = parser.parse_args()

    # Check if no arguments are provided, display help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    try:
        if args.single:
            # Single Target Mode
            domain = args.single
            print(Fore.CYAN + f"[*] Checking WAF for single domain: {domain}" + Style.RESET_ALL)
            check_waf_for_domain(domain)

        elif args.mass:
            # Mass Target Mode
            target_file = args.mass
            with open(target_file, 'r') as f:
                domains = f.read().splitlines()

            for domain in domains:
                print(Fore.CYAN + f"[*] Starting subdomain enumeration for {domain}" + Style.RESET_ALL)
                subdomains = run_subfinder(domain)

                # Validate subdomains with httprobe
                valid_subdomains = run_httprobe(subdomains)

                # Check WAF for all valid subdomains
                for subdomain in valid_subdomains:
                    check_waf_for_domain(subdomain)

    except KeyboardInterrupt:
        print(Fore.RED + "\n[INFO] Process interrupted by user. Exiting..." + Style.RESET_ALL)
        sys.exit(0)

if __name__ == "__main__":
    main()
