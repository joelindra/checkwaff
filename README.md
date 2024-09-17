![image](https://github.com/user-attachments/assets/e6db2643-fe44-4e11-931f-273d78290d23)

# WAFFEX
This tool is designed for automating the detection of Web Application Firewalls (WAFs) and subdomain enumeration. It provides two modes: single-target and mass-target, and integrates multiple tools like subfinder, httprobe, and wafw00f to streamline the process.

## Single Target Mode:
Allows checking a single domain for WAF detection.
Detects whether a WAF is present and identifies its type from a comprehensive list of known WAFs (Cloudflare, Akamai, AWS WAF, etc.).
Saves the results to results_nowaff.md if no WAF is detected or results_waffed.md if a WAF is found.

## Mass Target Mode:
Processes a list of domains for subdomain enumeration using subfinder.
Validates the discovered subdomains with httprobe, ensuring only live ones are further analyzed.
Runs WAF detection on each validated subdomain.
Appends the results to the corresponding files based on WAF detection status.

## Automatic Domain Extraction:
Automatically extracts domains from results_waffed.md and saves them in waffed_domain.md.
This ensures proper organization of domains protected by WAFs.

## Usage:
Single Target Mode:
python waf_detector.py --single example.com
This checks if a WAF is present for example.com and saves the findings.

## Mass Target Mode:
python waf_detector.py --mass targets.txt
This processes a file (targets.txt) containing a list of domains. For each domain, subdomains are enumerated, validated, and checked for WAF protection.

# Key Points:
Results are saved in results_nowaff.md, results_waffed.md, and waffed_domain.md.
Thread safety is maintained using file locks to ensure proper file writing in multithreaded environments.
The tool handles exceptions and error cases gracefully, ensuring robust execution during long scanning sessions.
This tool is perfect for pentesters looking to streamline WAF detection and subdomain validation processes across multiple domains.
