import argparse
import requests
import tldextract
import dns.resolver
import dns.exception
import whois
import subprocess
import datetime
import json

# Define ANSI color codes
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def check_website():
    print("Don't forget to enter the website link with Http/Https for the tool to work")
    url = input("Enter your website link: ")
    try:
        response = requests.get(url)
        response.raise_for_status()
        domain = tldextract.extract(url).domain
        print(f"[ ✓ ] Domain: {domain}")
        return domain
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[ X ] Error: Website does not exist or cannot be reached.{Colors.ENDC}")
        return None

def is_domain_registered(domain):
    try:
        whois_info = whois.whois(domain)
        if whois_info.status:
            return True
    except Exception as e:
        print(f"{Colors.WARNING}Domain {domain} is not registered or could not be checked.{Colors.ENDC}")
    return False

def check_domain_dns(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        return True
    except dns.resolver.NoAnswer:
        print(f"{Colors.WARNING}No A record found for {domain}.{Colors.ENDC}")
    except dns.resolver.NXDOMAIN:
        print(f"{Colors.FAIL}Domain {domain} does not exist.{Colors.ENDC}")
    except dns.exception.DNSException as e:
        print(f"{Colors.FAIL}DNS exception for {domain}: {e}{Colors.ENDC}")
    return False

def check_nameservers(domain):
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        ns_records = [str(rdata) for rdata in answers]
        return ns_records
    except dns.resolver.NoAnswer:
        print(f"{Colors.WARNING}No NS record found for {domain}.{Colors.ENDC}")
    except dns.resolver.NXDOMAIN:
        print(f"{Colors.FAIL}Domain {domain} does not exist.{Colors.ENDC}")
    except dns.exception.DNSException as e:
        print(f"{Colors.FAIL}DNS exception for {domain}: {e}{Colors.ENDC}")
    return []

def run_dig_command(domain, record_type, log_file):
    command = f"dig {domain} {record_type}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        log_file.write(f"\nOutput for {domain} ({record_type}):\n")
        log_file.write(result.stdout)
    except subprocess.CalledProcessError as e:
        log_file.write(f"Command failed with exit code {e.returncode}\n")
        log_file.write(e.output)

def fetch_subdomains_from_crtsh(domain):
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        certificates = response.json()
        for cert in certificates:
            # Split name_value field which contains subdomains separated by newlines
            names = cert['name_value'].split('\n')
            for name in names:
                if name:
                    subdomains.add(name.strip())
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[ X ] Error fetching subdomains from crt.sh: {e}{Colors.ENDC}")
    return subdomains

def detect_domain_shadowing(target_domain, subdomains):
    # Create timestamp for filenames
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Define filenames for the logs
    log_filename = f"{target_domain}+.txt"
    dns_and_ns_log_filename = f"{target_domain}+dns_and_ns.txt"
    ns_log_filename = f"{target_domain}+ns.txt"
    dns_only_log_filename = f"{target_domain}+dns_only.txt"

    try:
        # Open the log files
        with open(log_filename, 'w') as log_file, \
             open(dns_and_ns_log_filename, 'w') as dns_and_ns_log_file, \
             open(ns_log_filename, 'w') as ns_log_file, \
             open(dns_only_log_filename, 'w') as dns_only_log_file:
            print(f"{Colors.HEADER}Checking for domain shadowing for target domain: {target_domain}{Colors.ENDC}")

            for subdomain in subdomains:
                test_domain = f"{subdomain}.{target_domain}"
                print(f"{Colors.OKBLUE}Checking domain: {test_domain}{Colors.ENDC}")
                
                if is_domain_registered(test_domain):
                    print(f"{Colors.WARNING}Domain {test_domain} is registered.{Colors.ENDC}")
                    
                    if check_domain_dns(test_domain):
                        print(f"{Colors.OKGREEN}Domain {test_domain} has DNS records.{Colors.ENDC}")
                        
                        # Check nameservers
                        ns_records = check_nameservers(test_domain)
                        if ns_records:
                            print(f"{Colors.WARNING}Domain {test_domain} has nameservers: {', '.join(ns_records)}.{Colors.ENDC}")
                            # Log domains with both DNS records and nameservers
                            dns_and_ns_log_file.write(f"{test_domain} has DNS records and nameservers: {', '.join(ns_records)}\n")
                            # Log domains with nameservers
                            ns_log_file.write(f"{test_domain} has nameservers: {', '.join(ns_records)}\n")
                        else:
                            print(f"{Colors.OKGREEN}Domain {test_domain} has no associated nameservers, thus not vulnerable to domain shadowing.{Colors.ENDC}")
                            # Log domains with DNS records but no nameservers
                            dns_only_log_file.write(f"{test_domain} has DNS records but no nameservers.\n")
                    
                    else:
                        print(f"{Colors.FAIL}Domain {test_domain} does not have DNS records.{Colors.ENDC}")
                        # Log in the main log file if it has nameservers but no DNS records
                        ns_records = check_nameservers(test_domain)
                        if ns_records:
                            log_file.write(f"{test_domain} has nameservers but no DNS records.\n")
                            # Log domains with nameservers
                            ns_log_file.write(f"{test_domain} has nameservers: {', '.join(ns_records)}\n")
                    
                    # Run `dig` commands for detailed output
                    run_dig_command(test_domain, 'A', log_file)
                else:
                    print(f"{Colors.WARNING}Domain {test_domain} is not registered.{Colors.ENDC}")

    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    # Trigger the alert if a potential issue has been found
    check_log_file(ns_log_filename)

def check_log_file(filename):
    try:
        with open(filename, 'r') as file:
            content = file.read().strip()

        if not content:
            print(f"{Colors.WARNING}Log file {filename} is empty which is good.{Colors.ENDC}")
            return False

        brief_info = content.split('\n')[:5]  # Adjust this to get the first few lines or any other summary
        print(f"Attention! {Colors.OKGREEN}Log file contains the following information:{Colors.ENDC}")
        for line in brief_info:
            print(line)

        return True # Or json.dumps(brief_info, indent=4)

    except FileNotFoundError:
        print(f"{Colors.FAIL}Log file {filename} not found.{Colors.ENDC}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect potential domain shadowing.")
    parser.add_argument('target_domain', type=str, help='The target domain to check for shadowing.')
    parser.add_argument('subdomains_file', type=str, help='A file containing a list of subdomains to check.')
    args = parser.parse_args()

    # Read subdomains from file
    try:
        with open(args.subdomains_file, 'r') as file:
            wordlist_subdomains = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        print(f"{Colors.FAIL}Subdomains file not found.{Colors.ENDC}")
        exit(1)

    # Fetch subdomains from crt.sh
    crtsh_subdomains = fetch_subdomains_from_crtsh(args.target_domain)
    
    # Combine both sets of subdomains
    combined_subdomains = set(wordlist_subdomains) | crtsh_subdomains

    detect_domain_shadowing(args.target_domain, combined_subdomains)
