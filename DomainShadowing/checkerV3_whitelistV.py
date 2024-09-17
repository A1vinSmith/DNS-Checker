import argparse
import requests
import tldextract
import dns.resolver
import dns.exception
import whois
import subprocess
import datetime
import json
import os
from datetime import datetime, timedelta

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

# Cache settings
CACHE_EXPIRY_DAYS = 1  # Cache expiry in days
CACHE_DIR = 'cache'  # Directory where cache files will be stored

def read_cache(cache_file):
    """Read the cached data if it is still valid."""
    if not os.path.exists(cache_file):
        return None

    try:
        with open(cache_file, 'r') as f:
            cache_data = json.load(f)
        
        # Check cache expiry
        cache_time = datetime.fromisoformat(cache_data['timestamp'])
        if datetime.now() - cache_time < timedelta(days=CACHE_EXPIRY_DAYS):
            return set(cache_data['subdomains'])  # Convert to set
        else:
            return None
    except (json.JSONDecodeError, KeyError, ValueError):
        return None

def write_cache(cache_file, subdomains):
    """Write the data to cache file."""
    cache_data = {
        'timestamp': datetime.now().isoformat(),
        'subdomains': list(subdomains)  # Convert to list
    }
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)  # Ensure cache directory exists
    with open(cache_file, 'w') as f:
        json.dump(cache_data, f)

def get_cache_filename(domain):
    """Generate a cache filename based on the domain."""
    sanitized_domain = domain.replace('.', '_')
    return os.path.join(CACHE_DIR, f'{sanitized_domain}_cache.json')

def fetch_subdomains_from_crtsh(domain):
    """Fetch subdomains from crt.sh with caching."""
    cache_file = get_cache_filename(domain)
    
    # Attempt to read from cache
    cached_data = read_cache(cache_file)
    if cached_data:
        print(f"{Colors.YELLOW}Using cached data.{Colors.ENDC}")
        return cached_data

    # Fetch from crt.sh
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        certificates = response.json()
        for cert in certificates:
            names = cert['name_value'].split('\n')
            for name in names:
                if name and name.endswith(f".{domain}"):
                    subdomains.add(name.strip())
        
        # Write fetched data to cache
        write_cache(cache_file, subdomains)
    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}[ X ] Error fetching subdomains from crt.sh: {e}{Colors.ENDC}")
    
    return subdomains

'''
def read_whitelist(filename):
    """Read the nameserver whitelist from a file."""
    if not os.path.exists(filename):
        print(f"{Colors.FAIL}Whitelist file not found.{Colors.ENDC}")
        return set()
    
    with open(filename, 'r') as f:
        return {line.strip() for line in f}
        '''
def read_whitelist(filename):
    """Read the nameserver whitelist from a file, handling both formats."""
    if not os.path.exists(filename):
        print(f"{Colors.FAIL}Whitelist file not found.{Colors.ENDC}")
        return set()
    
    whitelist = set()
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                whitelist.add(line)
                # Add the version with the trailing dot if it doesn't already exist
                if not line.endswith('.'):
                    whitelist.add(line + '.')
    
    return whitelist

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

def detect_domain_shadowing(target_domain, subdomains_file, whitelist_file):
    # Fetch subdomains from crt.sh with caching
    crtsh_subdomains = fetch_subdomains_from_crtsh(target_domain)
    
    # Read additional subdomains from the provided file
    try:
        with open(subdomains_file, 'r') as file:
            additional_subdomains = {line.strip() + '.' + target_domain for line in file}
    except FileNotFoundError:
        print(f"{Colors.FAIL}Subdomains file not found.{Colors.ENDC}")
        exit(1)

    # Combine subdomains from both sources
    all_subdomains = crtsh_subdomains.union(additional_subdomains)
    
    # Read the whitelist
    whitelist = read_whitelist(whitelist_file)
    
    # Create timestamp for filenames
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
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

            for subdomain in all_subdomains:
                print(f"{Colors.OKBLUE}Checking domain: {subdomain}{Colors.ENDC}")
                
                if is_domain_registered(subdomain):
                    print(f"{Colors.WARNING}Domain {subdomain} is registered.{Colors.ENDC}")
                    
                    if check_domain_dns(subdomain):
                        print(f"{Colors.OKGREEN}Domain {subdomain} has DNS records.{Colors.ENDC}")
                        
                        # Check nameservers
                        ns_records = check_nameservers(subdomain)
                        if ns_records:
                            # Filter out nameservers that are in the whitelist
                            filtered_ns_records = [ns for ns in ns_records if ns not in whitelist]
                            if filtered_ns_records:
                                print(f"{Colors.WARNING}Domain {subdomain} has nameservers: {', '.join(filtered_ns_records)}.{Colors.ENDC}")
                                # Log domains with both DNS records and nameservers not in whitelist
                                dns_and_ns_log_file.write(f"{subdomain} has DNS records and nameservers: {', '.join(filtered_ns_records)}\n")
                                # Log domains with nameservers not in whitelist
                                ns_log_file.write(f"{subdomain} has nameservers: {', '.join(filtered_ns_records)}\n")
                            else:
                                print(f"{Colors.OKGREEN}Domain {subdomain} has nameservers that are all in the whitelist.{Colors.ENDC}")
                                # Log domains with DNS records but no relevant nameservers
                                dns_only_log_file.write(f"{subdomain} has DNS records but no relevant nameservers.\n")
                    
                    else:
                        print(f"{Colors.FAIL}Domain {subdomain} does not have DNS records.{Colors.ENDC}")
                        # Log in the main log file if it has nameservers but no DNS records
                        ns_records = check_nameservers(subdomain)
                        if ns_records:
                            filtered_ns_records = [ns for ns in ns_records if ns not in whitelist]
                            if filtered_ns_records:
                                log_file.write(f"{subdomain} has nameservers but no DNS records.\n")
                                # Log domains with nameservers not in whitelist
                                ns_log_file.write(f"{subdomain} has nameservers: {', '.join(filtered_ns_records)}\n")
                    
                    # Run `dig` commands for detailed output
                    run_dig_command(subdomain, 'A', log_file)
                else:
                    print(f"{Colors.WARNING}Domain {subdomain} is not registered.{Colors.ENDC}")

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

        return True  # Or json.dumps(brief_info, indent=4)

    except FileNotFoundError:
        print(f"{Colors.FAIL}Log file {filename} not found.{Colors.ENDC}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Detect potential domain shadowing.")
    parser.add_argument('target_domain', type=str, help='The target domain to check for shadowing.')
    parser.add_argument('subdomains_file', type=str, help='A file containing a list of subdomains to check.')
    parser.add_argument('whitelist_file', type=str, help='A file containing a list of nameservers to whitelist.')
    args = parser.parse_args()

    detect_domain_shadowing(args.target_domain, args.subdomains_file, args.whitelist_file)
