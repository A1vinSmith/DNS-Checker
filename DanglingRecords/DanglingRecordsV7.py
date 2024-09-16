import sys
import os
import json
import requests
import dns.resolver
from colorama import Fore, Style, init
from datetime import datetime, timedelta
import re

# Initialize Colorama
init(autoreset=True)

CACHE_EXPIRY_DAYS = 1  # Cache expiry duration in days

def get_cache_filename(domain):
    """Generate a unique cache filename based on the domain."""
    return f"{domain.replace('.', '_')}_cache.json"

def is_valid_domain(domain):
    """Check if the provided domain is valid."""
    return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain) is not None

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
            return cache_data['subdomains']
        else:
            return None
    except (json.JSONDecodeError, KeyError, ValueError):
        return None

def write_cache(cache_file, subdomains):
    """Write the data to cache file."""
    cache_data = {
        'timestamp': datetime.now().isoformat(),
        'subdomains': subdomains
    }
    with open(cache_file, 'w') as f:
        json.dump(cache_data, f)

def get_subdomains(domain):
    if not is_valid_domain(domain):
        print(f"{Fore.RED}Invalid domain format.{Style.RESET_ALL}")
        return []

    cache_file = get_cache_filename(domain)
    
    # Attempt to read from cache
    cached_data = read_cache(cache_file)
    if cached_data:
        print(f"{Fore.YELLOW}Using cached data.{Style.RESET_ALL}")
        return cached_data
    
    try:
        # Use crt.sh to get subdomains
        url = f'https://crt.sh/?q={domain}&output=json'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        subdomains = set()
        for entry in data:
            if 'name_value' in entry:
                subdomains.add(entry['name_value'])
        
        # Cache the new data
        write_cache(cache_file, list(subdomains))
        
        return list(subdomains)
    except requests.RequestException as e:
        print(f"{Fore.RED}Network error: {e}{Style.RESET_ALL}")
        # Return cached data if available
        cached_data = read_cache(cache_file)
        if cached_data:
            print(f"{Fore.YELLOW}Using cached data due to network error.{Style.RESET_ALL}")
            return cached_data
        return []
    except ValueError as e:
        print(f"{Fore.RED}Error parsing JSON response: {e}{Style.RESET_ALL}")
        return []

def check_dangling_dns(subdomain):
    record_types = ['A', 'CNAME', 'MX', 'TXT']
    dangling_records = {}
    
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(subdomain, record_type)
            if not answers:
                dangling_records[record_type] = 'No records found'
        except dns.resolver.NoAnswer:
            dangling_records[record_type] = 'No answer'
        except dns.resolver.NXDOMAIN:
            dangling_records[record_type] = 'NXDOMAIN'
        except Exception as e:
            dangling_records[record_type] = str(e)
    
    if not dangling_records:
        return None
    return dangling_records

def write_results_to_file(file_path, results):
    with open(file_path, 'w') as file:
        for subdomain, result in results.items():
            if result:
                file.write(f"** Dangling records found for {subdomain} **\n")
                for record_type, status in result.items():
                    file.write(f"  {record_type}: {status}\n")
                file.write("\n")
            else:
                file.write(f"No dangling records found for {subdomain}\n\n")

def main(domain):
    results = {}
    print(f"{Fore.BLUE}Checking domain: {domain}{Style.RESET_ALL}")
    subdomains = get_subdomains(domain)
    if not subdomains:
        print(f"{Fore.RED}No subdomains found or error occurred.{Style.RESET_ALL}")
        return
    
    for subdomain in subdomains:
        full_subdomain = subdomain if subdomain.endswith(domain) else f"{subdomain}.{domain}"
        print(f"{Fore.BLUE}Checking subdomain: {Fore.YELLOW}{full_subdomain}{Style.RESET_ALL}")
        result = check_dangling_dns(full_subdomain)
        if result:
            results[full_subdomain] = result
            print(f"{Fore.YELLOW}Dangling records found for {Fore.GREEN}{full_subdomain}:{Style.RESET_ALL}")
            for record_type, status in result.items():
                print(f"  {Fore.CYAN}{record_type}: {Fore.RED}{status}{Style.RESET_ALL}")
        else:
            results[full_subdomain] = None
            print(f"{Fore.GREEN}No dangling records found for {Fore.YELLOW}{full_subdomain}{Style.RESET_ALL}")
    
    # Write results to file
    file_path = f"{domain}_dangling_records.txt"
    write_results_to_file(file_path, results)
    print(f"{Fore.BLUE}Results have been written to {file_path}{Style.RESET_ALL}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"{Fore.RED}Usage: python DanglingRecordsV2.py <domain_name>{Style.RESET_ALL}")
        sys.exit(1)
    
    domain = sys.argv[1]
    main(domain)
