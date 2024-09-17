import sys
import os
import json
import requests
import re
import subprocess
from colorama import Fore, Style, init
from datetime import datetime, timedelta

# Initialize Colorama
init(autoreset=True)

CACHE_EXPIRY_DAYS = 1  # Cache expiry duration in days
CONTEXT_LINES = 5     # Number of lines to capture above and below

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

def get_subdomains(domain, wordlist_file):
    if not is_valid_domain(domain):
        print(f"{Fore.RED}Invalid domain format.{Style.RESET_ALL}")
        return []

    cache_file = get_cache_filename(domain)
    
    # Attempt to read from cache
    cached_data = read_cache(cache_file)
    if cached_data:
        print(f"{Fore.YELLOW}Using cached data.{Style.RESET_ALL}")
        subdomains = set(cached_data)
    else:
        subdomains = set()
    
    try:
        # Use crt.sh to get subdomains
        url = f'https://crt.sh/?q={domain}&output=json'
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        for entry in data:
            if 'name_value' in entry:
                subdomains.add(entry['name_value'])
        
        # Cache the new data if not using cached
        if not cached_data:
            write_cache(cache_file, list(subdomains))
    except requests.RequestException as e:
        print(f"{Fore.RED}Network error: {e}{Style.RESET_ALL}")
        # Return cached data if available
        if cached_data:
            print(f"{Fore.YELLOW}Using cached data due to network error.{Style.RESET_ALL}")
            return cached_data
        return []
    except ValueError as e:
        print(f"{Fore.RED}Error parsing JSON response: {e}{Style.RESET_ALL}")
        return []
    
    # Read and add subdomains from wordlist file
    if wordlist_file and os.path.exists(wordlist_file):
        with open(wordlist_file, 'r') as f:
            wordlist_subdomains = [line.strip() for line in f if line.strip()]
            for short_name in wordlist_subdomains:
                full_subdomain = f"{short_name}.{domain}"
                subdomains.add(full_subdomain)
    else:
        print(f"{Fore.RED}Wordlist file not found.{Style.RESET_ALL}")
    
    return list(subdomains)

def write_results_to_file(file_path, takeovers):
    with open(file_path, 'w') as file:
        # Write takeover information to the file
        if takeovers:
            file.write(f"{Fore.GREEN}Takeovers found:{Style.RESET_ALL}\n")
            for takeover in takeovers:
                file.write(takeover)
                file.write("\n" + "="*40 + "\n")
        else:
            file.write(f"{Fore.YELLOW}No takeovers found.{Style.RESET_ALL}\n")

def run_dnsreaper(subdomain):
    """Run the dnsreaper Docker command and capture its output."""
    command = [
        'sudo', 'stdbuf', '-oL', 'docker', 'run', '--rm',
        'punksecurity/dnsreaper', 'single', '--domain', subdomain
    ]
    with open('all_outputs.txt', 'a') as output_file:
        try:
            subprocess.run(command, stdout=output_file, stderr=subprocess.STDOUT, check=True)
        except subprocess.CalledProcessError as e:
            print(f"{Fore.RED}Command failed: {e}{Style.RESET_ALL}")

def extract_takeovers(file_path):
    """Extract lines with takeovers found and their surrounding context from the output file."""
    takeovers = []
    with open(file_path, 'r') as file:
        lines = file.readlines()
    
    for i, line in enumerate(lines):
        match = re.search(r'We found (\d+) takeovers ☠️', line)
        if match:
            count = int(match.group(1))
            if count > 0:
                # Collect the context around the takeover line
                context = []
                start = max(0, i - CONTEXT_LINES)
                end = min(len(lines), i + CONTEXT_LINES + 1)
                context = lines[start:end]
                takeovers.append(''.join(context))
    
    return takeovers

def main(domain, wordlist_file):
    print(f"{Fore.BLUE}Checking domain: {domain}{Style.RESET_ALL}")
    subdomains = get_subdomains(domain, wordlist_file)
    if not subdomains:
        print(f"{Fore.RED}No subdomains found or error occurred.{Style.RESET_ALL}")
        return
    
    # Run the dnsreaper command for each subdomain
    for subdomain in subdomains:
        run_dnsreaper(subdomain)
  
    # Extract takeovers from the output file
    takeovers = extract_takeovers('all_outputs.txt')
    if takeovers:
        print(f"{Fore.GREEN}Takeovers found:{Style.RESET_ALL}")
        for takeover in takeovers:
            print(takeover)
            print("\n" + "="*40 + "\n")  # Separator for readability

        # Write takeovers to file
        file_path = f"{domain}_dangling_records.txt"
        write_results_to_file(file_path, takeovers)
        print(f"{Fore.BLUE}Results have been written to {file_path}{Style.RESET_ALL}")

        return takeovers # return True to trigger the alert
    else:
        print(f"{Fore.YELLOW}No takeovers found.{Style.RESET_ALL}")
        return False # return False when not triggering the alert

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"{Fore.RED}Usage: python checker.py <domain_name> <wordlist_file>{Style.RESET_ALL}")
        sys.exit(1)
    
    domain = sys.argv[1]
    wordlist_file = sys.argv[2]
    main(domain, wordlist_file)
