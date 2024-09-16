import sys
import requests
import dns.resolver
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

def get_subdomains(domain):
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
        
        return list(subdomains)
    except Exception as e:
        print(f"{Fore.RED}Error fetching subdomains: {e}{Style.RESET_ALL}")
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

'''
grep -oP '\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' domain.com_dangling_records.txt | sort | uniq > domain.com_dangling_records_tobeverified.txt
```