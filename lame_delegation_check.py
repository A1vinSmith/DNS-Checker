import argparse
import dns.resolver
import dns.query
import dns.message
import dns.exception
import subprocess
import datetime
import os

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

def get_ip_addresses(name_server):
    try:
        answers = dns.resolver.resolve(name_server, 'A')
        return [rdata.address for rdata in answers]
    except dns.resolver.NoAnswer:
        print(f"{Colors.WARNING}No A record found for {name_server}{Colors.ENDC}")
        return []
    except dns.resolver.NXDOMAIN:
        print(f"{Colors.FAIL}Domain {name_server} does not exist{Colors.ENDC}")
        return []
    except dns.exception.DNSException as e:
        print(f"{Colors.FAIL}DNS exception for {name_server}: {e}{Colors.ENDC}")
        return []

def check_record_type(name_server_ip, domain, record_type):
    try:
        query_message = dns.message.make_query(domain, record_type)
        response = dns.query.udp(query_message, name_server_ip, timeout=5)

        if response.rcode() == dns.rcode.NOERROR:
            if response.answer:
                print(f"{Colors.OKGREEN}{name_server_ip} responds with valid {record_type} records.{Colors.ENDC}")
                return True
            else:
                print(f"{Colors.WARNING}{name_server_ip} responded with NOERROR but no {record_type} records found.{Colors.ENDC}")
                return True
        else:
            print(f"{Colors.FAIL}{name_server_ip} returned error code {response.rcode()} for {record_type} records.{Colors.ENDC}")
            return False # status: REFUSED, SERVFAIL or flag 'rd ra' will be count as fail
    except dns.exception.Timeout:
        print(f"{Colors.FAIL}Timeout querying {name_server_ip} for {record_type} records.{Colors.ENDC}")
    except dns.exception.DNSException as e:
        print(f"{Colors.FAIL}DNS exception querying {name_server_ip} for {record_type} records: {e}{Colors.ENDC}")
    return False # Potential vulnerable when return false

def run_dig_command(name_server_ip, domain, record_type, log_file):
    command = f"dig @{name_server_ip} {domain} {record_type}"
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        log_file.write(f"\nOutput for {name_server_ip} ({record_type}):\n")
        log_file.write(result.stdout)
    except subprocess.CalledProcessError as e:
        log_file.write(f"Command failed with exit code {e.returncode}\n")
        log_file.write(e.output)

def check_lame_delegation(domain):
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']  # List of record types to check

    # Create a timestamped filename for logging
    # timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    # log_filename = f"{domain}_{timestamp}.txt"
    log_filename = f"{domain}.txt"

    try:
        # Get the list of name servers for the domain
        ns_records = dns.resolver.resolve(domain, 'NS')
        name_servers = [ns.target.to_text() for ns in ns_records]

        print(f"{Colors.HEADER}Name servers for {domain}: {name_servers}{Colors.ENDC}")

        with open(log_filename, 'w') as log_file:
            for ns in name_servers:
                ns_ip_addresses = get_ip_addresses(ns)
                if not ns_ip_addresses:
                    print(f"{Colors.WARNING}Name server {ns} has no IP addresses or could not be resolved.{Colors.ENDC}")
                    continue

                failed_record_types = []
                for ns_ip in ns_ip_addresses:
                    print(f"{Colors.OKBLUE}Checking {ns_ip} for {domain}...{Colors.ENDC}")
                    # Check if the name server responds to queries for multiple record types
                    for record_type in record_types:
                        if not check_record_type(ns_ip, domain, record_type):
                            failed_record_types.append(record_type)

                    if not failed_record_types:
                        print(f"{Colors.OKGREEN}{ns} ({ns_ip}) is responsive and returning valid answers for all checked record types.{Colors.ENDC}")
                    else:
                        print(f"{Colors.FAIL}{ns} ({ns_ip}) is not responding correctly for the following record types:{Colors.ENDC}")
                        for record_type in failed_record_types:
                            print(f"{Colors.WARNING} - {record_type}{Colors.ENDC}")

                        # Run `dig` commands for manual verification and log the output
                        for record_type in record_types:
                            run_dig_command(ns_ip, domain, record_type, log_file)

                if failed_record_types:
                    print(f"{Colors.FAIL}{ns} is likely vulnerable to lame delegation due to failure for the following record types: {', '.join(failed_record_types)}.{Colors.ENDC}")
                    log_file.write(f"\n{ns} is likely vulnerable to lame delegation due to failure for the following record types: {', '.join(failed_record_types)}.\n")

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        print(f"{Colors.FAIL}Error resolving {domain}: {e}{Colors.ENDC}")

    # Check log file contents after processing
    return check_log_file(log_filename)

def check_log_file(filename):
    try:
        with open(filename, 'r') as file:
            content = file.read().strip()

        if not content:
            print(f"{Colors.WARNING}Log file {filename} is empty which is good.{Colors.ENDC}")
            return False

        brief_info = content.split('\n')[:5]  # Adjust this to get the first few lines or any other summary
        print(f"{Colors.OKGREEN}Log file contains the following information:{Colors.ENDC}")
        for line in brief_info:
            print(line)

        return True # Or json.dumps(brief_info, indent=4)

    except FileNotFoundError:
        print(f"{Colors.FAIL}Log file {filename} not found.{Colors.ENDC}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check for lame delegation of a domain.")
    parser.add_argument('domain', type=str, help='The domain to check for lame delegation.')
    args = parser.parse_args()

    check_lame_delegation(args.domain)
