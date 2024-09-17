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
CONTEXT_LINES = 5

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
  
    # Extract takeovers from the output file
    takeovers = extract_takeovers(wordlist_file)
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
