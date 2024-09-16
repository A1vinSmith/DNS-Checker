```bash
# Ensure domains.txt exists and is not empty
if [ ! -s domains.txt ]; then
  echo "Error: domains.txt is missing or empty"
  exit 1
fi

# Clear previous results if needed
> all_outputs.txt

# Process each domain
while IFS= read -r domain; do
  echo "Processing domain: $domain"
  # Capture both stdout and stderr, and use stdbuf to disable buffering
  sudo stdbuf -oL docker run --rm punksecurity/dnsreaper single --domain "$domain" >> all_outputs.txt 2>&1
done < domains.txt

# Check the content of all_outputs.txt
echo "Contents of all_outputs.txt:"
cat all_outputs.txt

# Filter the results to find takeovers
grep -Eo "found [0-9]+ takeovers" all_outputs.txt | awk '{split($0, a, " "); if (a[2] > 0) print $0}' > takeovers_found.txt
```