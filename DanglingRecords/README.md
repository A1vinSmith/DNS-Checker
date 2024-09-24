### Dependency
* https://github.com/punk-security/dnsReaper

Installation should be done with docker.

### Grabing IPs if needed

```bash
grep -oP '\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' domain.com_dangling_records.txt | sort | uniq > domain.com_dangling_records_tobeverified.txt
```

Script V9 is the definitive version. 

It serves as a preemptive measure, but it's crucial to have human verification of the crt.sh list before depending on this tool. This ensures we haven't been compromised at that point. The script is capable of identifying vulnerable takeover scenarios, but may not detect instances where a takeover has already occurred.
