```bash
grep -oP '\b[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b' domain.com_dangling_records.txt | sort | uniq > domain.com_dangling_records_tobeverified.txt
```