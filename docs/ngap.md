## Extracting Information in eBPF

In our eBPF program, we:

1. Identify SCTP DATA chunks with PPID 60 (NGAP)
2. Extract the first few bytes of the payload
3. Parse the PDU Type (first 2 bits)
4. Extract the Procedure Code (next 8 bits, may span multiple bytes)
5. Map the Procedure Code to a known NGAP message type

Note: Full ASN.1 PER parsing is complex for eBPF, so we use a simplified approach to extract just the essential information for statistics.
```

## Usage Instructions

1. Save all the files in the same directory.

2. Make the main script executable:
   ```
   chmod +x ngap_stats.py
   ```

3. Run the NGAP statistics collection:
   ```
   sudo ./ngap_stats.py
   ```

4. For more detailed output:
   ```
   sudo ./ngap_stats.py --detail
   ```

5. To monitor a specific process:
   ```
   sudo ./ngap_stats.py
   ```