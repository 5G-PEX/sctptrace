# NGAP Message Format

## Overview

NGAP messages use ASN.1 (Abstract Syntax Notation One) with PER (Packed Encoding Rules) for binary encoding. The protocol is defined in 3GPP TS 38.413.

## Basic NGAP PDU Structure

NGAP has four basic message types:

1. **Initiating Message**: Starts a procedure
2. **Successful Outcome**: Positive response to an initiating message
3. **Unsuccessful Outcome**: Negative response to an initiating message
4. **Elementary Procedure**: Standalone message requiring no response

## Message Header Structure

Each NGAP message begins with a PDU header:

```
NGAP-PDU ::= CHOICE {
    initiatingMessage      InitiatingMessage,
    successfulOutcome      SuccessfulOutcome,
    unsuccessfulOutcome    UnsuccessfulOutcome,
    ...
}

InitiatingMessage ::= SEQUENCE {
    procedureCode          ProcedureCode,
    criticality            Criticality,
    value                  ANY
}

SuccessfulOutcome ::= SEQUENCE {
    procedureCode          ProcedureCode,
    criticality            Criticality,
    value                  ANY
}

UnsuccessfulOutcome ::= SEQUENCE {
    procedureCode          ProcedureCode,
    criticality            Criticality,
    value                  ANY
}
```

## Binary Encoding

When encoded with PER, the NGAP PDU begins with:

1. **PDU Type** (2 bits):
   - 00: Initiating Message
   - 01: Successful Outcome
   - 10: Unsuccessful Outcome

2. **Procedure Code** (8 bits):
   - Identifies the specific procedure (e.g., Registration, PDU Session Setup)
   - Values defined in 3GPP TS 38.413 (and listed in ngap_procedure_codes.py)

3. **Criticality** (2 bits):
   - 00: reject
   - 01: ignore
   - 10: notify

## Common NGAP Messages

### Registration Related
- Registration Request
- Registration Accept
- Registration Complete
- Registration Reject

### Session Management Related
- PDU Session Establishment Request
- PDU Session Establishment Accept
- PDU Session Modification
- PDU Session Release

### Mobility Related
- Handover Required
- Handover Command
- Handover Notify
- Path Switch Request

### Connection Management
- Initial Context Setup
- UE Context Release
- UE Context Modification

## Example Binary Structure

Example of a Registration Request (initiating message):

```
+--------+--------+--------+--------+
| 00PPPPPP PPCCNNNN VVVVVVVV VVVVVVVV |
+--------+--------+--------+--------+
  ^         ^        ^
  |         |        |
  |         |        +-- Value (message content)
  |         +-- Criticality (CC) and length (NNNN)
  +-- PDU Type (00) and Procedure Code (PPPPPPPP)
```

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
   sudo ./ngap_stats.py -p PID
   ```