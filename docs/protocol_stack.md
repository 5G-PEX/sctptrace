# NGAP Protocol Stack Structure

## Overview

NGAP (NG Application Protocol) is used for control plane signaling between the gNB (5G base station) and the 5G Core Network (AMF - Access and Mobility Management Function). It carries control messages for functions like registration, session management, mobility, and paging.

## Protocol Stack Layers

```
+---------------------+
|     Application     |
|     (e.g., VoNR)    |
+---------------------+
|         NAS         |  <- Non-Access Stratum (UE-AMF signaling)
+---------------------+
|        NGAP         |  <- Our focus: gNB-AMF signaling
+---------------------+
|        SCTP         |  <- Transport for NGAP
+---------------------+
|      IP/IPSEC       |
+---------------------+
|    L2 (Ethernet)    |
+---------------------+
|    L1 (Physical)    |
+---------------------+
```

## NGAP in the Protocol Stack

1. **Transport Protocol**: SCTP (Stream Control Transmission Protocol)
   - NGAP messages are carried as payload in SCTP DATA chunks
   - SCTP port number 38412 is used for NGAP
   - SCTP PPID 60 identifies NGAP payload

2. **Encapsulation Process**:
   - NGAP message is encoded (typically using ASN.1 PER)
   - Encoded message is placed into SCTP DATA chunk payload
   - DATA chunk is transmitted within SCTP packet

3. **Path in Linux Kernel**:
   - Application creates NGAP message
   - Message passed to SCTP socket
   - SCTP forms chunks (`sctp_make_data_chunk`)
   - Chunks transmitted (`sctp_packet_transmit_chunk`)
   - Received by peer (`sctp_sf_eat_data_6_2`)
   - Delivered to NGAP application

## SCTP DATA Chunk Structure

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 0    | Reserved|U|B|E|    Length                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              TSN                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Stream Identifier S      |   Stream Sequence Number n    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Payload Protocol Identifier                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
\                                                               \
/                 User Data (seq n of Stream S)                 /
\                                                               \
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- The NGAP message is in the "User Data" section
- Payload Protocol Identifier (PPID) = 60 indicates NGAP
- NGAP uses one or more SCTP streams within an association

## Interception Points

1. **Outgoing NGAP Messages**:
   - `sctp_packet_transmit_chunk` - When a chunk is being transmitted

2. **Incoming NGAP Messages**:
   - `sctp_sf_eat_data_6_2` - When DATA chunk is received in established state

3. **Message Identification**:
   - Check PPID = 60 to confirm it's NGAP
   - Parse ASN.1 header to identify message type