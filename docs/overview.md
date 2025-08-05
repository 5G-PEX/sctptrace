# SCTP Protocol Overview

Stream Control Transmission Protocol (SCTP) is a transport layer protocol designed to combine the reliability of TCP with message-oriented features and multi-homing capabilities.

## Key Features of SCTP

- **Multi-streaming**: Allows independent delivery of messages in parallel streams
- **Multi-homing**: Supports multiple IP addresses per endpoint for redundancy
- **Message-oriented**: Preserves message boundaries unlike TCP's byte-stream model
- **Four-way handshake**: Provides protection against SYN flooding attacks
- **Partial reliability**: Optional extension allowing for timed reliability
- **Selective acknowledgments**: Built-in by default (unlike TCP)

## SCTP Association State Diagram

```mermaid
stateDiagram-v2
    [*] --> CLOSED
    CLOSED --> COOKIE_WAIT: Send INIT
    COOKIE_WAIT --> COOKIE_ECHOED: Receive INIT-ACK<br>Send COOKIE-ECHO
    COOKIE_ECHOED --> ESTABLISHED: Receive COOKIE-ACK
    
    ESTABLISHED --> SHUTDOWN_PENDING: App requests shutdown<br>Outstanding DATA
    ESTABLISHED --> SHUTDOWN_SENT: App requests shutdown<br>No outstanding DATA<br>Send SHUTDOWN
    ESTABLISHED --> SHUTDOWN_RECEIVED: Receive SHUTDOWN
    
    SHUTDOWN_PENDING --> SHUTDOWN_SENT: All DATA acknowledged<br>Send SHUTDOWN
    SHUTDOWN_SENT --> SHUTDOWN_ACK_SENT: Receive SHUTDOWN-ACK<br>Send SHUTDOWN-COMPLETE
    SHUTDOWN_RECEIVED --> SHUTDOWN_ACK_SENT: No outstanding DATA<br>Send SHUTDOWN-ACK
    
    SHUTDOWN_ACK_SENT --> CLOSED: Receive SHUTDOWN-COMPLETE<br>or timeout
    
    state ESTABLISHED {
        [*] --> DATA_TRANSFER
        DATA_TRANSFER --> DATA_TRANSFER: Send/Receive DATA<br>SACK exchange
        DATA_TRANSFER --> PATH_FAILURE: Max retransmits reached
        PATH_FAILURE --> DATA_TRANSFER: Switch to alternate path
        PATH_FAILURE --> [*]: No alternate paths
    }
```

## SCTP Connection Flow

```mermaid
sequenceDiagram
    participant Client
    participant Server
    
    Note over Client,Server: Association Establishment
    Client->>Server: INIT
    Server->>Client: INIT-ACK
    Client->>Server: COOKIE-ECHO
    Server->>Client: COOKIE-ACK
    
    Note over Client,Server: Data Transfer Phase
    Client->>Server: DATA (Stream 0)
    Server->>Client: SACK
    Client->>Server: DATA (Stream 1)
    Client->>Server: DATA (Stream 0)
    Server->>Client: SACK
    Client->>Server: DATA (Primary Path)
    Client-->>Server: DATA RETRANSMIT (Alternate Path)
    Server->>Client: SACK
    Client->>Server: DATA (Stream 2)
    Client->>Server: DATA (Stream 2)
    Server->>Client: SACK
    
    Note over Client,Server: Association Termination
    Client->>Server: SHUTDOWN
    Server->>Client: SHUTDOWN-ACK
    Client->>Server: SHUTDOWN-COMPLETE
```

![SCTP Packets Data Chunks](images/SCTP_Packets_Data%20Chunks.jpeg "SCTP Packets Data Chunks [^1]")

## Key Performance Metrics

SCTP performance can be evaluated using several key metrics:

1. **Round Trip Time (RTT)**: Time for data to travel from sender to receiver and back
2. **Retransmission Timeout (RTO)**: Adaptive timer for retransmission decisions
3. **Buffer Utilization**: How efficiently send/receive buffers are being used
4. **Jitter**: Variation in packet delivery timing
5. **Stream Utilization**: How effectively multiple streams are being leveraged

Each of these metrics has dedicated tooling in the `sctptrace` project to provide detailed visibility into SCTP performance.

## References

- [RFC 4960: Stream Control Transmission Protocol](https://tools.ietf.org/html/rfc4960)
- [RFC 3758: SCTP Partial Reliability Extension](https://tools.ietf.org/html/rfc3758)
- [RFC 5061: SCTP Dynamic Address Reconfiguration](https://tools.ietf.org/html/rfc5061)



## File: `docs/stream_utilization.md`

```markdown

```

Each of these files provides comprehensive information about SCTP and the individual performance metrics, complete with state diagrams and explanations that will help users understand both the protocol and how to interpret the results from the `sctptrace` tools.

[^1] https://www.myreadingroom.co.in/notes-and-studymaterial/68-dcn/855-sctp-features.html