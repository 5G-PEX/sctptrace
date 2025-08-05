# sctptrace

**Advanced eBPF-based tools for monitoring SCTP protocol performance**

![SCTP Monitoring](https://img.shields.io/badge/protocol-SCTP-blue)
![eBPF](https://img.shields.io/badge/technology-eBPF-orange)
![BCC](https://img.shields.io/badge/framework-BCC-green)

## Overview

`sctptrace` is a collection of BPF-based tools for monitoring, analysing, and troubleshooting SCTP (Stream Control Transmission Protocol) connections in real-time. The tools use eBPF technology to provide kernel-level insights with minimal overhead, enabling deep visibility into SCTP performance metrics.

SCTP is often used in telecommunications, financial services, and high-performance computing where its multi-streaming and multi-homing capabilities provide advantages over TCP. However, debugging and monitoring SCTP can be challenging. `sctptrace` bridges this gap with specialized tools for key SCTP performance metrics.

## Features

- **Low overhead**: Uses eBPF technology for efficient kernel-level tracing
- **Real-time monitoring**: Live analysis of active SCTP connections
- **Comprehensive metrics**: Tracks RTT, RTO, buffer utilization, jitter, and stream usage
- **Multi-stream visibility**: Detailed insights into SCTP's multi-streaming capability
- **Per-association tracking**: Monitor individual SCTP associations separately

## Tools

| Tool | Description |
|------|-------------|
| **sctp_rtt.py** | Measures Round Trip Time (RTT) for SCTP data chunks |
| **sctp_rto.py** | Monitors Retransmission Timeout (RTO) values and update algorithm |
| **sctp_bufmon.py** | Tracks send/receive buffer utilization and pressure |
| **sctp_jitter.py** | Analyses packet timing variations (jitter) across streams |
| **sctp_streamutil.py** | Provides insights into stream utilization and parallelism |

## Requirements

- Linux kernel 6.8+
- BCC (BPF Compiler Collection)
- Python 3.6+
- Root privileges for running the tools

## Installation

1. Install BCC framework (if not already installed):

```bash
# For Ubuntu/Debian
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)

# For RHEL/CentOS/Fedora
sudo yum install bcc-tools kernel-devel
```

2. Clone the repository:

```bash
git clone https://github.com/yourusername/sctptrace.git
cd sctptrace
```

3. Make the tools executable:

```bash
chmod +x *.py
```

## Usage Examples

See the .txt for each tool

## Understanding SCTP Performance Metrics

### Round Trip Time (RTT)
Time taken for a packet to travel from sender to receiver and back. SCTP tracks RTT per destination address for path management purposes. Lower RTT values indicate better network performance.

### Retransmission Timeout (RTO)
Adaptive timer used for retransmission decisions. SCTP calculates RTO based on RTT measurements using a similar algorithm to TCP but with adaptations for multi-homing support.

### Buffer Utilization
Tracks how effectively send and receive buffers are being used. High buffer utilization may indicate congestion or application processing bottlenecks.

### Jitter
Variation in packet delivery timing, critical for time-sensitive applications. SCTP's multi-streaming can help reduce jitter for prioritized streams.

### Stream Utilization
Measures how effectively an application uses SCTP's multi-streaming capability. Well-balanced stream usage maximizes SCTP's performance advantages.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs, questions, or new features.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The [BCC project](https://github.com/iovisor/bcc) for providing the BPF compiler collection framework
- The Linux kernel team for developing and maintaining SCTP and BPF technologies

---

**Note**: These tools rely on internal kernel structures which may change between kernel versions. The tools have been tested with Linux kernel 6.8, but may require adjustments for other kernel versions.