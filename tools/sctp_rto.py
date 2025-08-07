#!/usr/bin/python3
from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import socket
import struct
import csv

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <net/sctp/sctp.h>

struct rto_event_t {
    u32 transport_id;
    u64 rto_us;
    u32 srtt_us;
    u32 rttvar_us;
    // IP address components (v4)
    u32 ipv4_addr;
    u16 port;
    u8 addr_type;
};

BPF_PERF_OUTPUT(rto_events);

// Probe for RTO updates with correct signature
int kprobe__sctp_transport_update_rto(struct pt_regs *ctx, struct sctp_transport *tp, __u32 rtt) {
    struct rto_event_t event = {};
    
    if (!tp) 
        return 0;
    
    // Read RTO, SRTT, and RTTVAR values
    bpf_probe_read(&event.rto_us, sizeof(event.rto_us), &tp->rto);
    bpf_probe_read(&event.srtt_us, sizeof(event.srtt_us), &tp->srtt);
    bpf_probe_read(&event.rttvar_us, sizeof(event.rttvar_us), &tp->rttvar);
    
    // Use dst_cookie as transport_id
    bpf_probe_read(&event.transport_id, sizeof(event.transport_id), &tp->dst_cookie);
    
    // Try to get IP address info for better identification
    // Read the address family first to determine IPv4 or IPv6
    u16 family;
    bpf_probe_read(&family, sizeof(family), &tp->ipaddr.sa.sa_family);
    event.addr_type = family;
    
    if (family == AF_INET) {
        // For IPv4
        bpf_probe_read(&event.ipv4_addr, sizeof(event.ipv4_addr), &tp->ipaddr.v4.sin_addr.s_addr);
        bpf_probe_read(&event.port, sizeof(event.port), &tp->ipaddr.v4.sin_port);
    }
    
    rto_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Probe for retransmission events with correct signature
int kprobe__sctp_generate_t3_rtx_event(struct pt_regs *ctx, struct timer_list *t) {
    struct rto_event_t event = {};
    
    if (!t) 
        return 0;
    
    // Calculate the containing sctp_transport struct from the timer pointer
    // We need the offset of T3_rtx_timer in struct sctp_transport
    size_t timer_offset = offsetof(struct sctp_transport, T3_rtx_timer);
    struct sctp_transport *tp = (struct sctp_transport *)((char *)t - timer_offset);
    
    // Read RTO, SRTT, and RTTVAR values
    bpf_probe_read(&event.rto_us, sizeof(event.rto_us), &tp->rto);
    bpf_probe_read(&event.srtt_us, sizeof(event.srtt_us), &tp->srtt);
    bpf_probe_read(&event.rttvar_us, sizeof(event.rttvar_us), &tp->rttvar);
    
    // Use dst_cookie as transport_id
    bpf_probe_read(&event.transport_id, sizeof(event.transport_id), &tp->dst_cookie);
    
    // Get IP address info
    u16 family;
    bpf_probe_read(&family, sizeof(family), &tp->ipaddr.sa.sa_family);
    event.addr_type = family;
    
    if (family == AF_INET) {
        // For IPv4
        bpf_probe_read(&event.ipv4_addr, sizeof(event.ipv4_addr), &tp->ipaddr.v4.sin_addr.s_addr);
        bpf_probe_read(&event.port, sizeof(event.port), &tp->ipaddr.v4.sin_port);
    }
    
    rto_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Argument parsing
parser = argparse.ArgumentParser(
    description="Trace SCTP RTO updates and retransmissions"
)
parser.add_argument("-c", "--csv", action="store_true", help="Output in CSV format")
parser.add_argument(
    "-f", "--file", metavar="FILE", help="Write output to a specified file"
)
args = parser.parse_args()

# Load BPF program
b = BPF(text=bpf_text)

# RTO event structure
class RTOEvent(ct.Structure):
    _fields_ = [
        ("transport_id", ct.c_uint),
        ("rto_us", ct.c_ulonglong),
        ("srtt_us", ct.c_uint),
        ("rttvar_us", ct.c_uint),
        ("ipv4_addr", ct.c_uint),
        ("port", ct.c_ushort),
        ("addr_type", ct.c_ubyte),
    ]


# Setup CSV file and writer if requested
csvfile = None
writer = None
if args.file:
    csvfile = open(args.file, "w", newline="")
    writer = csv.writer(csvfile)
    


# Process RTO events
def process_rto_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RTOEvent)).contents
    
    rto_ms = float(event.rto_us) / 1000
    srtt_ms = float(event.srtt_us) / 1000 if event.srtt_us else 0
    rttvar_ms = float(event.rttvar_us) / 1000 if event.rttvar_us else 0

    # Format IP address if available
    ip_str = "N/A"
    port = 0
    if event.addr_type == socket.AF_INET and event.ipv4_addr != 0:
        ip_str = socket.inet_ntoa(struct.pack("I", event.ipv4_addr))
        port = socket.ntohs(event.port)
    
    if args.csv or args.file:
        row = [
            event.transport_id,
            ip_str,
            port,
            f"{rto_ms:.3f}",
            f"{srtt_ms:.3f}",
            f"{rttvar_ms:.3f}",
        ]
        if args.file:
            writer.writerow(row)
        else:
            print(",".join(map(str, row)))
    else:
        print(
            f"Transport: {event.transport_id}, "
            f"Addr: {ip_str}:{port}, "
            f"RTO: {rto_ms:.3f} ms, SRTT: {srtt_ms:.3f} ms, RTTVAR: {rttvar_ms:.3f} ms"
        )


b["rto_events"].open_perf_buffer(process_rto_event)

# Main loop
if not args.csv and not args.file:
    print("Tracing SCTP RTO... Ctrl+C to end")
elif args.file:
    # Write CSV header to file
    print(f"Tracing SCTP RTO to file '{args.file}'... Ctrl+C to end")
    writer.writerow(["transport_id", "ip_address", "port", "rto_ms", "srtt_ms", "rttvar_ms"])
else:
    # CSV to stdout, header already printed
    print("Tracing SCTP RTO to stdout in CSV format... Ctrl+C to end")
    print("transport_id,ip_address,port,rto_ms,srtt_ms,rttvar_ms")

try:
    while True:
        b.perf_buffer_poll()
        sleep(0.1)
except KeyboardInterrupt:
    print("\nTracing completed.")
finally:
    if csvfile:
        csvfile.close()