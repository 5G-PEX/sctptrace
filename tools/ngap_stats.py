#!/usr/bin/python3
"""
ngap_stats.py - Track NGAP message types and counts in SCTP traffic.

This tool traces SCTP data chunks and extracts NGAP message types to provide
statistics on the different procedures exchanged between gNB and core network.

USAGE: ngap_stats.py [-h] [-i INTERVAL] [-d]

Copyright (c) 2025 Tariro Mukute
Licensed under the Apache License, Version 2.0
"""

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import signal
import socket
import struct
from collections import defaultdict
from ngap_procedure_codes import NGAP_PROCEDURE_CODES, NGAP_DIRECTION

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="Track NGAP message statistics in SCTP traffic")
parser.add_argument("-i", "--interval", type=int, default=5,
    help="summary interval, in seconds")
parser.add_argument("-4", "--filter-ipv4", type=str, default="",
    help="filter by IPv4 address (e.g., 192.168.70.140)")
parser.add_argument("-d", "--detail", action="store_true",
    help="show detailed message type information")
parser.add_argument("-c", "--count", type=int, default=0,
    help="number of outputs before exit")
args = parser.parse_args()

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <net/sctp/sctp.h>

// NGAP uses SCTP port 38412
#define NGAP_PORT 38412

// NGAP PPID in SCTP
#define NGAP_PPID 60

// Direction flags
#define DIR_UNKNOWN 0
#define DIR_UPLINK  1
#define DIR_DOWNLINK 2

struct ngap_event_t {
    u32 procedure_code;
    // TODO: support IPv6
    u32 ipv4_addr; // IPv4 address if available
    u32 direction;  // 1=UL, 2=DL
    u32 message_type; // Initiating, Successful, Unsuccessful
    u32 data_length;
    u64 timestamp;
};

BPF_PERF_OUTPUT(ngap_events);

// Track NGAP message statistics
BPF_HASH(ngap_stats, u64, u32, 1024);  // (procedure_code << 32) | direction -> count

// Function to extract NGAP procedure code from payload
static __always_inline u32 extract_ngap_procedure_code(void *data, u32 len) {
    // NGAP messages start with a message type field
    // Then have a procedure code field (typically at offset 2-3)
    // This is a simplification - actual ASN.1 PER would require more complex parsing
    if (len < 4)
        return 0;
    
    // Extract procedure code - simplistic approach
    // For real implementation, proper ASN.1 PER parsing would be needed
    u8 first_byte;
    bpf_probe_read(&first_byte, sizeof(first_byte), data);
    
    // Check if it's an NGAP PDU
    if ((first_byte & 0xC0) != 0) // First two bits should be 00 for NGAP
        return 0;
    
    // Extract procedure code from offset 2-3
    u8 procedure_code = 0;
    bpf_probe_read(&procedure_code, sizeof(procedure_code), data + 1);
    
    // Convert from network byte order and extract just the procedure code
    return procedure_code;
}

// Helper to get message type (initiating, successful, unsuccessful)
static __always_inline u32 extract_ngap_message_type(void *data, u32 len) {
    if (len < 1)
        return 0;
    
    // Message type is encoded in the first byte
    u8 first_byte;
    bpf_probe_read(&first_byte, sizeof(first_byte), data);
    
    // Extract message type from bits 6-7
    return (first_byte >> 6) & 0x03;
}

static struct sctp_datahdr *sctp_sm_pull_data(struct sctp_chunk *chunk) {
    // This function pulls the SACK header from the chunk.
    struct sk_buff *skb = NULL;
    bpf_probe_read(&skb, sizeof(skb), &chunk->skb);
    if (!skb) {
        bpf_trace_printk("NULL skb pointer in SACK chunk\\n");
        return NULL;
    }
    struct sctp_datahdr *data_hdr = NULL;
    bpf_probe_read(&data_hdr, sizeof(data_hdr), &skb->data);
    if (!data_hdr) {
        bpf_trace_printk("NULL data_hdr pointer in SACK chunk\\n");
        return NULL;
    }

    return data_hdr;
}

// Process incoming SCTP data chunks
int kprobe__sctp_eat_data(struct pt_regs *ctx, const struct sctp_association *asoc,
                          struct sctp_chunk *chunk,
                          struct sctp_cmd_seq *commands) {
    bpf_trace_printk("In eat data\\n");
    struct ngap_event_t event = {};
    
    // Check for null chunk
    if (!chunk) 
        return 0;

    event.timestamp = bpf_ktime_get_ns();
    event.direction = DIR_UNKNOWN;
    
    // Pull the Data header
    struct sctp_datahdr *data_hdr = sctp_sm_pull_data(chunk);
    if (!data_hdr) {
        bpf_trace_printk("EAT DATA: NULL data_hdr pointer\\n");
        return 0;
    }

    // Assume data length is greater than 4 
    // TODO: Fetch data length from chunk header
    u32 data_length = 16; // Placeholder, should be actual length
    
     // Get PPID to verify it's NGAP
    u32 ppid;
    bpf_probe_read(&ppid, sizeof(ppid), &data_hdr->ppid);
    
    ppid = ntohl(ppid);
    // Check if it's NGAP (PPID 60) - simplified check
    if (ppid != NGAP_PPID) {
        bpf_trace_printk("EAT DATA: Not NGAP PPID: %d\\n", ppid);
        return 0;
    }
    
    bpf_trace_printk("EAT DATA: NGAP PPID confirmed\\n");

    // Determine direction based on port numbers
    // Get association from packet's transport
    struct sctp_transport *transport_ptr = NULL;
    bpf_probe_read(&transport_ptr, sizeof(transport_ptr), &asoc->peer.primary_path);
    if (!transport_ptr) {
        bpf_trace_printk("EAT DATA: NULL transport pointer in DATA chunk\\n");
        return 0;
    }

    // Try to get IP address info for better identification
    // Read the address family first to determine IPv4 or IPv6
    u16 family;
    bpf_probe_read(&family, sizeof(family), &transport_ptr->ipaddr.sa.sa_family);
    
    if (family == AF_INET) {
        // For IPv4
        bpf_probe_read(&event.ipv4_addr, sizeof(event.ipv4_addr), &transport_ptr->ipaddr.v4.sin_addr.s_addr);
    }

    FILTER_IPV4

    // Check port numbers
    // For simplicity we use a heuristic: 
    // - If local port is NGAP_PORT, it's downlink (core -> gNB)
    // - If peer port is NGAP_PORT, it's uplink (gNB -> core)
    u16 peer_port = 0;
    bpf_probe_read(&peer_port, sizeof(peer_port), &asoc->peer.port);
    if (peer_port == NGAP_PORT) {
        event.direction = DIR_DOWNLINK;  // From gNB to core
    } 
    // else {
    //     event.direction = DIR_UPLINK; // From core to gNB
    // }

    bpf_trace_printk("EAT DATA: Direction determined: %d\\n", event.direction);
    
     // Get pointer to data payload
    __u8 *payload_ptr = (__u8 *)(data_hdr + 1);
    
    // Extract NGAP procedure code
    event.procedure_code = extract_ngap_procedure_code(payload_ptr, data_length);
    if (event.procedure_code == 0) {
        bpf_trace_printk("EAT DATA: Not a valid NGAP message\\n");
        return 0;  // Not a valid NGAP message
    }

    bpf_trace_printk("EAT DATA: NGAP procedure code: %d\\n", event.procedure_code);
        
    // Get message type
    event.message_type = extract_ngap_message_type(payload_ptr, data_length);
    
    // Update statistics
    u64 key = ((u64)event.procedure_code << 48) | ((u64)event.direction << 32) | event.ipv4_addr;
    u32 *count = ngap_stats.lookup(&key);
    u32 val = 1;
    if (count) 
        val += *count;
    ngap_stats.update(&key, &val);
    
    // Submit event
    ngap_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Process outgoing SCTP data chunks
int kprobe__sctp_packet_transmit_chunk(struct pt_regs *ctx, 
                                       struct sctp_packet *packet,
                                       struct sctp_chunk *chunk,
                                       int one_packet, gfp_t gfp) {
    bpf_trace_printk("In transmit chunk\\n");
    struct ngap_event_t event = {};

    if (!chunk || !packet) 
        return 0;

    event.timestamp = bpf_ktime_get_ns();
    event.direction = DIR_UNKNOWN;
    
    struct sctp_chunkhdr *chunk_hdr;
    bpf_probe_read(&chunk_hdr, sizeof(chunk_hdr), &chunk->chunk_hdr);
    if (!chunk_hdr) {
        bpf_trace_printk("NULL chunk header pointer in DATA chunk\\n");
        return 0;
    }

    u8 chunk_type;
    bpf_probe_read(&chunk_type, sizeof(chunk_type), &chunk_hdr->type);
    if (chunk_type != SCTP_CID_DATA)  // Not a DATA chunk
        return 0;
    
    bpf_trace_printk("Processing DATA chunk\\n");

    // Get the data portion of the chunk
    struct sctp_datahdr *data_hdr = NULL;
    bpf_probe_read(&data_hdr, sizeof(data_hdr), &chunk->subh.data_hdr);
    if (!data_hdr) {
        bpf_trace_printk("NULL data header pointer in DATA chunk\\n");
        return 0;
    }
    
    // Get data length (chunk length - header size)
    __be16 chunk_length;
    bpf_probe_read(&chunk_length, sizeof(chunk_length), &chunk_hdr->length);
    u32 data_length = chunk_length - 16;
    event.data_length = data_length;
    
    // Get PPID to verify it's NGAP
    u32 ppid;
    bpf_probe_read(&ppid, sizeof(ppid), &data_hdr->ppid);
    
    ppid = ntohl(ppid);
    // Check if it's NGAP (PPID 60) - simplified check
    if (ppid != NGAP_PPID) {
        bpf_trace_printk("Not NGAP PPID: %d\\n", ppid);
        return 0;
    }
    
    bpf_trace_printk("NGAP PPID confirmed\\n");

    // Determine direction based on port numbers
    // Get association from packet's transport
    struct sctp_transport *transport_ptr = NULL;
    bpf_probe_read(&transport_ptr, sizeof(transport_ptr), &packet->transport);
    if (!transport_ptr) {
        bpf_trace_printk("NULL transport pointer in DATA chunk\\n");
        return 0;
    }

    struct sctp_association *asoc = NULL;
    bpf_probe_read(&asoc, sizeof(asoc), &transport_ptr->asoc);
    if (!asoc) {
        bpf_trace_printk("NULL association pointer in DATA chunk\\n");
        return 0;
    }

    bpf_trace_printk("Association pointer obtained\\n");

    // Try to get IP address info for better identification
    // Read the address family first to determine IPv4 or IPv6
    u16 family;
    bpf_probe_read(&family, sizeof(family), &transport_ptr->ipaddr.sa.sa_family);
    
    if (family == AF_INET) {
        // For IPv4
        bpf_probe_read(&event.ipv4_addr, sizeof(event.ipv4_addr), &transport_ptr->ipaddr.v4.sin_addr.s_addr);
    }

    FILTER_IPV4

    // Check port numbers
    // For simplicity we use a heuristic: 
    // - If local port is NGAP_PORT, it's downlink (core -> gNB)
    // - If peer port is NGAP_PORT, it's uplink (gNB -> core)
    u16 peer_port = 0;
    bpf_probe_read(&peer_port, sizeof(peer_port), &asoc->peer.port);
    if (peer_port == NGAP_PORT) {
        event.direction = DIR_UPLINK;  // From core to gNB
    } 
    // else {
    //     event.direction = DIR_UPLINK; // From gNB to core
    // }

    bpf_trace_printk("Direction determined: %d\\n", event.direction);

    // Get pointer to data payload
    __u8 *payload_ptr = (__u8 *)(data_hdr + 1);
    
    // Extract NGAP procedure code
    event.procedure_code = extract_ngap_procedure_code(payload_ptr, data_length);
    if (event.procedure_code == 0) {
        bpf_trace_printk("Not a valid NGAP message\\n");
        return 0;  // Not a valid NGAP message
    }

    bpf_trace_printk("NGAP procedure code: %d\\n", event.procedure_code);
        
    // Get message type
    event.message_type = extract_ngap_message_type(payload_ptr, data_length);
    
    bpf_trace_printk("NGAP message type: %d\\n", event.message_type);

    // Update statistics
    u64 key = ((u64)event.procedure_code << 48) | ((u64)event.direction << 32) | event.ipv4_addr;
    bpf_trace_printk("Stats key: %llx\\n", key);
    u32 *count = ngap_stats.lookup(&key);
    u32 val = 1;
    if (count) 
        val += *count;
    ngap_stats.update(&key, &val);
    bpf_trace_printk("Updated stats count: %d\\n", val);
    
    // Submit event
    ngap_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Apply IPv4 filter if specified
if args.filter_ipv4:
    try:
        ipv4_addr = struct.unpack("<I", socket.inet_aton(args.filter_ipv4))[0]
        filter_code = f"""
        if (event.ipv4_addr != {ipv4_addr}) {{
            return 0;
        }}
        """
        bpf_text = bpf_text.replace("FILTER_IPV4", filter_code)
    except socket.error:
        print(f"Invalid IPv4 address: {args.filter_ipv4}")
        exit(1)
else:
    bpf_text = bpf_text.replace("FILTER_IPV4", "")

# Load BPF program
b = BPF(text=bpf_text)

# NGAP event structure
class NGAPEvent(ct.Structure):
    _fields_ = [
        ("procedure_code", ct.c_uint),
        ("ipv4_addr", ct.c_uint),
        ("direction", ct.c_uint),
        ("message_type", ct.c_uint),
        ("data_length", ct.c_uint),
        ("timestamp", ct.c_ulonglong),
    ]

# Direction strings
direction_str = {
    0: "Unknown",
    1: "Uplink (gNB→Core)",
    2: "Downlink (Core→gNB)"
}

# Message type strings
message_type_str = {
    0: "Unknown",
    1: "Initiating",
    2: "Successful Outcome",
    3: "Unsuccessful Outcome"
}

# Track NGAP message counts
ngap_counts = defaultdict(int)  # (procedure_code, direction) -> count
message_details = defaultdict(lambda: defaultdict(int))  # procedure_code -> message_type -> count

print("Tracing NGAP messages in SCTP traffic... Hit Ctrl-C to end")
if args.detail:
    print("%-20s %-25s %-20s %-6s" % 
          ("PROCEDURE", "DIRECTION", "MESSAGE TYPE", "SIZE"))

# Process NGAP events
def process_ngap_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(NGAPEvent)).contents
    
    key = (event.procedure_code, event.ipv4_addr, event.direction)
    ngap_counts[key] += 1
    
    # Update message type details. The key now includes the ipv4_addr
    msg_detail_key = (event.procedure_code, event.ipv4_addr)
    message_details[msg_detail_key][event.message_type] += 1
    
    # Print details if requested
    if args.detail:
        proc_name = NGAP_PROCEDURE_CODES.get(event.procedure_code, f"Unknown ({event.procedure_code})")
        dir_name = direction_str.get(event.direction, "Unknown")
        msg_type = message_type_str.get(event.message_type, "Unknown")
        
        # Convert IPv4 address from integer to a readable string
        ipv4_str = socket.inet_ntoa(struct.pack("<I", event.ipv4_addr))
        
        print("%-30s %-15s %-25s %-20s %-6d" % 
              (proc_name, ipv4_str, dir_name, msg_type, event.data_length))

b["ngap_events"].open_perf_buffer(process_ngap_event)

# Print NGAP statistics summary
def print_summary():
    timestamp = strftime("%H:%M:%S")
    print(f"\n=== NGAP Message Statistics at {timestamp} ===\n")
    
    # Group by procedure and IP address
    by_procedure_and_ip = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for (proc_code, ipv4_addr, direction), count in sorted(ngap_counts.items()):
        by_procedure_and_ip[proc_code][ipv4_addr][direction] += count
    
    # Print summary table
    print("%-30s %-16s %-15s %-15s %-15s" % 
          ("PROCEDURE", "IP ADDRESS", "UPLINK", "DOWNLINK", "TOTAL"))
    print("-" * 91) # Adjusted line length
    
    total_ul = 0
    total_dl = 0
    for proc_code, ip_addresses in sorted(by_procedure_and_ip.items()):
        proc_name = NGAP_PROCEDURE_CODES.get(proc_code, f"Unknown ({proc_code})")
        
        for ipv4_addr, directions in sorted(ip_addresses.items()):
            # Convert IPv4 address from integer to a readable string
            ipv4_str = socket.inet_ntoa(struct.pack("<I", ipv4_addr))
            
            ul_count = directions.get(1, 0)  # Uplink
            dl_count = directions.get(2, 0)  # Downlink
            total = ul_count + dl_count
            
            total_ul += ul_count
            total_dl += dl_count
            
            print("%-30s %-16s %-15d %-15d %-15d" % 
                  (proc_name, ipv4_str, ul_count, dl_count, total))
    
    # Print totals
    print("-" * 91)
    print("%-47s %-15d %-15d %-15d" % 
          ("TOTAL", total_ul, total_dl, total_ul + total_dl))
    
    # Print message type details if we have any
    if message_details and args.detail:
        print("\n=== Message Type Details ===\n")
        print("%-30s %-15s %-15s %-15s" % 
              ("PROCEDURE", "INITIATING", "SUCCESSFUL", "UNSUCCESSFUL"))
        print("-" * 80)
        
        for proc_code, msg_types in sorted(message_details.items()):
            proc_name = NGAP_PROCEDURE_CODES.get(proc_code, f"Unknown ({proc_code})")
            init_count = msg_types.get(1, 0)  # Initiating
            succ_count = msg_types.get(2, 0)  # Successful
            unsucc_count = msg_types.get(3, 0)  # Unsuccessful
            
            print("%-30s %-15d %-15d %-15d" % 
                  (proc_name, init_count, succ_count, unsucc_count))

# Cleanup on keyboard interrupt
def signal_handler(signal, frame):
    print_summary()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop with periodic summaries
count = 0
while True:
    try:
        sleep(args.interval)
        b.perf_buffer_poll(0)
        print_summary()
        
        count += 1
        if args.count and count >= args.count:
            exit(0)
    except KeyboardInterrupt:
        signal_handler(0, 0)
        exit()