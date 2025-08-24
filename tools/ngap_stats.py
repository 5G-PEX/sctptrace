#!/usr/bin/python3
"""
ngap_stats.py - Track NGAP message types and counts in SCTP traffic.

This tool traces SCTP data chunks and extracts NGAP message types to provide
statistics on the different procedures exchanged between gNB and core network.

USAGE: ngap_stats.py [-h] [-i INTERVAL] [-d]

Copyright (c) 2023 5G Research Lab
Licensed under the Apache License, Version 2.0
"""

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import signal
from collections import defaultdict
from ngap_procedure_codes import NGAP_PROCEDURE_CODES, NGAP_DIRECTION

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="Track NGAP message statistics in SCTP traffic")
parser.add_argument("-i", "--interval", type=int, default=5,
    help="summary interval, in seconds")
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

// Process incoming SCTP data chunks
int kprobe__sctp_sf_eat_data_6_2(struct pt_regs *ctx) {
    struct ngap_event_t event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.direction = DIR_UNKNOWN;
    
    // For sctp_sf_eat_data_6_2, arguments include chunk and association
    // The DATA chunk is typically the second argument
    void *chunk_ptr = (void *)PT_REGS_PARM2(ctx);
    if (!chunk_ptr) 
        return 0;
    
    // Verify it's a DATA chunk (type 0)
    u8 chunk_type;
    bpf_probe_read(&chunk_type, sizeof(chunk_type), chunk_ptr);
    if (chunk_type != 0)  // Not a DATA chunk
        return 0;
    
    // Get the data portion of the chunk
    // DATA chunk format: [1 byte type][1 byte flags][2 bytes length][4 bytes TSN]
    //                    [2 bytes stream id][2 bytes stream seq][4 bytes ppid][data...]
    void *data_ptr = chunk_ptr + 16;  // Skip the header
    
    // Get data length (chunk length - header size)
    u16 chunk_length;
    bpf_probe_read(&chunk_length, sizeof(chunk_length), chunk_ptr + 2);
    u32 data_length = chunk_length - 16;
    event.data_length = data_length;
    
    // Get PPID to verify it's NGAP
    u32 ppid;
    bpf_probe_read(&ppid, sizeof(ppid), chunk_ptr + 12);
    
    // Check if it's NGAP (PPID 60) - simplified check
    if (ppid != NGAP_PPID) 
        return 0;
    
    // Determine direction based on port numbers
    // Get association from first argument
    void *asoc_ptr = (void *)PT_REGS_PARM1(ctx);
    if (asoc_ptr) {
        // Get socket from association
        void *sk_ptr;
        bpf_probe_read(&sk_ptr, sizeof(sk_ptr), asoc_ptr + 8); // Offset to sk pointer
        if (sk_ptr) {
            // Check port numbers
            // For simplicity we use a heuristic: 
            // - If local port is NGAP_PORT, it's downlink (core -> gNB)
            // - If peer port is NGAP_PORT, it's uplink (gNB -> core)
            u16 local_port = 0, peer_port = 0;
            bpf_probe_read(&local_port, sizeof(local_port), sk_ptr + 14); // sk->sk_num
            // Peer port is harder to get directly, this is simplified
            
            if (local_port == NGAP_PORT) {
                event.direction = DIR_DOWNLINK;
            } else {
                event.direction = DIR_UPLINK;  // Default if we can't determine
            }
        }
    }
    
    // Extract NGAP procedure code
    event.procedure_code = extract_ngap_procedure_code(data_ptr, data_length);
    if (event.procedure_code == 0)
        return 0;  // Not a valid NGAP message
        
    // Get message type
    event.message_type = extract_ngap_message_type(data_ptr, data_length);
    
    // Update statistics
    u64 key = ((u64)event.procedure_code << 32) | event.direction;
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

    // Check port numbers
    // For simplicity we use a heuristic: 
    // - If local port is NGAP_PORT, it's downlink (core -> gNB)
    // - If peer port is NGAP_PORT, it's uplink (gNB -> core)
    u16 peer_port = 0;
    bpf_probe_read(&peer_port, sizeof(peer_port), &asoc->peer.port);
    if (peer_port == NGAP_PORT) {
        event.direction = DIR_UPLINK;  // From gNB to core
    } else {
        event.direction = DIR_DOWNLINK; // From core to gNB
    }

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
    u64 key = ((u64)event.procedure_code << 32) | event.direction;
    u32 *count = ngap_stats.lookup(&key);
    u32 val = 1;
    if (count) 
        val += *count;
    ngap_stats.update(&key, &val);
    
    // Submit event
    ngap_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# NGAP event structure
class NGAPEvent(ct.Structure):
    _fields_ = [
        ("procedure_code", ct.c_uint),
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
    
    # Update counts
    key = (event.procedure_code, event.direction)
    ngap_counts[key] += 1
    
    # Update message type details
    message_details[event.procedure_code][event.message_type] += 1
    
    # Print details if requested
    if args.detail:
        proc_name = NGAP_PROCEDURE_CODES.get(event.procedure_code, f"Unknown ({event.procedure_code})")
        dir_name = direction_str.get(event.direction, "Unknown")
        msg_type = message_type_str.get(event.message_type, "Unknown")
        
        print("%-8d %-20s %-25s %-20s %-6d" % 
              (proc_name, dir_name, msg_type, event.data_length))

b["ngap_events"].open_perf_buffer(process_ngap_event)

# Print NGAP statistics summary
def print_summary():
    timestamp = strftime("%H:%M:%S")
    print(f"\n=== NGAP Message Statistics at {timestamp} ===\n")
    
    # Group by procedure
    by_procedure = defaultdict(lambda: defaultdict(int))
    for (proc_code, direction), count in sorted(ngap_counts.items()):
        by_procedure[proc_code][direction] += count
    
    # Print summary table
    print("%-30s %-15s %-15s %-15s" % 
          ("PROCEDURE", "UPLINK", "DOWNLINK", "TOTAL"))
    print("-" * 80)
    
    total_ul = 0
    total_dl = 0
    for proc_code, directions in sorted(by_procedure.items()):
        proc_name = NGAP_PROCEDURE_CODES.get(proc_code, f"Unknown ({proc_code})")
        ul_count = directions.get(1, 0)  # Uplink
        dl_count = directions.get(2, 0)  # Downlink
        total = ul_count + dl_count
        
        total_ul += ul_count
        total_dl += dl_count
        
        print("%-30s %-15d %-15d %-15d" % 
              (proc_name, ul_count, dl_count, total))
    
    # Print totals
    print("-" * 80)
    print("%-30s %-15d %-15d %-15d" % 
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