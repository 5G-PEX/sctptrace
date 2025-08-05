#!/usr/bin/python3
"""
sctp_rtt.py - Measure SCTP Round Trip Time (RTT) for data transmissions.

This tool traces SCTP packet transmissions and SACK processing to calculate
the RTT between data chunk transmission and acknowledgment, organized by association ID.

USAGE: sctp_rtt.py [-h] [-p PID] [-i INTERVAL]

"""

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import signal

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="Measure SCTP Round Trip Time (RTT)")
parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
parser.add_argument("-i", "--interval", type=int, default=1,
    help="output interval, in seconds")
args = parser.parse_args()

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <net/sctp/sctp.h>

// Forward declaration for visibility
struct sctp_cmd_seq;

struct packet_key_t {
    u32 tsn;            // Transmission Sequence Number for SCTP
    u32 assoc_id;       // SCTP Association ID
};

struct rtt_event_t {
    u32 tsn;
    u32 assoc_id;
    u64 send_time;
    u64 recv_time;
    u64 rtt_ns;
    u32 pid;           // Keep PID for filtering
};

BPF_HASH(packets, struct packet_key_t, u64, 10240);
BPF_PERF_OUTPUT(rtt_events);

// Probe for outgoing packets with updated signature
int kprobe__sctp_packet_transmit(struct pt_regs *ctx, struct sctp_packet *packet, gfp_t gfp) {

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    FILTER_PID

    if (!packet) 
        return 0;
    
    // Get the association
    struct sctp_transport *transport_ptr = NULL;
    bpf_probe_read(&transport_ptr, sizeof(transport_ptr), &packet->transport);
    if (!transport_ptr) {
        bpf_trace_printk("NULL transport pointer\\n");
        return 0;
    }

    struct sctp_association *asoc = NULL;
    bpf_probe_read(&asoc, sizeof(asoc), &transport_ptr->asoc);
    if (!asoc)
        return 0;
    
    // Extract TSN from packet/chunk structure
    struct list_head chunk_list_head;
    bpf_probe_read(&chunk_list_head, sizeof(chunk_list_head), &packet->chunk_list);

    struct sctp_chunk *chunk = NULL;
   
    // TODO: Read and iterate through the chunk list

    void *chunk_next_ptr = NULL;
    bpf_probe_read(&chunk_next_ptr, sizeof(chunk_next_ptr), &chunk_list_head.next);
    chunk = (struct sctp_chunk *)chunk_next_ptr;

    if (!chunk) {
        bpf_trace_printk("NULL chunk pointer\\n");
        return 0;
    }
    
    // For DATA chunks, extract the TSN
    struct sctp_chunkhdr *chunk_hdr_ptr = NULL;
    bpf_probe_read(&chunk_hdr_ptr, sizeof(chunk_hdr_ptr), &chunk->chunk_hdr);
    if (!chunk_hdr_ptr) {
        bpf_trace_printk("NULL chunk_hdr_ptr\\n");
        return 0;
    }

    u8 chunk_type;
    bpf_probe_read(&chunk_type, sizeof(chunk_type), &chunk_hdr_ptr->type);
    
    if (chunk_type == SCTP_CID_DATA) {
        struct packet_key_t pkt = {};
        
        struct sctp_datahdr *data_hdr_ptr = NULL;
        bpf_probe_read(&data_hdr_ptr, sizeof(data_hdr_ptr), &chunk->subh.data_hdr);
        if (!data_hdr_ptr) {
            bpf_trace_printk("NULL data_hdr_ptr\\n");
            return 0;
        }

        // Read TSN from the data chunk header
        __be32 tsn;
        bpf_probe_read(&tsn, sizeof(tsn), &data_hdr_ptr->tsn);
        
        pkt.tsn = ntohl(tsn);

        // Read association ID
        bpf_probe_read(&pkt.assoc_id, sizeof(pkt.assoc_id), &asoc->assoc_id);

        // Add packet to hash with current time
        u64 send_time = bpf_ktime_get_ns();
        packets.update(&pkt, &send_time);
    }
    
    return 0;
}

static struct sctp_sackhdr *sctp_sm_pull_sack(struct sctp_chunk *chunk) {
    // This function pulls the SACK header from the chunk.
    struct sk_buff *skb = NULL;
    bpf_probe_read(&skb, sizeof(skb), &chunk->skb);
    if (!skb) {
        bpf_trace_printk("NULL skb pointer in SACK chunk\\n");
        return NULL;
    }
    struct sctp_sackhdr *sack_hdr = NULL;
    bpf_probe_read(&sack_hdr, sizeof(sack_hdr), &skb->data);
    if (!sack_hdr) {
        bpf_trace_printk("NULL sack_hdr pointer in SACK chunk\\n");
        return NULL;
    }

    return sack_hdr;
}

// Probe for incoming SACK processing with updated signature
int kprobe__sctp_sf_eat_sack_6_2(struct pt_regs *ctx) {
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    FILTER_PID
    
    // Extract SACK chunk from the 5th argument (r8)
    struct sctp_chunk *chunk = (struct sctp_chunk *)PT_REGS_PARM5(ctx);
    if (!chunk) {
        bpf_trace_printk("NULL SACK chunk pointer\\n");
        return 0;
    }
    
    struct sctp_chunkhdr *chunk_hdr_ptr = NULL;
    bpf_probe_read(&chunk_hdr_ptr, sizeof(chunk_hdr_ptr), &chunk->chunk_hdr);
    if (!chunk_hdr_ptr) {
        bpf_trace_printk("NULL chunk_hdr_ptr\\n");
        return 0;
    }

    u8 chunk_type;
    bpf_probe_read(&chunk_type, sizeof(chunk_type), &chunk_hdr_ptr->type);
    
    if (chunk_type != SCTP_CID_SACK) {
        bpf_trace_printk("Not a SACK chunk (type %d), skipping\\n", chunk_type);
        return 0;
    }
    
    // Pull the SACK header
    struct sctp_sackhdr *sack_hdr = sctp_sm_pull_sack(chunk);
    if (!sack_hdr) {
        bpf_trace_printk("Failed to pull SACK header\\n");
        return 0;
    }

    __be32 cum_tsn_ack;
    bpf_probe_read(&cum_tsn_ack, sizeof(cum_tsn_ack), &sack_hdr->cum_tsn_ack);

    __u32 tsn = ntohl(cum_tsn_ack); 

    // Get association pointer from the 3rd argument
    struct sctp_association *asoc = (struct sctp_association *)PT_REGS_PARM3(ctx);
    if (!asoc) {
        bpf_trace_printk("NULL association pointer\\n");
        return 0;
    }
    
    // Create key for lookup
    struct packet_key_t pkt = {};
    pkt.tsn = tsn;
    bpf_probe_read(&pkt.assoc_id, sizeof(pkt.assoc_id), &asoc->assoc_id);
    
    u64 *send_time = packets.lookup(&pkt);
    if (send_time) {
        
        struct rtt_event_t event = {};
        event.tsn = pkt.tsn;
        event.assoc_id = pkt.assoc_id;
        event.send_time = *send_time;
        event.recv_time = bpf_ktime_get_ns();
        event.rtt_ns = event.recv_time - event.send_time;
        event.pid = pid;
        
        rtt_events.perf_submit(ctx, &event, sizeof(event));
        packets.delete(&pkt);
    }
    
    return 0;
}
"""

# Set up pid filter if specified
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID',
        'if (pid != %d) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '')

# Load BPF program
b = BPF(text=bpf_text)

# RTT event structure
class RTTEvent(ct.Structure):
    _fields_ = [
        ("tsn", ct.c_uint),
        ("assoc_id", ct.c_uint),
        ("send_time", ct.c_ulonglong),
        ("recv_time", ct.c_ulonglong),
        ("rtt_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
    ]

# RTT calculation
rtt_values = {}  # Now keyed by assoc_id
print("Tracing SCTP RTT... Hit Ctrl-C to end")
print("%-8s %-10s %-10s %-8s" % ("ASSOC", "TSN", "RTT(ms)", "TIME"))

# Process RTT events
def process_rtt_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(RTTEvent)).contents
    rtt_ms = float(event.rtt_ns) / 1000000
    
    if event.assoc_id not in rtt_values:
        rtt_values[event.assoc_id] = []
    
    rtt_values[event.assoc_id].append(rtt_ms)
    
    timestamp = strftime("%H:%M:%S")
    print("%-8d %-10u %-10.3f %-8s" % 
          (event.assoc_id, event.tsn, rtt_ms, timestamp))

b["rtt_events"].open_perf_buffer(process_rtt_event)

# Cleanup on keyboard interrupt
def signal_handler(signal, frame):
    print("\n=== RTT Summary ===")
    for assoc_id, rtts in sorted(rtt_values.items()):
        if rtts:
            avg_rtt = sum(rtts) / len(rtts)
            print(f"Association {assoc_id}:")
            print(f"  Samples: {len(rtts)}")
            print(f"  Average RTT: {avg_rtt:.3f} ms")
            print(f"  Min RTT: {min(rtts):.3f} ms")
            print(f"  Max RTT: {max(rtts):.3f} ms")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop
while True:
    try:
        b.perf_buffer_poll(timeout=args.interval * 1000)
    except KeyboardInterrupt:
        signal_handler(0, 0)
        exit()