#!/usr/bin/python3
"""
sctp_streamutil.py - Analyze SCTP stream utilisation patterns.

This tool traces SCTP packet transmissions to track how data is distributed
across streams, helping identify if applications are effectively leveraging
SCTP's multi-streaming capability.

USAGE: sctp_streamutil.py [-h] [-i INTERVAL]

"""

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import signal
import math
from collections import defaultdict

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="Analyze SCTP stream utilisation")
parser.add_argument("-i", "--interval", type=int, default=5,
    help="summary interval, in seconds")
args = parser.parse_args()

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <net/sctp/sctp.h>

struct stream_data_t {
    u32 association_id;
    u16 stream_id;
    u32 data_bytes;
    u8 is_unordered;
};

BPF_PERF_OUTPUT(stream_events);

// Process chunk transmission with updated signature
int kprobe__sctp_packet_transmit_chunk(struct pt_regs *ctx, 
                                       struct sctp_packet *packet,
                                       struct sctp_chunk *chunk,
                                       int one_packet, gfp_t gfp) {
    struct stream_data_t event = {};
    
    if (!chunk || !packet) 
        return 0;
    
    // Check if it's a DATA chunk (type 0)

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
        
    // Get association ID
    bpf_probe_read(&event.association_id, sizeof(event.association_id), &asoc->assoc_id);
    
    // Extract stream ID directly from the data header
    struct sctp_datahdr *data_hdr = NULL;
    bpf_probe_read(&data_hdr, sizeof(data_hdr), &chunk->subh.data_hdr);
    if (!data_hdr) {
        bpf_trace_printk("NULL data header pointer in DATA chunk\\n");
        return 0;
    }
    // Read stream ID from data header
    __be16 stream_id;
    bpf_probe_read(&stream_id, sizeof(stream_id), &data_hdr->stream);
    event.stream_id = ntohs(stream_id);
    
    // Check if unordered flag is set (bit 2 in flags byte)
    u8 flags;
    bpf_probe_read(&flags, sizeof(flags), &chunk_hdr->flags);
    event.is_unordered = (flags & SCTP_DATA_UNORDERED) ? 1 : 0;
    
    // Get data length from chunk length
    __be16 chunk_length;
    bpf_probe_read(&chunk_length, sizeof(chunk_length), &chunk_hdr->length);

    // Convert from network byte order
    chunk_length = ntohs(chunk_length);
    event.data_bytes = chunk_length - sizeof(struct sctp_chunkhdr);  // Subtract header size
    
    stream_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Also monitor stream initialization to track total streams with updated signature
int kprobe__sctp_stream_init(struct pt_regs *ctx, 
                             struct sctp_stream *stream, 
                             __u16 outcnt, __u16 incnt,
                             gfp_t gfp) {
    // Function signature: sctp_stream_init(struct sctp_stream *stream, u16 outcnt, u16 incnt, gfp_t gfp)
    // Can be used to track max stream count
    
    // For now, we're just tracing packet transmission, but this could be extended
    // to track the number of streams allocated per association.
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)

# Stream data event structure
class StreamEvent(ct.Structure):
    _fields_ = [
        ("association_id", ct.c_uint),
        ("stream_id", ct.c_ushort),
        ("data_bytes", ct.c_uint),
        ("is_unordered", ct.c_ubyte),
    ]

# Stream statistics class
class StreamStats:
    def __init__(self):
        self.bytes_sent = 0
        self.chunks_sent = 0
        self.ordered_chunks = 0
        self.unordered_chunks = 0
        
    def update(self, bytes_sent, is_unordered):
        self.bytes_sent += bytes_sent
        self.chunks_sent += 1
        if is_unordered:
            self.unordered_chunks += 1
        else:
            self.ordered_chunks += 1

# Association statistics
associations = {}  # (assoc_id) -> {stream_id -> StreamStats}

print("Tracing SCTP stream utilisation... Hit Ctrl-C to end")

# Process stream events
def process_stream_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(StreamEvent)).contents
    
    # Track per-stream stats
    assoc_key = (event.association_id)
    if assoc_key not in associations:
        associations[assoc_key] = defaultdict(StreamStats)
    
    stream_stats = associations[assoc_key][event.stream_id]
    stream_stats.update(event.data_bytes, event.is_unordered)

b["stream_events"].open_perf_buffer(process_stream_event)

# Calculate stream utilisation index (entropy-based measure)
def calculate_sui(stream_bytes):
    total_bytes = sum(stream_bytes.values())
    if total_bytes == 0:
        return 0
    
    # Calculate SUI using Shannon entropy
    stream_count = len(stream_bytes)
    if stream_count <= 1:
        return 0
    
    entropy = 0
    for bytes_sent in stream_bytes.values():
        if bytes_sent > 0:
            p = bytes_sent / total_bytes
            entropy -= p * math.log2(p)
    
    # Normalize by maximum possible entropy
    max_entropy = math.log2(stream_count)
    return entropy / max_entropy if max_entropy > 0 else 0

# Print utilisation summary
def print_summary():
    print("\n=== Stream utilisation Summary ===")
    for (assoc_id), streams in sorted(associations.items()):
        print(f"\nAssociation {assoc_id}:")
        
        # Collect stream statistics
        total_bytes = 0
        total_chunks = 0
        stream_bytes = {}
        ordered_vs_unordered = [0, 0]  # [ordered, unordered]
        
        for stream_id, stats in sorted(streams.items()):
            print(f"  Stream {stream_id}: {stats.bytes_sent} bytes, {stats.chunks_sent} chunks "
                  f"({stats.ordered_chunks} ordered, {stats.unordered_chunks} unordered)")
            
            total_bytes += stats.bytes_sent
            total_chunks += stats.chunks_sent
            stream_bytes[stream_id] = stats.bytes_sent
            ordered_vs_unordered[0] += stats.ordered_chunks
            ordered_vs_unordered[1] += stats.unordered_chunks
        
        # Calculate stream utilisation index
        sui = calculate_sui(stream_bytes)
        
        # Calculate stream parallelism
        active_streams = len([b for b in stream_bytes.values() if b > 0])
        stream_parallelism = active_streams / len(streams) if streams else 0
        
        print(f"  Total streams: {len(streams)}, Active streams: {active_streams}")
        print(f"  Total data: {total_bytes} bytes, {total_chunks} chunks")
        print(f"  Ordered vs Unordered ratio: {ordered_vs_unordered[0]}:{ordered_vs_unordered[1]}")
        print(f"  Stream utilisation Index: {sui:.3f} (0=imbalanced, 1=balanced)")
        print(f"  Stream Parallelism: {stream_parallelism:.3f}")

# Cleanup on keyboard interrupt
def signal_handler(signal, frame):
    print_summary()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop with periodic summaries
while True:
    try:
        sleep(args.interval)
        print_summary()
        b.perf_buffer_poll(0)
    except KeyboardInterrupt:
        signal_handler(0, 0)
        exit()