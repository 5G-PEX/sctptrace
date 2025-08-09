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
import csv
import os

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
"""

# Stream event structure
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

class SCTPStreamTracer:
    def __init__(self, interval=5, csv_output=False, output_file=None):
        self.interval = interval
        self.csv_output = csv_output
        self.output_file = output_file
        self.b = None
        self.csvfile = None
        self.writer = None
        # Keep original variable name for association tracking
        self.associations = {}  # (assoc_id) -> {stream_id -> StreamStats}
        self._setup_complete = False
        
    def setup(self):
        if self._setup_complete:
            return
            
        # Load BPF program
        self.b = BPF(text=bpf_text)
        
        # Setup CSV file and writer if requested
        if self.output_file:
            output_dir = os.path.dirname(self.output_file)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir)
                
            self.csvfile = open(self.output_file, "w", newline="")
            self.writer = csv.writer(self.csvfile)
            self.writer.writerow([
                "assoc_id", 
                "total_streams", 
                "active_streams", 
                "total_bytes", 
                "total_chunks", 
                "ordered", 
                "unordered", 
                "sui", 
                "stream_parallelism"
            ])
        
        # Set up perf buffer for events
        self.b["stream_events"].open_perf_buffer(self._process_stream_event)
        self._setup_complete = True
        
    def _process_stream_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(StreamEvent)).contents
        
        # Track per-stream stats
        assoc_key = (event.association_id)
        if assoc_key not in self.associations:
            self.associations[assoc_key] = defaultdict(StreamStats)
        
        stream_stats = self.associations[assoc_key][event.stream_id]
        stream_stats.update(event.data_bytes, event.is_unordered)
    
    def poll_events(self, timeout=None):
        """Poll for events with optional timeout (in ms)"""
        if not self._setup_complete:
            self.setup()
        if timeout is None:
            timeout = self.interval * 1000
        self.b.perf_buffer_poll(timeout=timeout)
    
    # Calculate stream utilisation index (entropy-based measure)
    # Keeping the original function
    def calculate_sui(self, stream_bytes):
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
    
    def get_summary(self):
        """Return summary statistics for collected data"""
        results = []
        for assoc_id, streams in sorted(self.associations.items()):
            # Calculate total statistics
            total_streams = len(streams)
            active_streams = sum(1 for stats in streams.values() if stats.bytes_sent > 0)
            total_bytes = sum(stats.bytes_sent for stats in streams.values())
            total_chunks = sum(stats.chunks_sent for stats in streams.values())
            ordered_chunks = sum(stats.ordered_chunks for stats in streams.values())
            unordered_chunks = sum(stats.unordered_chunks for stats in streams.values())
            
            # Get bytes per stream for SUI calculation
            stream_bytes = {stream_id: stats.bytes_sent for stream_id, stats in streams.items()}
            sui = self.calculate_sui(stream_bytes)
            
            # Calculate stream parallelism (% of streams that are active)
            stream_parallelism = (active_streams / total_streams * 100) if total_streams > 0 else 0
            
            results.append({
                'assoc_id': assoc_id,
                'total_streams': total_streams,
                'active_streams': active_streams,
                'total_bytes': total_bytes,
                'total_chunks': total_chunks,
                'ordered_chunks': ordered_chunks,
                'unordered_chunks': unordered_chunks,
                'sui': sui,
                'stream_parallelism': stream_parallelism
            })
        return results
    
    def print_summary(self):
        """Print or write summary data based on output mode"""
        results = self.get_summary()
        
        if not results:
            return
            
        for result in results:
            if self.csv_output or self.output_file:
                row = [
                    result['assoc_id'],
                    result['total_streams'],
                    result['active_streams'],
                    result['total_bytes'],
                    result['total_chunks'],
                    result['ordered_chunks'],
                    result['unordered_chunks'],
                    f"{result['sui']:.4f}",
                    f"{result['stream_parallelism']:.1f}"
                ]
                if self.output_file:
                    self.writer.writerow(row)
                elif self.csv_output:
                    print(",".join(map(str, row)))
            else:
                # Plain text output
                print(f"Association {result['assoc_id']}:")
                print(f"  Streams: {result['active_streams']} active out of {result['total_streams']} total")
                print(f"  Data: {result['total_bytes']} bytes across {result['total_chunks']} chunks")
                print(f"  Ordering: {result['ordered_chunks']} ordered, {result['unordered_chunks']} unordered")
                print(f"  Stream Utilization Index: {result['sui']:.4f}")
                print(f"  Stream Parallelism: {result['stream_parallelism']:.1f}%")
    
    def cleanup(self):
        """Clean up resources"""
        if self.csvfile:
            self.csvfile.close()

def parse_args():
    # Parse command line arguments - keeping same args
    parser = argparse.ArgumentParser(
        description="Analyze SCTP stream utilisation")
    parser.add_argument("-i", "--interval", type=int, default=5,
        help="summary interval, in seconds")
    parser.add_argument("-c", "--csv", action="store_true", help="Output in CSV format")
    parser.add_argument(
        "-f", "--file", metavar="FILE", help="Write output to a specified file"
    )
    return parser.parse_args()

def signal_handler(signal, frame, tracer):
    tracer.print_summary()
    tracer.cleanup()
    print("\nTracing completed.")
    exit()

def main():
    args = parse_args()
    
    tracer = SCTPStreamTracer(
        interval=args.interval,
        csv_output=args.csv,
        output_file=args.file
    )
    tracer.setup()
    
    # Set up signal handler for clean exit
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, tracer))
    
    if args.csv:
        # CSV to stdout, header already printed
        print("Tracing SCTP RTT to stdout in CSV format... Ctrl+C to end")
        print("assoc_id,total_streams,active_streams,total_bytes,total_chunks,ordered,unordered,sui,stream_parallelism")
    else:
        # Write CSV header to file
        print(f"Tracing SCTP stream utilization... Ctrl+C to end")
    
    # Main loop
    try:
        while True:
            tracer.poll_events()
            sleep(args.interval)
            # Only print summaries in standalone mode at interval
            if not args.csv and not args.file:
                tracer.print_summary()
    except KeyboardInterrupt:
        signal_handler(0, 0, tracer)

if __name__ == "__main__":
    main()