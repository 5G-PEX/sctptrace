#!/usr/bin/python3
"""
sctp_bufmon.py - Monitor SCTP buffer utilisation metrics.

This tool traces SCTP buffer-related functions to measure send buffer utilisation,
outbound queue size, and buffer pressure. It helps identify potential throughput
bottlenecks related to buffer management.

USAGE: sctp_bufmon.py [-h] [-i INTERVAL]
"""

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import signal
from collections import defaultdict
import csv
import os

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <net/sctp/sctp.h>

// Event types to differentiate buffer events
#define EVENT_OUTQ_TAIL     1
#define EVENT_OUTQ_FLUSH    2
#define EVENT_SNDBUF_WAIT   3
#define EVENT_WRITE_SPACE   4

struct buffer_event_t {
    u32 event_type;
    u32 association_id;
    u32 outq_size;     // Size of outqueue
    u32 sndbuf_used;   // Used send buffer
    u32 sndbuf_total;  // Total send buffer size
    u32 rwnd;          // Peer's advertised receive window
    u64 timestamp;
};

BPF_PERF_OUTPUT(buffer_events);

// Hash to track sk_buff pointers per association for querying socket info
BPF_HASH(sock_map, u32, void*, 1024);

// Monitor data being added to outqueue with the correct signature
int kprobe__sctp_outq_tail(struct pt_regs *ctx, struct sctp_outq *q, struct sctp_chunk *chunk, gfp_t gfp) {
    struct buffer_event_t event = {};

    event.event_type = EVENT_OUTQ_TAIL;
    event.timestamp = bpf_ktime_get_ns();
    
    // First argument is sctp_outq
    if (!q) 
        return 0;
    
    // Get association from outqueue
    struct sctp_association *asoc = NULL;
    bpf_probe_read(&asoc, sizeof(asoc), &q->asoc);
    if (!asoc)
        return 0;
    
    // Get association ID
    bpf_probe_read(&event.association_id, sizeof(event.association_id), &asoc->assoc_id);
    
    // Get outqueue size
    bpf_probe_read(&event.outq_size, sizeof(event.outq_size), &q->out_qlen);
    
    // Get rwnd from association
    bpf_probe_read(&event.rwnd, sizeof(event.rwnd), &asoc->peer.rwnd);
    
    // Get socket from association
    struct sock *sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &asoc->base.sk);
    if (!sk)
        return 0;
    
    // Save socket pointer for this association ID
    sock_map.update(&event.association_id, &sk);
    
    // Get socket buffer information
    bpf_probe_read(&event.sndbuf_total, sizeof(event.sndbuf_total), &sk->sk_sndbuf);
    
    // Get used buffer (wmem_alloc)
    u32 wmem_alloc;
    bpf_probe_read(&wmem_alloc, sizeof(wmem_alloc), &sk->sk_wmem_alloc);
    event.sndbuf_used = wmem_alloc;
    
    buffer_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Monitor outqueue flush with the correct signature
int kprobe__sctp_outq_flush(struct pt_regs *ctx, struct sctp_outq *q, int rtx_timeout, gfp_t gfp) {
    struct buffer_event_t event = {};

    event.event_type = EVENT_OUTQ_FLUSH;
    event.timestamp = bpf_ktime_get_ns();
    
    // First argument is sctp_outq
    if (!q) 
        return 0;
    
    // Get association from outqueue
    struct sctp_association *asoc = NULL;
    bpf_probe_read(&asoc, sizeof(asoc), &q->asoc);
    if (!asoc)
        return 0;
    
    // Get association ID
    bpf_probe_read(&event.association_id, sizeof(event.association_id), &asoc->assoc_id);
    
    // Get outqueue size
    bpf_probe_read(&event.outq_size, sizeof(event.outq_size), &q->out_qlen);
    
    // Get rwnd from association
    bpf_probe_read(&event.rwnd, sizeof(event.rwnd), &asoc->peer.rwnd);
    
    // Get socket from association
    struct sock *sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &asoc->base.sk);
    if (!sk)
        return 0;
    
    // Get socket buffer information
    bpf_probe_read(&event.sndbuf_total, sizeof(event.sndbuf_total), &sk->sk_sndbuf);
    
    // Get used buffer (wmem_alloc)
    u32 wmem_alloc;
    bpf_probe_read(&wmem_alloc, sizeof(wmem_alloc), &sk->sk_wmem_alloc);
    event.sndbuf_used = wmem_alloc;
    
    buffer_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Monitor send buffer pressure with the correct signature
int kprobe__sctp_wait_for_sndbuf(struct pt_regs *ctx, struct sctp_association *asoc,
                                 struct sctp_transport *transport,
                                 long *timeo_p, size_t msg_len) {
    struct buffer_event_t event = {};

    event.event_type = EVENT_SNDBUF_WAIT;
    event.timestamp = bpf_ktime_get_ns();
    
    // First argument is sctp_association
    if (!asoc)
        return 0;
    
    // Get association ID
    bpf_probe_read(&event.association_id, sizeof(event.association_id), &asoc->assoc_id);
    
    // Get rwnd from association
    bpf_probe_read(&event.rwnd, sizeof(event.rwnd), &asoc->peer.rwnd);
    
    // Get socket from association
    struct sock *sk = NULL;
    bpf_probe_read(&sk, sizeof(sk), &asoc->base.sk);
    if (!sk)
        return 0;
    
    // Save socket pointer for this association ID
    sock_map.update(&event.association_id, &sk);
    
    // Get socket buffer information
    bpf_probe_read(&event.sndbuf_total, sizeof(event.sndbuf_total), &sk->sk_sndbuf);
    
    // Get used buffer (wmem_alloc)
    u32 wmem_alloc;
    bpf_probe_read(&wmem_alloc, sizeof(wmem_alloc), &sk->sk_wmem_alloc);
    event.sndbuf_used = wmem_alloc;
    
    // Get outqueue
    struct sctp_outq *outq = NULL;
    bpf_probe_read(&outq, sizeof(outq), &asoc->outqueue);
    if (outq) {
        bpf_probe_read(&event.outq_size, sizeof(event.outq_size), &outq->out_qlen);
    }
    
    buffer_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Monitor write space availability with the correct signature
int kprobe__sctp_write_space(struct pt_regs *ctx, struct sock *sk) {
    struct buffer_event_t event = {};

    event.event_type = EVENT_WRITE_SPACE;
    event.timestamp = bpf_ktime_get_ns();
    
    // First argument is sock
    if (!sk)
        return 0;
    
    // Get socket buffer information
    bpf_probe_read(&event.sndbuf_total, sizeof(event.sndbuf_total), &sk->sk_sndbuf);
    
    // Get used buffer (wmem_alloc)
    u32 wmem_alloc;
    bpf_probe_read(&wmem_alloc, sizeof(wmem_alloc), &sk->sk_wmem_alloc);
    event.sndbuf_used = wmem_alloc;
    
    // We don't have direct access to association from sock, but we can submit the event anyway
    // with the information we have
    buffer_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

# Buffer event structure
class BufferEvent(ct.Structure):
    _fields_ = [
        ("event_type", ct.c_uint),
        ("association_id", ct.c_uint),
        ("outq_size", ct.c_uint),
        ("sndbuf_used", ct.c_uint),
        ("sndbuf_total", ct.c_uint),
        ("rwnd", ct.c_uint),
        ("timestamp", ct.c_ulonglong),
    ]

# Event type names
event_types = {
    1: "OUTQ_TAIL",
    2: "OUTQ_FLUSH",
    3: "SNDBUF_WAIT",
    4: "WRITE_SPACE"
}

# Track buffer metrics per association
class BufferStats:
    def __init__(self):
        self.samples = 0
        self.total_utilisation = 0
        self.max_utilisation = 0
        self.min_utilisation = 100
        self.outq_samples = 0
        self.total_outq_size = 0
        self.max_outq_size = 0
        self.rwnd_samples = 0
        self.total_rwnd = 0
        self.min_rwnd = float('inf')
        self.sndbuf_wait_count = 0
        
    def update_buffer(self, used, total, outq_size=None, rwnd=None, is_wait=False):
        if total > 0:
            utilisation = (used * 100) / total
            self.samples += 1
            self.total_utilisation += utilisation
            self.max_utilisation = max(self.max_utilisation, utilisation)
            self.min_utilisation = min(self.min_utilisation, utilisation)
        
        if outq_size is not None:
            self.outq_samples += 1
            self.total_outq_size += outq_size
            self.max_outq_size = max(self.max_outq_size, outq_size)
        
        if rwnd is not None:
            self.rwnd_samples += 1
            self.total_rwnd += rwnd
            self.min_rwnd = min(self.min_rwnd, rwnd)
        
        if is_wait:
            self.sndbuf_wait_count += 1

class SCTPBufmonTracer:
    def __init__(self, interval=1, csv_output=False, output_file=None):
        self.interval = interval
        self.csv_output = csv_output
        self.output_file = output_file
        self.b = None
        self.csvfile = None
        self.writer = None
        # Using the same variable names as in the original script
        self.buffer_stats = {}  # (assoc_id) -> BufferStats
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
            # Use same header as original
            header = [
                "Association ID", "Avg_Util_%", "Min_Util_%", "Max_Util_%", "Util_Samples",
                "Avg_Outqueue_bytes", "Max_Outqueue_bytes", "Outqueue_Samples",
                "Avg_RWND_bytes", "Min_RWND_bytes", "RWND_Samples",
                "Sndbuf_Wait_Events"
            ]
            self.writer.writerow(header)
        
        # Set up perf buffer for events using the same function signature
        def process_buffer_event(cpu, data, size):
            event = ct.cast(data, ct.POINTER(BufferEvent)).contents
            
            # Track stats per association
            assoc_key = event.association_id
            if assoc_key not in self.buffer_stats:
                self.buffer_stats[assoc_key] = BufferStats()
            
            # Update statistics
            is_wait = (event.event_type == 3)  # SNDBUF_WAIT
            self.buffer_stats[assoc_key].update_buffer(
                event.sndbuf_used, 
                event.sndbuf_total,
                event.outq_size if event.outq_size > 0 else None,
                event.rwnd if event.rwnd > 0 else None,
                is_wait
            )
            
            # Calculate buffer utilisation percentage
            buffer_util = 0
            if event.sndbuf_total > 0:
                buffer_util = (event.sndbuf_used * 100) / event.sndbuf_total
        
        self.b["buffer_events"].open_perf_buffer(process_buffer_event)
        self._setup_complete = True
        
    def poll_events(self, timeout=None):
        """Poll for events with optional timeout (in ms)"""
        if not self._setup_complete:
            self.setup()
        if timeout is None:
            timeout = self.interval * 1000
        self.b.perf_buffer_poll(timeout=timeout)
    
    def print_summary(self):
        """Print summary using the original function logic but with instance variables"""
        csv_mode = self.csv_output or self.output_file
        
        # Iterate through the sorted buffer statistics
        for assoc_id, stats in sorted(self.buffer_stats.items()):
            # Initialize values for the CSV row to 0 or None
            avg_util = 0.0
            min_util = 0.0
            max_util = 0.0
            avg_outq = 0.0
            max_outq = 0.0
            avg_rwnd = 0.0
            min_rwnd = 0.0
            
            # All print statements are now conditional on `csv_mode` not being true.
            if not csv_mode:
                print(f"\nAssociation {assoc_id}:")
            
            # Buffer utilisation stats
            if stats.samples > 0:
                avg_util = stats.total_utilisation / stats.samples
                min_util = stats.min_utilisation
                max_util = stats.max_utilisation
                if not csv_mode:
                    print(f"  Send Buffer utilisation:")
                    print(f"    Average: {avg_util:.1f}%")
                    print(f"    Min/Max: {min_util:.1f}%/{max_util:.1f}%")
                    print(f"    Samples: {stats.samples}")
            
            # Outqueue stats
            if stats.outq_samples > 0:
                avg_outq = stats.total_outq_size / stats.outq_samples
                max_outq = stats.max_outq_size
                if not csv_mode:
                    print(f"  Outqueue Size:")
                    print(f"    Average: {avg_outq:.1f} bytes")
                    print(f"    Maximum: {max_outq} bytes")
                    print(f"    Samples: {stats.outq_samples}")
            
            # RWND stats
            if stats.rwnd_samples > 0:
                avg_rwnd = stats.total_rwnd / stats.rwnd_samples
                min_rwnd = stats.min_rwnd
                if not csv_mode:
                    print(f"  Receiver Window (RWND):")
                    print(f"    Average: {avg_rwnd:.1f} bytes")
                    print(f"    Minimum: {min_rwnd} bytes")
                    print(f"    Samples: {stats.rwnd_samples}")
            
            # Buffer pressure events
            sndbuf_wait_count = stats.sndbuf_wait_count
            if not csv_mode:
                print(f"  Send Buffer Pressure:")
                print(f"    Wait events: {sndbuf_wait_count}")

            if csv_mode:
                row = [
                    assoc_id,
                    f"{avg_util:.1f}", f"{min_util:.1f}", f"{max_util:.1f}", stats.samples,
                    f"{avg_outq:.1f}", max_outq, stats.outq_samples,
                    f"{avg_rwnd:.1f}", min_rwnd, stats.rwnd_samples,
                    sndbuf_wait_count
                ]
                if self.output_file:
                    self.writer.writerow(row)
                else:
                    print(",".join(map(str, row)))
    
    def cleanup(self):
        """Clean up resources"""
        if self.csvfile:
            self.csvfile.close()

# Keep the original print_summary function for backward compatibility 
# and standalone operation
def print_summary():
    """Original print_summary function that will be used in standalone mode"""
    csv_mode = args.csv or args.file
    # Iterate through the sorted buffer statistics
    for assoc_id, stats in sorted(buffer_stats.items()):
        # Initialize values for the CSV row to 0 or None
        avg_util = 0.0
        min_util = 0.0
        max_util = 0.0
        avg_outq = 0.0
        max_outq = 0.0
        avg_rwnd = 0.0
        min_rwnd = 0.0
        
        # All print statements are now conditional on `csv_file` not being defined.
        if not csv_mode:
            print(f"\nAssociation {assoc_id}:")
        
        # Buffer utilisation stats
        if stats.samples > 0:
            avg_util = stats.total_utilisation / stats.samples
            min_util = stats.min_utilisation
            max_util = stats.max_utilisation
            if not csv_mode:
                print(f"  Send Buffer utilisation:")
                print(f"    Average: {avg_util:.1f}%")
                print(f"    Min/Max: {min_util:.1f}%/{max_util:.1f}%")
                print(f"    Samples: {stats.samples}")
        
        # Outqueue stats
        if stats.outq_samples > 0:
            avg_outq = stats.total_outq_size / stats.outq_samples
            max_outq = stats.max_outq_size
            if not csv_mode:
                print(f"  Outqueue Size:")
                print(f"    Average: {avg_outq:.1f} bytes")
                print(f"    Maximum: {max_outq} bytes")
                print(f"    Samples: {stats.outq_samples}")
        
        # RWND stats
        if stats.rwnd_samples > 0:
            avg_rwnd = stats.total_rwnd / stats.rwnd_samples
            min_rwnd = stats.min_rwnd
            if not csv_mode:
                print(f"  Receiver Window (RWND):")
                print(f"    Average: {avg_rwnd:.1f} bytes")
                print(f"    Minimum: {min_rwnd} bytes")
                print(f"    Samples: {stats.rwnd_samples}")
        
        # Buffer pressure events
        sndbuf_wait_count = stats.sndbuf_wait_count
        if not csv_mode:
            print(f"  Send Buffer Pressure:")
            print(f"    Wait events: {sndbuf_wait_count}")

        if csv_mode:
            row = [
                assoc_id,
                f"{avg_util:.1f}", f"{min_util:.1f}", f"{max_util:.1f}", stats.samples,
                f"{avg_outq:.1f}", max_outq, stats.outq_samples,
                f"{avg_rwnd:.1f}", min_rwnd, stats.rwnd_samples,
                sndbuf_wait_count
            ]
            if args.file:
                writer.writerow(row)
            else:
                print(",".join(map(str, row)))

def parse_args():
    # Keep original argument parser
    parser = argparse.ArgumentParser(
        description="Monitor SCTP buffer utilisation")
    parser.add_argument("-i", "--interval", type=int, default=1,
        help="output interval, in seconds")
    parser.add_argument("-c", "--csv", action="store_true", help="Output in CSV format")
    parser.add_argument(
        "-f", "--file", metavar="FILE", help="Write output to a specified file"
    )
    return parser.parse_args()

def signal_handler(signal, frame):
    # Original signal handler for standalone mode
    print_summary()
    if csvfile:
        csvfile.close()
    print("\nTracing completed.")
    exit(0)

def main():
    global args, b, buffer_stats, csvfile, writer
    
    args = parse_args()
    
    # Load BPF program
    b = BPF(text=bpf_text)
    
    # Buffer statistics per (association) - global as in original
    buffer_stats = {}  # (assoc_id) -> BufferStats
    
    print("Tracing SCTP buffer utilisation... Hit Ctrl-C to end")
    
    # Setup CSV file and writer if requested
    csvfile = None
    writer = None
    if args.file:
        csvfile = open(args.file, "w", newline="")
        writer = csv.writer(csvfile)
    
    # Process buffer events - use global variables
    def process_buffer_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(BufferEvent)).contents
        
        # Track stats per association
        assoc_key = event.association_id
        if assoc_key not in buffer_stats:
            buffer_stats[assoc_key] = BufferStats()
        
        # Update statistics
        is_wait = (event.event_type == 3)  # SNDBUF_WAIT
        buffer_stats[assoc_key].update_buffer(
            event.sndbuf_used, 
            event.sndbuf_total,
            event.outq_size if event.outq_size > 0 else None,
            event.rwnd if event.rwnd > 0 else None,
            is_wait
        )
        
        # Calculate buffer utilisation percentage
        buffer_util = 0
        if event.sndbuf_total > 0:
            buffer_util = (event.sndbuf_used * 100) / event.sndbuf_total
        
        event_name = event_types.get(event.event_type, "UNKNOWN")
    
    b["buffer_events"].open_perf_buffer(process_buffer_event)
    
    # Register signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    header = [
            "Association ID", "Avg_Util_%", "Min_Util_%", "Max_Util_%", "Util_Samples",
            "Avg_Outqueue_bytes", "Max_Outqueue_bytes", "Outqueue_Samples",
            "Avg_RWND_bytes", "Min_RWND_bytes", "RWND_Samples",
            "Sndbuf_Wait_Events"
        ]
    
    if args.csv:
        # CSV to stdout, header already printed
        print(",".join(map(str, header)))
    elif args.file:
        # Write CSV header to file
        writer.writerow(header)
    
    # Main loop with periodic summaries
    while True:
        try:
            sleep(args.interval)
            b.perf_buffer_poll(0)
        except KeyboardInterrupt:
            signal_handler(0, 0)
            if csvfile:
                csvfile.close()
            print("\nTracing completed.")
            exit()

if __name__ == "__main__":
    main()