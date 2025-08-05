#!/usr/bin/python3
"""
sctp_jitter.py - Measure SCTP inter-packet reception jitter.

This tool traces SCTP packet receptions to calculate jitter on a per-stream
basis. Jitter is the variation in packet arrival timing.

USAGE: sctp_jitter.py [-h] [-i INTERVAL]
"""

from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import signal
import collections

# Parse command line arguments
parser = argparse.ArgumentParser(
    description="Measure SCTP packet reception jitter")
parser.add_argument("-i", "--interval", type=int, default=1,
    help="output interval, in seconds")
args = parser.parse_args()

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <linux/sched.h>
#include <net/sctp/sctp.h>

// Forward declarations for struct types needed by function signature
struct sctp_cmd_seq;

struct jitter_event_t {
    u32 stream_id;
    u64 timestamp;
    u64 delta_ns;  // Time since last reception
};

// Key stream ID
struct stream_key_t {
    u32 stream_id;
};

BPF_HASH(last_rx, struct stream_key_t, u64, 1024);
BPF_PERF_OUTPUT(jitter_events);


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

// Trace data chunk reception with updated function signature
int kprobe__sctp_eat_data(struct pt_regs *ctx, const struct sctp_association *asoc,
                          struct sctp_chunk *chunk,
                          struct sctp_cmd_seq *commands) {
    bpf_trace_printk("sctp_eat_data called\\n");
    struct jitter_event_t event = {};
    
    event.timestamp = bpf_ktime_get_ns();
    event.delta_ns = 0;
    
    // Check for null chunk
    if (!chunk) 
        return 0;
    
    bpf_trace_printk("Chunk received: %p\\n", chunk);

    // Read stream ID directly from the chunk's data header
    // The stream ID is in the data_hdr substructure
    // Pull the Data header
    struct sctp_datahdr *data_hdr = sctp_sm_pull_data(chunk);
    if (!data_hdr) {
        bpf_trace_printk("Failed to pull SACK header\\n");
        return 0;
    }
    
    if (!data_hdr) {
        bpf_trace_printk("Data header is null\\n");
        return 0;
    }

    bpf_trace_printk("Data header: %p\\n", data_hdr);

    // Read stream ID from data header
    __be16 stream_id;
    bpf_probe_read(&stream_id, sizeof(stream_id), &data_hdr->stream);
    
    event.stream_id = ntohs(stream_id);

    bpf_trace_printk("Stream ID: %d\\n", event.stream_id);
    
    // Create key stream ID
    struct stream_key_t key = {};
    key.stream_id = event.stream_id;

    bpf_trace_printk("Key created: Stream ID %d\\n", key.stream_id);
    
    // Get previous reception time for this stream
    u64 *prev_time = last_rx.lookup(&key);
    if (prev_time) {
        bpf_trace_printk("Previous time found: %llu\\n", *prev_time);
        event.delta_ns = event.timestamp - *prev_time;
        jitter_events.perf_submit(ctx, &event, sizeof(event));
    } else {
        bpf_trace_printk("No previous time found for this stream\\n");
    }
    
    // Update the last reception time
    last_rx.update(&key, &event.timestamp);
    return 0;
}
"""

# Load BPF program
b = BPF(text=bpf_text)


# Jitter event structure
class JitterEvent(ct.Structure):
    _fields_ = [
        ("stream_id", ct.c_uint),
        ("timestamp", ct.c_ulonglong),
        ("delta_ns", ct.c_ulonglong),
    ]

# Jitter calculation class
class JitterTracker:
    def __init__(self):
        self.prev_delta = 0
        self.jitter = 0
        self.sample_count = 0
        self.deltas = collections.deque(maxlen=100)  # Last 100 samples
        
    def update(self, delta_ms):
        self.deltas.append(delta_ms)
        self.sample_count += 1
        
        if self.prev_delta:
            # Calculate jitter using RFC 3550 formula
            d = abs(delta_ms - self.prev_delta)
            self.jitter += (d - self.jitter) / 16
        
        self.prev_delta = delta_ms

# Track jitter per stream
jitter_stats = {}  # (stream_id) -> JitterTracker

print("Tracing SCTP packet reception jitter... Hit Ctrl-C to end")
print("%-8s %-12s %-12s" % ("STREAM", "DELTA(ms)", "TIME"))

# Process jitter events
def process_jitter_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(JitterEvent)).contents
    delta_ms = float(event.delta_ns) / 1000000  # ns to ms
    
    # Track jitter
    key = (event.stream_id)
    if key not in jitter_stats:
        jitter_stats[key] = JitterTracker()
    
    jitter_stats[key].update(delta_ms)
    
    timestamp = strftime("%H:%M:%S")
    print("%-8d %-12.3f %-12s" % 
          (event.stream_id, delta_ms, timestamp))

b["jitter_events"].open_perf_buffer(process_jitter_event)

# Cleanup on keyboard interrupt
def signal_handler(signal, frame):
    print("\n=== Reception Jitter Summary ===")
    for (stream_id), tracker in sorted(jitter_stats.items()):
        if tracker.deltas:
            delta_avg = sum(tracker.deltas) / len(tracker.deltas) if tracker.deltas else 0
            delta_min = min(tracker.deltas) if tracker.deltas else 0
            delta_max = max(tracker.deltas) if tracker.deltas else 0
            
            print(f"Stream {stream_id}:")
            print(f"  Samples: {tracker.sample_count}")
            print(f"  Avg packet arrival delta: {delta_avg:.3f} ms")
            print(f"  Min/Max arrival delta: {delta_min:.3f}/{delta_max:.3f} ms")
            print(f"  Reception jitter (RFC 3550): {tracker.jitter:.3f} ms")
    exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Main loop
while True:
    try:
        b.perf_buffer_poll(timeout=args.interval * 1000)
    except KeyboardInterrupt:
        signal_handler(0, 0)
        exit()