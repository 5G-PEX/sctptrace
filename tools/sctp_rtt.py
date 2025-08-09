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
import csv

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

class SCTPRttTracer:
    def __init__(self, pid=None, interval=1, csv_output=False, output_file=None):
        self.pid = pid
        self.interval = interval
        self.csv_output = csv_output
        self.output_file = output_file
        self.b = None
        self.csvfile = None
        self.writer = None
        self.rtt_values = {}
        self._setup_complete = False

    def setup(self):
        if self._setup_complete:
            return
            
        # Set up pid filter if specified
        bpf_text_copy = bpf_text
        if self.pid:
            bpf_text_copy = bpf_text_copy.replace('FILTER_PID', 
                'if (pid != %d) { return 0; }' % self.pid)
        else:
            bpf_text_copy = bpf_text_copy.replace('FILTER_PID', '')

        # Load BPF program
        self.b = BPF(text=bpf_text_copy)
        
        # Setup CSV file and writer if requested
        if self.output_file:
            self.csvfile = open(self.output_file, "w", newline="")
            self.writer = csv.writer(self.csvfile)
            self.writer.writerow(["assoc_id", "samples", "rtt_avg_us", "rtt_min_us", "rtt_max_us"])
        
        # Set up perf buffer for events
        self.b["rtt_events"].open_perf_buffer(self._process_rtt_event)
        self._setup_complete = True

    def _process_rtt_event(self, cpu, data, size):
        # Same event processing as before, but store data instead of printing
        event = ct.cast(data, ct.POINTER(RTTEvent)).contents
        rtt_ms = float(event.rtt_ns) / 1000
        tsn = event.tsn
        assoc_id = event.assoc_id
        timestamp = strftime("%H:%M:%S")

        if not (self.csv_output or self.output_file):
            print("%-8d %-10u %-10.3f %-8s" % 
                (assoc_id, tsn, rtt_ms, timestamp))

        # Collect data but don't print (run.py will handle printing)
        if event.assoc_id not in self.rtt_values:
            self.rtt_values[event.assoc_id] = []
        
        self.rtt_values[event.assoc_id].append(rtt_ms)
    
    def poll_events(self, timeout=None):
        """Poll for events with optional timeout (in ms)"""
        if not self._setup_complete:
            self.setup()
        if timeout is None:
            timeout = self.interval * 1000
        self.b.perf_buffer_poll(timeout=timeout)
    
    def get_summary(self):
        """Return summary statistics for collected data"""
        results = []
        for assoc_id, rtts in self.rtt_values.items():
            if not rtts:
                continue
            samples = len(rtts)
            rtt_avg_us = sum(rtts) * 1000 / samples
            rtt_min_us = min(rtts) * 1000
            rtt_max_us = max(rtts) * 1000
            results.append({
                'assoc_id': assoc_id,
                'samples': samples,
                'rtt_avg_us': rtt_avg_us,
                'rtt_min_us': rtt_min_us,
                'rtt_max_us': rtt_max_us
            })
        return results
    
    def print_summary(self):
        """Print or write summary data based on output mode"""
        results = self.get_summary()
        
        for result in results:
            if self.csv_output:
                row = [
                    result['assoc_id'],
                    result['samples'],
                    result['rtt_avg_us'],
                    result['rtt_min_us'],
                    result['rtt_max_us']
                ]
                if self.output_file:
                    self.writer.writerow(row)
                else:
                    print(",".join(map(str, row)))
            else:
                print(f"Association {result['assoc_id']}:")
                print(f"  Samples: {result['samples']}")
                print(f"  Avg RTT: {result['rtt_avg_us']:.3f} us")
                print(f"  Min/Max RTT: {result['rtt_min_us']:.3f}/{result['rtt_max_us']:.3f} us")
    
    def cleanup(self):
        """Clean up resources"""
        if self.csvfile:
            self.csvfile.close()

def parse_args():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Measure SCTP Round Trip Time (RTT)")
    parser.add_argument("-p", "--pid", type=int, help="trace this PID only")
    parser.add_argument("-i", "--interval", type=int, default=1,
        help="output interval, in seconds")
    parser.add_argument("-c", "--csv", action="store_true", help="Output in CSV format")
    parser.add_argument(
        "-f", "--file", metavar="FILE", help="Write output to a specified file"
    )
    return parser.parse_args()

# Cleanup on keyboard interrupt
def signal_handler(signal, frame, tracer):
    tracer.print_summary()
    tracer.cleanup()
    print("\nTracing completed.")
    exit()

def main():
    args = parse_args()
    
    tracer = SCTPRttTracer(
        pid=args.pid,
        interval=args.interval,
        csv_output=args.csv,
        output_file=args.file
    )
    tracer.setup()
    
    # Set up signal handler for clean exit
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, tracer))

    if not args.csv and not args.file:
        print("Tracing SCTP RTT... Ctrl+C to end")
        print("%-8s %-10s %-10s %-8s" % ("ASSOC", "TSN", "RTT(ms)", "TIME"))
    elif args.csv:
        # CSV to stdout, header already printed
        print("Tracing SCTP RTT to stdout in CSV format... Ctrl+C to end")
        print("assoc_id,samples,rtt_avg_us,rtt_min_us,rtt_max_us")
    else:
        # Write CSV header to file
        print(f"Tracing SCTP RTT to file '{args.file}'... Ctrl+C to end")

    # Main loop
    while True:
        try:
            tracer.poll_events()
        except KeyboardInterrupt:
            signal_handler(0, 0, tracer)

if __name__ == "__main__":
    main()