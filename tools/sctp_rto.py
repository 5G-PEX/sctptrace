#!/usr/bin/python3
from bcc import BPF
from time import sleep, strftime
import ctypes as ct
import argparse
import socket
import struct
import csv
import os

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

class SCTPRtoTracer:
    def __init__(self, interval=1, csv_output=False, output_file=None):
        self.interval = interval
        self.csv_output = csv_output
        self.output_file = output_file
        self.b = None
        self.csvfile = None
        self.writer = None
        # Track RTO values per transport - new data structure
        self.rto_values = {}  # (transport_id) -> [rto_values]
        self.transport_info = {}  # (transport_id) -> address info
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
                "transport_id", 
                "ip_address",
                "port",
                "samples", 
                "rto_avg_ms", 
                "srtt_avg_ms", 
                "rttvar_avg_ms"
            ])
        
        # Set up perf buffer for events
        self.b["rto_events"].open_perf_buffer(self._process_rto_event)
        self._setup_complete = True
        
    def _process_rto_event(self, cpu, data, size):
        event = ct.cast(data, ct.POINTER(RTOEvent)).contents
        
        rto_ms = float(event.rto_us) / 1000
        srtt_ms = float(event.srtt_us) / 1000 if event.srtt_us else 0
        rttvar_ms = float(event.rttvar_us) / 1000 if event.rttvar_us else 0
        
        # Format IP address for IPv4
        ip_str = ""
        if event.addr_type == socket.AF_INET:  # IPv4
            ipv4_bytes = struct.pack("I", event.ipv4_addr)
            ip_str = socket.inet_ntop(socket.AF_INET, ipv4_bytes)
            port = socket.ntohs(event.port)
        
        # Store transport info for summary
        transport_id = event.transport_id
        if transport_id not in self.transport_info:
            self.transport_info[transport_id] = {
                'ip': ip_str,
                'port': port
            }
        
        # Store RTO values for summary
        if transport_id not in self.rto_values:
            self.rto_values[transport_id] = []
        
        self.rto_values[transport_id].append({
            'rto': rto_ms,
            'srtt': srtt_ms,
            'rttvar': rttvar_ms
        })
        
        # Print event details in non-CSV mode
        if not (self.csv_output or self.output_file):
            timestamp = strftime("%H:%M:%S")
            print("%-12d %-15s %-6d %-10.2f %-10.2f %-10.2f %-12s" % 
                  (transport_id, ip_str, port, 
                   rto_ms, srtt_ms, rttvar_ms, timestamp))
    
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
        for transport_id, events in sorted(self.rto_values.items()):
            if not events:
                continue
            
            # Calculate averages
            rto_avg = sum(e['rto'] for e in events) / len(events)
            srtt_avg = sum(e['srtt'] for e in events) / len(events)
            rttvar_avg = sum(e['rttvar'] for e in events) / len(events)
            
            # Get transport info
            info = self.transport_info.get(transport_id, {'ip': '', 'port': 0})
            
            results.append({
                'transport_id': transport_id,
                'ip': info['ip'],
                'port': info['port'],
                'samples': len(events),
                'rto_avg': rto_avg,
                'srtt_avg': srtt_avg,
                'rttvar_avg': rttvar_avg
            })
        return results
    
    def print_summary(self):
        """Print or write summary data based on output mode"""
        results = self.get_summary()
        
        if not results:
            if not self.csv_output and not self.output_file:
                print("No RTO events recorded yet.")
            return
            
        for result in results:
            if self.csv_output or self.output_file:
                row = [
                    result['transport_id'],
                    result['ip'],
                    result['port'],
                    result['samples'],
                    f"{result['rto_avg']:.2f}",
                    f"{result['srtt_avg']:.2f}",
                    f"{result['rttvar_avg']:.2f}"
                ]
                if self.output_file:
                    self.writer.writerow(row)
                elif self.csv_output:
                    print(",".join(map(str, row)))
            else:
                # Plain text output
                print(f"Transport {result['transport_id']} ({result['ip']}:{result['port']}):")
                print(f"  Samples: {result['samples']}")
                print(f"  RTO: {result['rto_avg']:.2f} ms avg")
                print(f"  SRTT: {result['srtt_avg']:.2f} ms avg")
                print(f"  RTTVAR: {result['rttvar_avg']:.2f} ms avg")
    
    def cleanup(self):
        """Clean up resources"""
        if self.csvfile:
            self.csvfile.close()

def parse_args():
    # Parse command line arguments - keeping same args
    parser = argparse.ArgumentParser(
        description="Trace SCTP RTO updates and retransmissions")
    parser.add_argument("-i", "--interval", type=int, default=1,
        help="output interval, in seconds")
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
    
    tracer = SCTPRtoTracer(
        interval=args.interval,
        csv_output=args.csv,
        output_file=args.file
    )
    tracer.setup()
    
    # Set up signal handler for clean exit
    import signal
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, tracer))
    
    if not args.csv and not args.file:
        print("Tracing SCTP RTO updates... Hit Ctrl-C to end")
        print("%-12s %-15s %-6s %-10s %-10s %-10s %-12s" % 
              ("TRANSPORT", "IP", "PORT", "RTO(ms)", "SRTT(ms)", "RTTVAR(ms)", "TIME"))
    elif args.csv:
        print("Tracing SCTP RTO updates to stdout in CSV format... Ctrl+C to end")
        print("transport_id,ip_address,port,rto_ms,srtt_ms,rttvar_ms")
    else:
        print(f"Tracing SCTP RTO updates to file '{args.file}'... Ctrl+C to end")
    
    # Main loop
    try:
        while True:
            tracer.poll_events()
            sleep(args.interval)
    except KeyboardInterrupt:
        signal_handler(0, 0, tracer)

if __name__ == "__main__":
    main()