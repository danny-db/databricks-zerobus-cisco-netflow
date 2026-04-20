"""
NetFlow v5 traffic generator for testing the Telegraf -> Zerobus pipeline.
Generates realistic-looking flow records and sends them to Telegraf.

Usage:
  python3 netflow_generator.py [--rate 10] [--host 127.0.0.1] [--port 2055]
"""

import socket
import struct
import time
import random
import argparse

# Realistic IP pools
INTERNAL_IPS = [
    "10.1.1.10", "10.1.1.20", "10.1.1.30", "10.1.2.10", "10.1.2.20",
    "10.1.3.10", "10.1.3.15", "10.2.1.10", "10.2.1.50", "10.2.2.100",
    "172.16.0.10", "172.16.0.20", "172.16.1.5", "172.16.1.100",
    "192.168.1.10", "192.168.1.20", "192.168.1.50", "192.168.2.10",
]

EXTERNAL_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",            # DNS
    "142.250.70.46", "142.250.66.110", "172.217.14.99",       # Google
    "13.107.42.14", "20.190.159.0", "52.96.165.130",          # Microsoft
    "54.239.28.85", "52.94.236.248", "99.84.191.100",         # AWS
    "104.16.132.229", "104.18.32.7",                          # Cloudflare
    "157.240.1.35", "31.13.71.36",                            # Meta
    "185.199.108.153",                                         # GitHub
]

# Common services
SERVICES = [
    (443, 6, "HTTPS"),
    (80, 6, "HTTP"),
    (53, 17, "DNS"),
    (22, 6, "SSH"),
    (3389, 6, "RDP"),
    (8443, 6, "HTTPS-Alt"),
    (993, 6, "IMAPS"),
    (587, 6, "SMTP"),
    (5432, 6, "PostgreSQL"),
    (3306, 6, "MySQL"),
]


def ip_to_int(ip):
    parts = ip.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def make_v5_packet(flows, seq, uptime):
    """Create a NetFlow v5 packet with the given flow records."""
    unix_secs = int(time.time())
    unix_nsecs = int((time.time() % 1) * 1e9)

    header = struct.pack("!HHIIIIBBH",
        5,              # version
        len(flows),     # count
        uptime,         # sysuptime (ms)
        unix_secs,
        unix_nsecs,
        seq,            # flow_sequence
        0,              # engine_type
        0,              # engine_id
        0,              # sampling_interval
    )

    records = b""
    for f in flows:
        records += struct.pack("!IIIHHIIIIHHxBBBHHBBxx",
            ip_to_int(f["src"]),
            ip_to_int(f["dst"]),
            0,                      # nexthop
            f.get("input", 0),      # input interface
            f.get("output", 0),     # output interface
            f["packets"],
            f["bytes"],
            f["first"],             # first switched (ms from uptime)
            f["last"],              # last switched
            f["src_port"],
            f["dst_port"],
            # pad1 (1 byte via 'x')
            f.get("tcp_flags", 0x12),  # SYN+ACK
            f["protocol"],
            f.get("tos", 0),
            0,                      # src_as
            0,                      # dst_as
            0,                      # src_mask
            0,                      # dst_mask
            # pad2 (2 bytes via 'xx')
        )

    return header + records


def generate_flow(uptime_ms):
    """Generate a realistic flow record."""
    src = random.choice(INTERNAL_IPS)
    dst = random.choice(EXTERNAL_IPS)
    dst_port, protocol, _ = random.choice(SERVICES)
    src_port = random.randint(32768, 65535)

    # Realistic byte/packet counts
    if dst_port == 443:
        bytes_count = random.randint(1000, 500000)
        packets = max(1, bytes_count // random.randint(500, 1500))
    elif dst_port == 53:
        bytes_count = random.randint(50, 500)
        packets = random.randint(1, 4)
    else:
        bytes_count = random.randint(200, 100000)
        packets = max(1, bytes_count // random.randint(200, 1000))

    duration_ms = random.randint(100, 30000)
    first = max(0, uptime_ms - duration_ms - random.randint(0, 5000))
    last = first + duration_ms

    tcp_flags = 0
    if protocol == 6:
        tcp_flags = random.choice([0x02, 0x12, 0x10, 0x18, 0x11, 0x19])

    return {
        "src": src, "dst": dst,
        "src_port": src_port, "dst_port": dst_port,
        "protocol": protocol,
        "bytes": bytes_count, "packets": packets,
        "first": first, "last": last,
        "tcp_flags": tcp_flags,
        "input": random.randint(1, 4),
        "output": random.randint(1, 4),
    }


def main():
    parser = argparse.ArgumentParser(description="NetFlow v5 generator")
    parser.add_argument("--host", default="127.0.0.1", help="Telegraf host")
    parser.add_argument("--port", type=int, default=2055, help="Telegraf port")
    parser.add_argument("--rate", type=int, default=10, help="Flows per second")
    parser.add_argument("--batch", type=int, default=10, help="Flows per packet (max 30)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq = 0
    start_time = time.time()
    total_flows = 0

    print(f"NetFlow v5 generator -> {args.host}:{args.port}")
    print(f"  Rate: {args.rate} flows/sec, batch size: {args.batch}")
    print(f"  Press Ctrl+C to stop\n")

    try:
        while True:
            uptime_ms = int((time.time() - start_time) * 1000) + 1000000
            batch_size = min(args.batch, 30)  # v5 max 30 records per packet
            flows = [generate_flow(uptime_ms) for _ in range(batch_size)]

            packet = make_v5_packet(flows, seq, uptime_ms)
            sock.sendto(packet, (args.host, args.port))

            seq += batch_size
            total_flows += batch_size

            if total_flows % 100 == 0:
                elapsed = time.time() - start_time
                print(f"  Sent {total_flows} flows ({total_flows/elapsed:.0f} flows/sec)")

            # Sleep to maintain desired rate
            time.sleep(batch_size / args.rate)

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\nStopped. Sent {total_flows} flows in {elapsed:.1f}s ({total_flows/elapsed:.0f} flows/sec)")
        sock.close()


if __name__ == "__main__":
    main()
