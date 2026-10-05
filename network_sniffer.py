import argparse
from datetime import datetime

from scapy.all import sniff, wrpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

# IP protocol numbers -> names
PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}

captured = []       # packets are stored here (for saving to .pcap)
stats = {}          # protocol counter


def payload_preview(packet, max_bytes=64):
    """Return a printable preview of the packet payload."""
    if packet.haslayer(Raw):
        data = bytes(packet[Raw].load)[:max_bytes]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
        return f"{text}  | hex: {data.hex()}"
    return "(no payload)"


def tcp_flags(tcp):
    """Convert TCP flags to readable form, e.g. SYN, ACK."""
    names = {"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH", "A": "ACK", "U": "URG"}
    return ",".join(names[f] for f in str(tcp.flags) if f in names) or "-"


def process_packet(packet):
    captured.append(packet)
    now = datetime.now().strftime("%H:%M:%S")
    number = len(captured)

    print("=" * 70)
    print(f"[#{number}] Time: {now} | Size: {len(packet)} bytes")

    # ---- ARP (Layer 2/3) ----
    if packet.haslayer(ARP):
        arp = packet[ARP]
        op = "Request" if arp.op == 1 else "Reply"
        print(f"Protocol : ARP ({op})")
        print(f"Sender   : {arp.psrc} ({arp.hwsrc})")
        print(f"Target   : {arp.pdst} ({arp.hwdst})")
        stats["ARP"] = stats.get("ARP", 0) + 1
        return

    # ---- IP layer ----
    if packet.haslayer(IP):
        ip = packet[IP]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.proto, f"Other({ip.proto})")
        extra = f"TTL: {ip.ttl}"
    elif packet.haslayer(IPv6):
        ip = packet[IPv6]
        src, dst = ip.src, ip.dst
        proto = PROTO_NAMES.get(ip.nh, f"Other({ip.nh})")
        extra = f"Hop limit: {ip.hlim}"
    else:
        print("Non-IP packet:", packet.summary())
        return

    print(f"Source IP     : {src}")
    print(f"Destination IP: {dst}")
    print(f"Protocol      : {proto} | {extra}")

    # ---- Transport layer ----
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        print(f"Ports         : {tcp.sport} -> {tcp.dport}")
        print(f"TCP Flags     : {tcp_flags(tcp)} | Seq: {tcp.seq} | Ack: {tcp.ack}")
        proto = "TCP"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        print(f"Ports         : {udp.sport} -> {udp.dport}")
        proto = "UDP"
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        print(f"ICMP Type/Code: {icmp.type}/{icmp.code}")
        proto = "ICMP"

    # ---- Application layer hints ----
    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        qname = packet[DNS].qd.qname.decode(errors="ignore")
        print(f"DNS Query     : {qname}")
        proto = "DNS"
    elif packet.haslayer(TCP):
        ports = {packet[TCP].sport, packet[TCP].dport}
        if 80 in ports:
            proto = "HTTP"
            print("App Protocol  : HTTP (unencrypted)")
        elif 443 in ports:
            proto = "HTTPS"
            print("App Protocol  : HTTPS (payload is encrypted)")

    print(f"Payload       : {payload_preview(packet)}")
    stats[proto] = stats.get(proto, 0) + 1


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (scapy)")
    parser.add_argument("-i", "--iface", help="Network interface (default: auto)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (0 = until Ctrl+C)")
    parser.add_argument("-f", "--filter", default="",
                        help='BPF filter, e.g. "tcp", "udp port 53", "host 8.8.8.8"')
    parser.add_argument("-w", "--write", help="Save captured packets to a .pcap file")
    args = parser.parse_args()

    print("[*] Sniffing started... press Ctrl+C to stop\n")
    try:
        sniff(iface=args.iface, filter=args.filter or None,
              prn=process_packet, count=args.count, store=False)
    except PermissionError:
        print("[!] Permission denied. Run as root/Administrator.")
        return
    except KeyboardInterrupt:
        pass

    print("\n" + "=" * 70)
    print(f"[*] Total packets captured: {len(captured)}")
    for name, n in sorted(stats.items(), key=lambda x: -x[1]):
        print(f"    {name:<8}: {n}")

    if args.write and captured:
        wrpcap(args.write, captured)
        print(f"[*] Saved to {args.write} (open in Wireshark)")


if __name__ == "__main__":
    main()