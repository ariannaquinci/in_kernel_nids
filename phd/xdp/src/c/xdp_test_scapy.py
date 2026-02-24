#!/usr/bin/env python3
import argparse

from scapy.all import Ether, IP, TCP, UDP, Raw, conf, get_if_hwaddr, sendp

DEFAULT_IFACE = "enp7s0"
DEFAULT_DST_IP = "192.168.17.44"
DEFAULT_DPORT = 9999
DEFAULT_SPORT = 5555
DEFAULT_COUNT = 5
DEFAULT_INTERVAL = 0.2
DEFAULT_PAYLOAD = b"hello DW_DUMMY_NEEDLE test"


def build_packet(args):
    l4 = (
        UDP(sport=args.sport, dport=args.dport)
        if args.proto == "udp"
        else TCP(sport=args.sport, dport=args.dport, flags="PA", seq=1, ack=1)
    )
    ether = Ether(dst=args.dst_mac, src=get_if_hwaddr(args.iface))
    return ether / IP(dst=args.dst_ip) / l4 / Raw(load=args.payload)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Invia pacchetti Scapy con payload di test verso l'interfaccia target."
    )
    parser.add_argument("--iface", default=DEFAULT_IFACE, help="Interfaccia di uscita")
    parser.add_argument("--dst-ip", default=DEFAULT_DST_IP, help="IP destinazione")
    parser.add_argument(
        "--dst-mac",
        default="ff:ff:ff:ff:ff:ff",
        help="MAC destinazione (default broadcast per forzare frame su L2)",
    )
    parser.add_argument("--proto", choices=("udp", "tcp"), default="udp")
    parser.add_argument("--sport", type=int, default=DEFAULT_SPORT)
    parser.add_argument("--dport", type=int, default=DEFAULT_DPORT)
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL)
    parser.add_argument(
        "--payload",
        default=DEFAULT_PAYLOAD,
        type=lambda x: x.encode() if isinstance(x, str) else x,
        help="Payload ASCII (default contiene DW_DUMMY_NEEDLE)",
    )
    parser.add_argument("--show", action="store_true", help="Mostra packet summary e bytes")
    return parser.parse_args()


def main():
    args = parse_args()
    conf.verb = 1
    pkt = build_packet(args)

    if args.show:
        pkt.show2()
        print(bytes(pkt).hex())

    print(
        f"Sending {args.count} {args.proto.upper()} packets on {args.iface} "
        f"to {args.dst_ip}:{args.dport} (dst-mac {args.dst_mac})"
    )
    sendp(pkt, iface=args.iface, count=args.count, inter=args.interval, verbose=True)


if __name__ == "__main__":
    main()
