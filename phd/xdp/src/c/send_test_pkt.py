from scapy.all import Ether, IP, UDP, Raw, sendp

iface = "enp7s0"

pkt = (
    Ether()
    / IP(dst="192.0.2.10")
    / UDP(sport=5555, dport=9999)
    / Raw(load=b"hello malicious test")
)

sendp(pkt, iface=iface, count=5, inter=0.2, verbose=True)

