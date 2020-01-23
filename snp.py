#!/usr/bin/python

from scapy.all import *
from scapy.layers.inet import ICMP, IP


def print_pkt(pkt):
        pkt.show()
        a = IP()
        a.src = pkt[IP].dst
        a.dst = pkt[IP].src
        b = pkt[Raw].load
        b.type = 'echo-reply'
        b.code = 0
        b.id = pkt[ICMP].id
        b.seq = pkt[ICMP].seq
        p = a / b
        send(p)
        p.show()


pkt = sniff(filter='icmp[icmptype] == icmp-echo', prn=print_pkt)