#!/usr/bin/python
from scapy.all import *


def print_pkt(pkt):
    pkt.show()


pkt = sniff(filter='', prn=print_pkt)
