#!/usr/bin/bash

from scapy.all import *

def spoof(pkt):
    a = IP(src=pkt[1].dst, dst=pkt[1].src)
    b = ICMP(type=0,id=pkt[2].id,seq=pkt[2].seq)
    load = pkt[3].load
    p = a/b/load
    send(p)

pkt = sniff(iface='br-9d336dcc5ceb', filter='icmp', prn=spoof)
