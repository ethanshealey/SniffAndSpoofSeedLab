#!/usr/bin/bash
from scapy.all import * 

def prnt(pkt):
    pkt.show()

pkt = sniff(iface='br-9d336dcc5ceb', filter='icmp', prn=prnt)

