#!/usr/bin/bash
from scapy.all import * 

def prnt(pkt):
    pkt.show()

pkt = sniff(iface=['br-9d336dcc5ceb', 'enp0s3'], filter='icmp', prn=prnt)
