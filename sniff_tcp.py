#!/usr/bin/bash
from scapy.all import * 

def prnt(pkt):
    pkt.show()

pkt = sniff(iface=['br-9d336dcc5ceb', 'enp0s3'], filter='src host 8.8.8.8 and dst port 23', prn=prnt)
