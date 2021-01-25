#!/usr/bin/python
from scapy.all import *

def spoof_ICMP(pkt):
	#Once an icmp packet is seen on the traffic, spoof an ICMP packet
	a = IP()
	
	# Set the dst IP to originator's IP address
	a.dst=pkt[IP].src

	# Set src to be the original dst of the request
	a.src= pkt[IP].dst

	# Set type of ICMP packet, along with sequence and id fields 
	b = ICMP(type="echo-reply")
	b.seq = pkt[ICMP].seq
	b.id = pkt[ICMP].id

	# Set the data field based off of what we sniff so that the data fields are the same
	# This data is found in the [Raw] section of the packet.
	payload = pkt[Raw].load

	spoofed_packet = a/b/payload
	send(spoofed_packet)

pkt = sniff(filter='icmp[icmptype] == icmp-echo',prn=spoof_ICMP)
