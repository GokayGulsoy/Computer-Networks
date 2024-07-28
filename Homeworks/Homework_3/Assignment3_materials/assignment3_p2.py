from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.sendrecv import wrpcap
import random
from datetime import datetime, timedelta
import socket
import struct

# Generate random LAN IP address
lan_ip = socket.inet_ntoa(struct.pack('>I', random.randint(0x0A000000, 0x0AFFFFFF)))

# Generate random WAN IP address
wan_ip = socket.inet_ntoa(struct.pack('>I', random.randint(0x0B000000, 0xBFFFFFFF)))

# Create a list to hold LAN packets
lan_packets = []

# Create a list to hold WAN packets
wan_packets = []

# Set the initial timestamp
time_now = datetime.now()

timestamps = []

timestamps.extend([(time_now + timedelta(milliseconds=random.randint(2, 5))).timestamp(),
                   (time_now + timedelta(milliseconds=random.randint(10, 13))).timestamp(),
                   (time_now + timedelta(milliseconds=random.randint(13, 16))).timestamp(),
                   (time_now + timedelta(milliseconds=random.randint(16, 17))).timestamp(),
                   (time_now + timedelta(milliseconds=random.randint(25, 30))).timestamp()])

# Generate LAN packets
lan_pkt1 = Ether() / IP(src=lan_ip, dst="8.8.8.8") / TCP(sport=5000, dport=80, flags="S")
lan_pkt2 = Ether() / IP(src="8.8.8.8", dst=lan_ip) / TCP(sport=80, dport=5000, flags="SA")
lan_pkt3 = Ether() / IP(src=lan_ip, dst="8.8.8.8") / TCP(sport=5001, dport=443, flags="A")
lan_pkt4 = Ether() / IP(src="8.8.8.8", dst=lan_ip) / TCP(sport=443, dport=5001, flags="PA")
lan_pkt5 = Ether() / IP(src=lan_ip, dst="8.8.8.8") / UDP(sport=3000, dport=53)

# Assign timestamps to LAN packets
lan_pkt1.time = timestamps[0]
lan_pkt2.time = timestamps[1]
lan_pkt3.time = timestamps[2]
lan_pkt4.time = timestamps[3]
lan_pkt5.time = timestamps[4]

# Append LAN packets to the list
lan_packets.extend([lan_pkt1, lan_pkt2, lan_pkt3, lan_pkt4, lan_pkt5])


# Generate WAN packets
wan_pkt1 = Ether() / IP(src=wan_ip, dst="8.8.8.8") / TCP(sport=5000, dport=80, flags="S")
wan_pkt2 = Ether() / IP(src="8.8.8.8", dst=wan_ip) / TCP(sport=80, dport=5000, flags="SA")
wan_pkt3 = Ether() / IP(src=wan_ip, dst="8.8.8.8") / TCP(sport=5001, dport=443, flags="A")
wan_pkt4 = Ether() / IP(src="8.8.8.8", dst=wan_ip) / TCP(sport=443, dport=5001, flags="PA")
wan_pkt5 = Ether() / IP(src=wan_ip, dst="8.8.8.8") / UDP(sport=3000, dport=53)

# Assign timestamps to WAN packets
wan_pkt1.time = timestamps[0]
wan_pkt2.time = timestamps[1]
wan_pkt3.time = timestamps[2]
wan_pkt4.time = timestamps[3]
wan_pkt5.time = timestamps[4]

# Append WAN packets to the list
wan_packets.extend([wan_pkt1, wan_pkt2, wan_pkt3, wan_pkt4, wan_pkt5])

# Save LAN packets as a PCAP file
wrpcap("lan_packets.pcap", lan_packets)

# Save WAN packets as a PCAP file
wrpcap("wan_packets.pcap", wan_packets)
