from scapy.all import sniff, IP, conf
import pandas as pd
from datetime import datetime

packets_data = []

def process_packet(packet):
    if IP in packet:
        packets_data.append({
            "timestamp": datetime.fromtimestamp(packet.time),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "length": len(packet)
        })

# Use L3 socket instead of default
conf.L3socket
sniff(prn=process_packet, count=100, store=False)
