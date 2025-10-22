from scapy.all import sniff, IP, conf
import pandas as pd
from datetime import datetime

packets_data = []

def process_packet(packet):
    if IP in packet:
        # Append packet data to the list
        packets_data.append({
            "timestamp": datetime.fromtimestamp(packet.time),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": packet[IP].proto,
            "length": len(packet)
        })

# Use L3 socket instead of the default
conf.L3socket

# Start sniffing 100 packets
sniff(prn=process_packet, count=100, store=False)

# Convert packet data to a DataFrame
df = pd.DataFrame(packets_data)

# Save the DataFrame to a CSV file
csv_file = "packets_data.csv"
df.to_csv(csv_file, index=False)

# Display the saved CSV content
print(f"Saved packet data to {csv_file}")
print(df)
