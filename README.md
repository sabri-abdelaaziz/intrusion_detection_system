# intusion_detection_system

    1 - Pcap and parsing 
    
capture packets (PCAP) and parse them in Python, ideally by running a single Python file that does everything automatically:
1️⃣ captures live traffic or loads from a .pcap file,
2️⃣ parses packets (extracts features like source/destination IP, ports, protocol, etc.),
3️⃣ saves them (CSV/Parquet) for later analysis or ML training.

Step 1 — Install Required Libraries
pip install scapy pyshark pandas
✅ scapy — capture and parse packets directly in Python.
✅ pyshark — wrapper around Wireshark’s tshark (more detailed parsing).
✅ pandas — for saving to CSV or further processing.
