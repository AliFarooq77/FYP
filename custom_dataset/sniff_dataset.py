import os
import csv
from scapy.all import sniff, IP, TCP

# Output CSV file
CSV_FILE = 'temp.csv'

# Updated column names to include src_port and dst_port
FEATURE_COLUMNS = [
    'Frame Length',
    'TCP Window Size',
    'IP TTL',
    'Has SYN',
    'Has ACK',
    'Has RST',
    'Payload Length',
    'TCP Option Count',
    'TCP Header Length',
    'Source Port',
    'Destination Port'
]

# Ensure CSV file exists with headers
def initialize_csv():
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, mode='w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
            writer.writeheader()

# Extract features from a packet
def extract_features(packet):
    features = {
        'Frame Length': len(packet),
        'TCP Window Size': packet[TCP].window if packet.haslayer(TCP) else 0,
        'IP TTL': packet[IP].ttl if packet.haslayer(IP) else 0,
        'Has SYN': int(packet[TCP].flags & 0x02 != 0) if packet.haslayer(TCP) else 0,
        'Has ACK': int(packet[TCP].flags & 0x10 != 0) if packet.haslayer(TCP) else 0,
        'Has RST': int(packet[TCP].flags & 0x04 != 0) if packet.haslayer(TCP) else 0,
        'Payload Length': len(packet[TCP].payload) if packet.haslayer(TCP) else 0,
        'TCP Option Count': len(packet[TCP].options) if packet.haslayer(TCP) else 0,
        'TCP Header Length': packet[TCP].dataofs * 4 if packet.haslayer(TCP) else 0,
        'Source Port': packet[TCP].sport,
        'Destination Port': packet[TCP].dport
    }

    print("\n--- Extracted Features ---")
    for key, value in features.items():
        print(f"{key}: {value}")
    
    # Append to CSV
    with open(CSV_FILE, mode='a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
        writer.writerow(features)

# Process only incoming packets (assumes your IP ends in .213 for example)
def process_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Replace this with your system IP if you want to narrow down further
        local_ip = "192.168.1.104"
        #source_ip = "192.168.0.204"
        if packet[IP].dst == local_ip: #and packet[IP].src == source_ip:
            extract_features(packet)

# Main function
def main():
    print("🔍 Sniffing incoming TCP traffic...")
    initialize_csv()
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()

