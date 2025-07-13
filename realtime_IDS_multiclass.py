import os
#import joblib
from scapy.all import sniff, IP, TCP
import numpy as np
import pandas as pd
import joblib

# Path to your trained model
MODEL_PATH = 'random_forest_for_local_traffic.pkl'

# Features used in prediction
MODEL_FEATURES = [
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

# Load your trained model
print("📦 Loading trained model...")
model = joblib.load(MODEL_PATH)

# Extract relevant features from a packet
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
        'Source Port': packet[TCP].sport if packet.haslayer(TCP) else 0,
        'Destination Port': packet[TCP].dport if packet.haslayer(TCP) else 0
    }
    return features

# Make a prediction for each packet
def process_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[IP].dst == '192.168.1.108':
            features = extract_features(packet)
            feature_values = [features[feature] for feature in MODEL_FEATURES]
            input_df = pd.DataFrame([feature_values], columns=MODEL_FEATURES)

            # Predict using the loaded model
            prediction = model.predict(input_df)[0]

            # Convert numeric label back to text
            label_map = {0: '✅ Benign', 1: '🚨 Dos', 2: '⚠️ Portscan'}
            label = label_map.get(prediction, '❓ Unknown')

            # Show prediction
            print("\n--- Packet Info ---")
            for key in MODEL_FEATURES:
                print(f"{key}: {features[key]}")
            print(f"Destination IP: {packet[IP].dst}")
            print(f"\n🧠 Prediction: {label}")

# Main sniffing function
def main():
    print("🌐 Starting real-time packet analysis (TCP packets)...")
    sniff(filter="tcp", prn=process_packet, store=0)

if __name__ == "__main__":
    main()

