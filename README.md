# Machine Learning-Based Intrusion Detection System with Automated ARP Spoofing (Ghost Route)

This project combines **Machine Learning for Intrusion Detection** with automated **ARP spoofing techniques** to simulate and analyze network behavior in a controlled lab environment.

It is ideal for researchers, students, and cybersecurity enthusiasts interested in:
- Real-time packet analysis
- Local area network (LAN) spoofing experiments
- Behavior of ML-based IDS systems in offensive and defensive scenarios

---

## Project Objective

The goal is to automate:
- **ARP spoofing of selected ESP32 devices** on a local network (via custom script `arpspoof-esps.sh`)
- **Launching a trained Machine Learning model** that performs real-time classification of traffic as:
  - ✅ Benign
  - 🚨 Denial of Service (DoS)
  - ⚠️ Port Scan

All spoofing and IDS launching tasks are handled by a single Bash script.

---

## 🧩 Components

### 1. `arpspoof-esps.sh`
- Discovers active hosts on the network
- Spoofs their ARP tables to impersonate ESP32 IPs
- Launches the Python-based IDS in a new terminal
- Sets up system routing and forwarding rules
- Cleans up on exit

### 2. `realtime_IDS_multiclass.py`
- Captures TCP/IP packets using `scapy`
- Extracts meaningful network features
- Uses a pre-trained `Random Forest` model to classify packets in real time
- Provides console output showing prediction details

### 3. `random_forest_for_local_traffic.pkl`
- Trained on extracted TCP/IP features
- Distinguishes between normal and malicious behavior

---

## Directory Structure

```
.
├── arpspoof-esps.sh                     # Automation + spoofing script
├── realtime_IDS_multiclass.py          # Real-time IDS using scapy and ML
├── random_forest_for_local_traffic.pkl # Pre-trained model (not included)
```

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/alifarooq77/FYP.git
cd FYP
```

### 2. Run the Main Script

```bash
chmod +x arpspoof-esps.sh
sudo ./arpspoof-esps.sh
```

The script will:
- Scan the LAN for active devices
- Spoof them using ARP (targeting ESP32 IPs)
- Launch the IDS in a new terminal using virtualenv

---

## Python Dependencies (Auto Installed)

- scapy
- pandas
- numpy
- joblib
- scikit-learn

These are installed automatically in a `myenv` virtual environment.

---

## Features Used for Detection

The IDS analyzes the following per-packet features:
- Frame Length
- TCP Window Size
- IP TTL
- SYN/ACK/RST Flags
- Payload Length
- TCP Option Count
- TCP Header Length
- Source & Destination Ports

---

## ⚠️ Disclaimer

This tool is intended for **educational and research purposes only**.
Running ARP spoofing on networks you do not own or control may violate laws and ethics.

Use in controlled lab environments only.

---

## Author

**Muhammad Ali Farooq**  
Version: 1.0  
Tool: Machine Learning IDS + Ghost Route Automation

---

## License

This project is licensed under the GNU General Public License v3.0.

---

## Contributions

Feel free to fork, improve, and suggest enhancements!
