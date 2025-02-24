# Intrusion Detection System (IDS)

A Python-based Intrusion Detection System (IDS) built for Kali Linux. This tool monitors network traffic in real-time and detects potential intrusions or malicious activities using signature-based detection.

---

## How It Works

The IDS works by analyzing network packets and comparing them against a set of predefined rules or signatures to identify suspicious behavior. Here's how it functions:

1. **Packet Capture**:
   - The tool uses the `scapy` library to capture network packets in real-time.
   - It listens on a specified network interface (e.g., `eth0` or `wlan0`).

2. **Signature-Based Detection**:
   - The tool checks each packet against a set of rules or signatures (e.g., known attack patterns).
   - If a packet matches a rule, the tool flags it as a potential intrusion.

3. **Alert System**:
   - When a potential intrusion is detected, the tool generates an alert with details about the suspicious activity.

4. **Logging**:
   - All alerts are logged to a file for further analysis.

---

## How to Use

### Prerequisites
- Kali Linux (or any Linux distribution with Python 3).
- Python 3.x.
- The `scapy` library (install using `pip`).

### Installation

1. **Install Required Libraries**:
   ```bash
   sudo apt update
   sudo apt install python3-pip
   pip3 install scapy

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/ids-tool.git
   cd ids-tool

3. **Run the Script**:
   ```bash
   sudo python3 ids.py

4. **Usage**:
   ```bash
   sudo python3 ids.py
Enter the network interface to monitor (e.g., eth0, wlan0).

The tool will start monitoring network traffic and display alerts for potential intrusions.

Example Output
 ```bash
$ sudo python3 ids.py
Enter the network interface to monitor (e.g., eth0, wlan0): wlan0
[*] Starting IDS on interface wlan0...

[!] Potential intrusion detected:
    Source IP: 192.168.1.100
    Destination IP: 192.168.1.1
    Protocol: TCP
    Signature: SYN Flood Attack

[!] Potential intrusion detected:
    Source IP: 192.168.1.200
    Destination IP: 192.168.1.1
    Protocol: UDP
    Signature: DNS Amplification Attack

[*] Monitoring in progress... (Press Ctrl+C to stop)
