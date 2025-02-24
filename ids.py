from scapy.all import sniff, IP, TCP, UDP
import sys

# Define detection rules
RULES = [
    {"name": "SYN Flood Attack", "protocol": "TCP", "flags": "S", "threshold": 100},
    {"name": "DNS Amplification Attack", "protocol": "UDP", "dport": 53, "threshold": 50},
]

# Function to analyze packets
def analyze_packet(packet):
    for rule in RULES:
        if rule["protocol"] == "TCP" and TCP in packet:
            if packet[TCP].flags == rule["flags"]:
                print(f"[!] Potential intrusion detected:\n"
                      f"    Source IP: {packet[IP].src}\n"
                      f"    Destination IP: {packet[IP].dst}\n"
                      f"    Protocol: TCP\n"
                      f"    Signature: {rule['name']}\n")
        elif rule["protocol"] == "UDP" and UDP in packet:
            if packet[UDP].dport == rule["dport"]:
                print(f"[!] Potential intrusion detected:\n"
                      f"    Source IP: {packet[IP].src}\n"
                      f"    Destination IP: {packet[IP].dst}\n"
                      f"    Protocol: UDP\n"
                      f"    Signature: {rule['name']}\n")

# Function to start IDS
def start_ids(interface):
    print(f"[*] Starting IDS on interface {interface}...\n")
    sniff(iface=interface, prn=analyze_packet, store=False)

# Main function
def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 ids.py <interface>")
        sys.exit(1)

    interface = sys.argv[1]
    start_ids(interface)

if __name__ == "__main__":
    main()
