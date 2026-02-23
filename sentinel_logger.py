from scapy.all import sniff, IP
from collections import defaultdict
import csv
from datetime import datetime
import os

# --- SENTINEL CONFIGURATION ---
packet_counts = defaultdict(int)
THRESHOLD = 10 
LOG_FILE = "security_log.csv"
# ------------------------------

# Create the CSV file with headers if it doesn't exist yet
if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Attacker_IP", "Attack_Type", "Packets", "Action"])

def log_alert(ip_src, packet_count):
    """Writes the attack details to a persistent CSV file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, ip_src, "ICMP Flood", packet_count, "Logged"])

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        packet_counts[ip_src] += 1
        
        if packet_counts[ip_src] >= THRESHOLD:
            print(f"[!!!] ALERT: {ip_src} is flooding us! (Packet {packet_counts[ip_src]})")
            # Trigger the new logging function!
            log_alert(ip_src, packet_counts[ip_src])
            
        elif packet_counts[ip_src] < THRESHOLD:
            print(f"[+] Normal Traffic: {ip_src} --> {ip_dst}")

print("Sentinel NIDS is monitoring... (Logging Enabled - Press Ctrl+C to stop)")
sniff(iface='eth0', prn=process_packet, count=25)
