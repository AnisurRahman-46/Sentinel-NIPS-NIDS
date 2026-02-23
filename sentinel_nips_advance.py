from scapy.all import sniff, IP
from collections import defaultdict
import csv
from datetime import datetime
import os

# --- SENTINEL CONFIGURATION ---
packet_counts = defaultdict(int)
blocked_ips = set() # NEW: Keeps track of IPs we have already blocked
THRESHOLD = 10 
LOG_FILE = "security_log.csv"
# ------------------------------

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "Attacker_IP", "Attack_Type", "Packets", "Action"])

def log_alert(ip_src, packet_count, action="Logged"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, ip_src, "ICMP Flood", packet_count, action])

def block_ip(ip_src):
    """NEW: Tells the Linux Firewall to drop all traffic from the hacker!"""
    print(f"\n[X] THREAT MITIGATED: Dropping all traffic from {ip_src} via iptables!\n")
    #Linux command to block an IP
    os.system(f"iptables -A INPUT -s {ip_src} -j DROP")

def process_packet(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        packet_counts[ip_src] += 1
        
        if packet_counts[ip_src] >= THRESHOLD:
            
            if ip_src not in blocked_ips:
                print(f"[!!!] ALERT: {ip_src} crossed threshold! Initiating block...")
                block_ip(ip_src)
                blocked_ips.add(ip_src) # Remember that we blocked them
                log_alert(ip_src, packet_counts[ip_src], action="BLOCKED")
            
        elif packet_counts[ip_src] < THRESHOLD:
            print(f"[+] Normal Traffic: {ip_src} --> {ip_dst}")

print("Sentinel NIPS is monitoring... (ACTIVE FIREWALL MITIGATION ENABLED)")
sniff(iface='eth0', prn=process_packet, count=50)
