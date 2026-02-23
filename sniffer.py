from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict

# --- SENTINEL CONFIGURATION ---

packet_counts = defaultdict(int)


THRESHOLD = 10 
# ------------------------------

def process_packet(packet):
    # Only process packets with an IP layer
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # 1. Update the tally for the source IP
        packet_counts[ip_src] += 1
        
        # 2. Check if the IP has crossed the danger threshold
        if packet_counts[ip_src] >= THRESHOLD:
            print(f"[!!!] ALERT: {ip_src} is flooding us! (Packet {packet_counts[ip_src]})")
            
        # 3. If they are below the threshold, just print normal traffic
        elif packet_counts[ip_src] < THRESHOLD:
            print(f"[+] Normal Traffic: {ip_src} --> {ip_dst}")

print("Sentinel NIDS is monitoring... (Endless Mode Active - Press Ctrl+C to stop)")

# For Info - (count=0 means infinite)
sniff(iface='eth0', prn=process_packet, count=0)
