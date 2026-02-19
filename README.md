# Sentinel: Custom Network Intrusion Detection System (NIDS)

## Overview
Sentinel is a lightweight, custom-built Network Intrusion Detection System (NIDS) designed to monitor network traffic in real-time and detect malicious activity. Built entirely in Python using the `scapy` library, this tool passively sniffs network packets, analyzes traffic patterns, and triggers automated alerts when predefined security thresholds are breached.

## The Lab Environment
This project was developed and tested within a secure, isolated VirtualBox homelab:
* **The Defender (Blue Team):** Kali Linux running the Sentinel script.
* **The Attacker (Red Team):** Metasploitable 2.
* **Network Architecture:** Isolated Host-Only VirtualBox Network.

## Features
* **Real-Time Packet Sniffing:** Captures live network traffic directly from the designated network interface (`eth0`).
* **Stateful Tracking:** Utilizes Python dictionaries to map and count packets originating from unique IP addresses.
* **Denial-of-Service (DoS) Detection:** Identifies volumetric attacks (like ICMP Ping Floods) by comparing incoming traffic against a hardcoded danger threshold.
* **Modular Execution:** Can be configured for continuous live monitoring or controlled burst captures.

## Proof of Concept: Live-Fire Testing
To validate the NIDS, simulated ICMP Flood attacks (`ping -f`) were launched from the Metasploitable attacker machine against the Kali Linux defender. The script was tested under two different operational configurations to demonstrate its modularity.

### Test 1: Endless Mode (Live DoS Monitoring)
By configuring the capture limit to `count=0`, Sentinel operates in a continuous monitoring state. During a volumetric flood attack, the system successfully tracks the rapid influx of packets and outputs a continuous stream of alerts, accurately reflecting a live network under heavy fire.

<img width="1920" height="927" alt="HACK1" src="https://github.com/user-attachments/assets/8eaba225-5425-4461-84e5-a2869e498bab" />

### Test 2: Controlled Capture & Clean Exit
To demonstrate clean logging and automated shutdown, the tool was reconfigured to `count=25`. Sentinel successfully registered the baseline traffic, instantly detected the attack the millisecond the threshold of 10 packets was crossed, triggered the `[!!!] SECURITY ALERT`, and cleanly exited the capture sequence.

<img width="1920" height="927" alt="HACK2" src="https://github.com/user-attachments/assets/0bd2355d-45a4-43a4-b61a-1080649c6e4a" />

## Tech Stack
* **Language:** Python 3
* **Libraries:** Scapy, Collections
* **Environment:** Linux CLI, VirtualBox
