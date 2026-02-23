# Sentinel: Network Intrusion Detection & Prevention System (NIDS/NIPS)

## Overview
Sentinel is a lightweight, custom-built cybersecurity tool designed to monitor network traffic in real-time and detect malicious activity. Built entirely in Python using the `scapy` library, this project demonstrates the practical evolution of network defense: starting as a passive Network Intrusion Detection System (NIDS) and scaling into an active Intrusion Prevention System (NIPS) with enterprise-grade logging and automated firewall mitigation.

## The Lab Environment
This project was developed and tested within a secure, isolated VirtualBox homelab:
* **The Defender (Blue Team):** Kali Linux 
* **The Attacker (Red Team):** Metasploitable 2 
* **Network Architecture:** Isolated Host-Only VirtualBox Network.

---

## Phase 1: Custom NIDS (Passive Detection)
**File:** `sniffer.py`

The foundational version of Sentinel passively sniffs network packets, analyzes traffic patterns, and triggers automated alerts when predefined security thresholds are breached.

### Features
* **Real-Time Packet Sniffing:** Captures live network traffic directly from the designated network interface (`eth0`).
* **Stateful Tracking:** Utilizes Python dictionaries to map and count packets originating from unique IP addresses.
* **Denial-of-Service (DoS) Detection:** Identifies volumetric attacks (like ICMP Ping Floods) by comparing incoming traffic against a hardcoded danger threshold.
* **Modular Execution:** Can be configured for continuous live monitoring or controlled burst captures.

### Proof of Concept: Live-Fire Testing
To validate the NIDS, simulated ICMP Flood attacks (`ping -f`) were launched from the Metasploitable attacker machine against the Kali Linux defender. The script was tested under two different operational configurations to demonstrate its modularity.

**Test 1: Endless Mode (Live DoS Monitoring)**
By configuring the capture limit to `count=0`, Sentinel operates in a continuous monitoring state. During a volumetric flood attack, the system successfully tracks the rapid influx of packets and outputs a continuous stream of alerts, accurately reflecting a live network under heavy fire.

<img width="1920" height="927" alt="HACK1" src="https://github.com/user-attachments/assets/77ddd9c6-1209-49e9-aae7-70f63b91f64d" />


**Test 2: Controlled Capture & Clean Exit**
To demonstrate clean logging and automated shutdown, the tool was reconfigured to `count=25`. Sentinel successfully registered the baseline traffic, instantly detected the attack the millisecond the threshold of 10 packets was crossed, triggered the `[!!!] SECURITY ALERT`, and cleanly exited the capture sequence.

<img width="1920" height="927" alt="HACK2" src="https://github.com/user-attachments/assets/d25898b8-2f8e-400d-8997-43e797ba4626" />


---

## Phase 2: NIPS Evolution (Active Mitigation & Logging)
**Files:** `sentinel_logger.py` & `sentinel_nips.py`

To elevate the tool from a basic monitoring script to an enterprise-grade utility, Sentinel was upgraded with persistent memory and active threat mitigation capabilities.

### Upgrade 1: Persistent Threat Logging
Terminal alerts are ephemeral. This upgrade automatically generates a `security_log.csv` file, permanently recording the Timestamp, Attacker IP, Attack Type, and Action Taken. This mimics how commercial tools format threat data for SIEM ingestion (e.g., Splunk).

<img width="1920" height="927" alt="hack3LOG" src="https://github.com/user-attachments/assets/2b9cd45d-5903-4b94-a681-8db31b5d7fd0" />



### Upgrade 2: Automated Firewall Mitigation
Instead of just alerting, the NIPS actively neutralizes the threat. The exact millisecond an attacking IP crosses the DoS threshold, Sentinel logs the event as "BLOCKED", interfaces directly with the Linux kernel, and executes an `iptables` rule to permanently drop all traffic from the malicious IP into a black hole.

<img width="1920" height="927" alt="hack4FW" src="https://github.com/user-attachments/assets/a569765d-d6d1-476c-92b6-2f3aaeb5037b" />



---

## Tech Stack
* **Language:** Python 3
* **Libraries:** Scapy, Collections, OS, CSV, Datetime
* **Environment:** Linux CLI, VirtualBox, iptables
