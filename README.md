# PCAP Analyzer & Network Attack Detection Tool

## Project Overview
The **PCAP Analyzer** is a Python-based CLI tool that analyzes network traffic captured in `.pcap` files. It performs both network performance analysis and attack detection, simulating a lightweight Intrusion Detection System (IDS). The tool helps identify suspicious patterns, anomalies, and common attacks in controlled lab environments.

---

## Features

### Network Performance Analysis
- **Total Packets:** Counts all packets in the capture file.
- **Top Talker:** Identifies the IP generating the most traffic.
- **Top Protocol:** Determines the most frequent protocol (TCP, UDP, ICMP, DNS, etc.).
- **Retransmissions:** Detects TCP retransmissions.
- **Bandwidth Usage:** Calculates total captured traffic in KB.

### Attack Detection
- **Port Scan Detection:** Detects IPs scanning multiple ports.
- **SYN Flood Detection:** Flags excessive TCP SYN packets.
- **ARP Spoofing Detection:** Detects multiple MAC addresses for the same IP.
- **DNS Tunneling Detection:** Detects high-frequency queries with long, high-entropy subdomains.
- **Brute Force Detection:** Identifies repeated login attempts or high SYN packet counts from a single IP.

---

## Requirements
- Python 3.x
- Tshark (Wireshark CLI)
- Linux environment recommended

---

## Installation
1. Install **Tshark**:

```bash
sudo apt update
sudo apt install tshark -y
```

### Clone the repository:
```bash
git clone <your-repo-url>
cd <repo-folder>
```

### Ensure Python 3 is installed:
```bash
python3 --version
```

### Usage
- Capture network traffic with Tshark (optional):

```bash
sudo tshark -i any -w capture.pcap
```

- Run the analyzer:
```bash
python3 tshark_ids_final.py
```

- Enter the path to your .pcap file when prompted:
- Enter PCAP file path: capture.pcap
- View the detailed report, including network performance and detected attacks.

- Legal & Lab Safety
- This tool is intended for educational and lab use only.
- Generate traffic only on networks you control.

- Avoid sending automated queries to public servers to prevent legal issues.

Example Output
==============================
PCAP ANALYSIS REPORT
==============================

Network Performance:
- Total Packets: 200
- Top Talker: 192.168.54.3
- Top Protocol: DNS
- Avg RTT: N/A
- Retransmissions: 0
- Bandwidth: 12.5 KB

Attack Detection:
- Port Scan: NO
- SYN Flood: NO
- ARP Spoofing: NO
- DNS Tunneling: YES
- Brute Force: NO

## Learning Outcomes
- Practical experience in network traffic analysis.
- Understanding of intrusion detection techniques.
- Python scripting for Tshark automation.
- Detecting attacks like DNS tunneling, port scans, and brute force attempts.

## Author
- Dharson Ram – Final-Year B.Tech Cybersecurity Student

