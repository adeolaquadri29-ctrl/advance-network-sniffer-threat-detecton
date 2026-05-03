# advance-network-sniffer-threat-detecton
Advanced Python-based network sniffer with real-time packet analysis, GeoIP enrichment, threat detection, JSON logging, and a live Flask dashboard.

# 🚀 Advanced Network Sniffer & Threat Detection System

## 📌 Overview

This project is a Python-based network monitoring and threat detection tool designed to capture, analyze, and visualize live network traffic in real time.

It simulates a lightweight SOC (Security Operations Center) monitoring solution by combining packet sniffing, protocol analysis, GeoIP enrichment, threat detection logic, and a web-based dashboard.

---

## 🎯 Objectives

- Capture live network traffic

- Analyze packet structure and protocols

- Detect suspicious behavior

- Provide real-time visibility into network activity

- Generate structured logs for security analysis

---

## 🏗️ Architecture

```text

Network Traffic

      ↓

Packet Capture (Scapy)

      ↓

Packet Analysis Engine

      ↓

Threat Detection Engine

      ↓

GeoIP Enrichment

      ↓

JSON Logging

      ↓

Flask Dashboard (Real-Time Monitoring)

```

---

## ⚙️ Technologies Used

- Python

- Scapy

- Flask

- GeoIP2 (MaxMind)

- JSON

---

## 🔍 Packet Capture & Analysis

The tool captures and analyzes:

- Source & Destination IP addresses

- Source & Destination ports

- Protocols (TCP, UDP, ICMP)

- DNS queries

- Payload data

- Payload classification (HTTP, TLS, SSH)

---

## 🚨 Threat Detection & Analysis

### 🔹 Port Scan Detection

Identifies high-volume connection attempts from a single IP.

### 🔹 ICMP Flood Detection

Detects excessive ICMP traffic (DoS behavior).

### 🔹 Suspicious Port Monitoring

Flags traffic involving:

- 22 (SSH)

- 23 (Telnet)

- 3389 (RDP)

- 4444 (Backdoor)

### 🔹 Blacklisted IP Detection

Compares traffic against known malicious IPs.

---

## 🧪 Attack Scenarios Tested

- ICMP flood (ping flood)

- Port scanning using Nmap

- DNS query monitoring

- HTTP traffic inspection

---

## 🧠 MITRE ATT&CK Mapping

| Technique | Description |

|----------|------------|

| T1046 | Network Service Scanning |

| T1498 | Network Denial of Service |

| T1071 | Application Layer Protocol |

| T1040 | Network Sniffing |

---

## 📊 Logging & Monitoring

All captured traffic is stored in:

```text

sniffer_log.json

```

Benefits:

- Structured logging

- SIEM compatibility

- Easier incident investigation

---

## 🌐 Real-Time Dashboard

A Flask-based dashboard provides:

- Live traffic monitoring

- Alert visualization

- Packet details

- GeoIP location tracking

Access:

```text

http://127.0.0.1:5000

```

---

### 2. Install Dependencies

```bash

pip install -r requirements.txt

```

---

### 3. Download GeoIP Database

Download `GeoLite2-City.mmdb` from MaxMind and place it in the project directory.

---

### 4. Run the Application

```bash

sudo python3 app.py

```

---

## 🧪 Generate Test Traffic

```bash

ping 192.168.0.1

```

```bash

nmap -sS -A 192.168.0.1

```

```bash

hydra-L users.txt -P passwords.txt ssh://192.168.0.1 -V

```

---

## 🛡️ Incident Response Perspective

This tool helps identify:

- Network scanning activity

- Potential denial-of-service behavior

- Suspicious service access attempts

- Unknown or malicious IP communication

---

## 📚 Lessons Learned

- Deep understanding of network protocols

- Packet structure analysis

- Handling encrypted traffic (TLS)

- Implementing detection logic

- Building real-time monitoring systems

---

## 💡 Skills Gained

- Network traffic analysis

- Python development

- Threat detection techniques

- SOC monitoring concepts

- Web dashboard development

---

## 🔮 Future Improvements

- Threat intelligence API integration

- Automated IP blocking

- Machine learning anomaly detection

- Elasticsearch logging

- Docker containerization

---

## 👨‍💻 Author

Adeola Quadri
