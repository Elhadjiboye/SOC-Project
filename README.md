# 🚨 SOC Hybrid Project – Real-Time Threat Detection & Response

## 🔍 Overview

This project implements a complete Security Operations Center (SOC) capable of detecting, analyzing, visualizing, and responding to cyber attacks in real time.

The architecture is hybrid:
- A Raspberry Pi acts as a detection and correlation node
- A Mac (M1) hosts the SIEM using Wazuh via Docker

The system simulates real-world attacks and processes them end-to-end:

Detection → Correlation → Enrichment → Alerting → Visualization → Response

---

## 🧱 Architecture

Attacker  
↓  
Raspberry Pi (Suricata + Cowrie + Correlator)  
↓  
incidents.json  
↓  
Wazuh Agent  
↓  
Wazuh Manager (Docker on Mac)  
↓  
Wazuh Dashboard + Custom SOC Dashboard + Discord Alerts  

---

## ⚙️ Core Components

### 🔹 Raspberry Pi (Detection Layer)
- Suricata (Network IDS)
- Cowrie (SSH Honeypot)
- Custom Python Correlator

The correlator:
- Aggregates logs from Suricata and Cowrie
- Tracks attacker behavior
- Computes risk scores
- Detects attack stages
- Builds attack chains
- Maps MITRE ATT&CK techniques
- Generates structured incidents

---

### 🔹 Wazuh SIEM (Analysis Layer)
- Log ingestion from incidents.json
- Custom detection rules
- Alert classification
- Dashboard visualization
- Integration with external systems

---

### 🔹 Custom SOC Dashboard (Flask)
- Real-time monitoring interface
- Attack map visualization
- Live incident feed
- Top attackers ranking
- Command tracking
- System health monitoring

---

## 📊 Scoring System

- Suricata alert → +1  
- SSH network activity → +1  
- Failed login → +3  
- Successful login → +8  
- Command execution → +5  
- Suspicious command → +12  

---

## 🚨 Severity Levels

- Score < 10 → Low  
- 10 – 24 → Medium  
- 25 – 29 → High  
- ≥ 30 → Critical  

---

## 🔗 Attack Chain Detection

The correlator reconstructs attacker behavior:

- Reconnaissance  
- Bruteforce  
- Exploitation  
- Post-exploitation  

Example:
ssh_intrusion_to_post_exploitation

---

## 🧬 MITRE ATT&CK Mapping

- T1078 → Valid Accounts  
- T1059 → Command Execution  
- T1105 → Ingress Tool Transfer  
- T1110 → Brute Force  
- T1046 → Network Scan  

---

## 📦 Example Incident

```json
{
  "attack_chain": "ssh_intrusion_to_post_exploitation",
  "src_ip": "192.168.1.18",
  "attack_stage": "post_exploitation",
  "severity": "critical",
  "score": 49,
  "mitre": [
    "T1078 - Valid Accounts",
    "T1059 - Command Execution",
    "T1105 - Ingress Tool Transfer"
  ]
}
```

---

## 📊 Dashboards

### 🔹 Wazuh Dashboard
- Alerts timeline
- Top attacking IPs
- Attack stages distribution
- Command activity
- MITRE techniques visualization

### 🔹 Custom SOC Dashboard
- Real-time monitoring
- Attack map
- Live incident feed
- Top attackers
- System status

---

## 🚨 Discord Alerting

Critical alerts are sent in real time with:
- Source IP
- Attack stage
- Score
- Reason

---

## 🛡️ Automated Response

- Automatic IP blocking (iptables)
- Wazuh logs the response
- Discord alert triggered

Safeguards:
- Local IP ignored
- Whitelisted IPs protected

---

## 🧪 Attack Simulation

- SSH connection attempts  
- Login success  
- Command execution (ls, chmod, curl)  
- Suspicious behavior  

Triggers full SOC pipeline.

---

## 📁 Project Structure

```bash
SOC-Project/
├── correlator/        (correlator.py)
├── dashboard/         (app.py)
├── scripts/           (attack simulation)
├── wazuh/             (configs, rules, integrations)
└── README.md
```

---

## 🚀 Key Features

- Multi-source log correlation
- Real-time attack detection
- MITRE ATT&CK integration
- Attack chain reconstruction
- Custom SOC dashboard
- Wazuh SIEM integration
- Discord alerting
- Automated IP blocking
- End-to-end SOC simulation

---

## 🎯 Conclusion

This project demonstrates a fully operational SOC pipeline from detection to automated response.

It highlights real Blue Team skills:
- Threat detection
- Event correlation
- SIEM usage
- Security automation

The system successfully detects, analyzes, and blocks malicious activity.

---

## 👨‍💻 Author

SOC Project by DARK – Cybersecurity & Blue Team Engineering