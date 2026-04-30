# 🚨 SOC Hybrid Project – Real-Time Threat Detection, Correlation & Automated Response

## 🔍 Overview
This project implements a complete end-to-end Security Operations Center (SOC) designed to simulate real-world cyber defense operations. It combines multiple cybersecurity tools into a unified pipeline capable of detecting, analyzing, correlating, visualizing, and responding to cyber attacks in real time. The architecture is hybrid: a Raspberry Pi is used as a detection and correlation node, while a Mac M1 hosts the SIEM platform using Wazuh via Docker. The system follows a full SOC workflow: Detection → Correlation → Enrichment → Alerting → Visualization → Response.

## 🧱 Architecture
Attacker → Raspberry Pi (Suricata + Cowrie + Correlator) → incidents.json → Wazuh Agent → Wazuh Manager (Docker) → Wazuh Dashboard + Custom SOC Dashboard + Discord Alerts.

## ⚙️ Core Components

### 🟢 Detection & Correlation Layer (Raspberry Pi)
The Raspberry Pi acts as a realistic exposed system and security sensor. It includes:
- Suricata: a network IDS that analyzes traffic and detects suspicious behavior such as SSH flows and scans.
- Cowrie: an SSH honeypot that captures attacker interactions including login attempts, commands, and sessions.
- Correlator (Python): a custom engine that aggregates logs, tracks attacker behavior, computes risk scores, detects attack stages, builds attack chains, maps MITRE ATT&CK techniques, and generates structured incidents in JSON format.

### 🔵 SIEM Layer (Wazuh on Mac M1)
Wazuh is deployed using Docker and acts as the central SOC platform. It includes:
- Wazuh Manager: log analysis and rule engine.
- Wazuh Indexer: data storage and indexing.
- Wazuh Dashboard: visualization and monitoring interface.
Capabilities include log ingestion, custom rule processing, alert classification, and visualization.

## 🧠 Correlation Engine Logic
The correlator transforms raw logs into actionable SOC incidents by analyzing:
- Network alerts (Suricata)
- SSH activity (Cowrie)
- Login attempts (failed and successful)
- Commands executed
- Suspicious behavior

## 📊 Scoring System
- Suricata alert: +1
- SSH activity: +1
- Failed login: +3
- Successful login: +8
- Command execution: +5
- Suspicious command: +12

## 🚨 Severity Levels
- Score < 10 → Low
- Score 10–24 → Medium
- Score 25–29 → High
- Score ≥ 30 → Critical

## 🔗 Attack Chain Detection
The system reconstructs attacker behavior across multiple stages:
- Reconnaissance
- Intrusion attempts
- Bruteforce
- Exploitation
- Post-exploitation
Example: ssh_intrusion_to_post_exploitation

## 🧬 MITRE ATT&CK Mapping
Each incident is enriched with MITRE ATT&CK techniques:
- T1078 → Valid Accounts
- T1059 → Command Execution
- T1105 → Ingress Tool Transfer
- T1110 → Brute Force
- T1046 → Network Discovery

## 📦 Example Correlated Incident
{"attack_chain":"ssh_intrusion_to_post_exploitation","src_ip":"192.168.1.18","attack_stage":"post_exploitation","severity":"critical","score":49,"mitre":["T1078 - Valid Accounts","T1059 - Command Execution","T1105 - Ingress Tool Transfer"]}

## 📊 Visualization
The system provides two levels of monitoring:
- Wazuh Dashboard: historical and analytical insights (alerts, IPs, stages, MITRE, commands)
- Custom SOC Dashboard: real-time monitoring (live feed, active threats, attack progression, response status)

## 🚨 Discord Alerting
Critical alerts are automatically sent in real-time via webhook, including source IP, attack stage, score, and detection reason.

## 🛡️ Automated Response
When a threat exceeds a defined threshold:
- The attacker IP is blocked using iptables
- The action is logged in Wazuh
- A high-severity alert is generated
- A Discord notification is triggered
Safety mechanisms prevent blocking local or whitelisted IPs.

## 🧪 Attack Simulation
The system is tested using SSH attack scenarios including login attempts, successful authentication, and command execution such as ls, chmod, and curl. These actions trigger the full SOC pipeline from detection to automated response.

## 📁 Project Structure
SOC-Project/
├── correlator/ (correlator.py)
├── dashboard/ (app.py)
├── scripts/ (attack simulation)
├── wazuh/ (configs, rules, integrations)
├── README.md

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

## 🎯 Conclusion
This project demonstrates a fully operational SOC pipeline from raw log collection to automated response. It highlights practical Blue Team skills including threat detection, event correlation, SIEM usage, and automation. The system successfully detects, analyzes, and blocks malicious activity, reflecting a realistic SOC environment.