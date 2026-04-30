# 🚨 SOC Hybrid Project – Real-Time Threat Detection & Response

## 🔍 Overview
This project implements a complete Security Operations Center (SOC) combining detection, correlation, visualization, alerting, and automated response. The architecture is hybrid: a Raspberry Pi acts as a detection node (Suricata + Cowrie + Correlator), while a Mac M1 hosts the SIEM platform using Wazuh via Docker. The system simulates real-world attacks and processes them end-to-end: Detection → Correlation → Enrichment → Alerting → Visualization → Response.

## 🧱 Architecture
Attacker → Raspberry Pi (Suricata + Cowrie + Correlator) → incidents.json → Wazuh Agent → Wazuh Manager (Docker) → Wazuh Dashboard + Custom SOC Dashboard + Discord Alerts.

## ⚙️ Core Components
Raspberry Pi (Detection Layer): Suricata (network IDS), Cowrie (SSH honeypot), and a custom Python correlator that aggregates logs, tracks attackers, computes risk scores, detects attack stages, builds attack chains, maps MITRE ATT&CK techniques, and generates structured incidents.
Wazuh SIEM (Analysis Layer): log ingestion, custom rules, alert classification, visualization, and automated response tracking.
Correlation Engine: analyzes Suricata and Cowrie logs (network activity, login attempts, commands, suspicious behavior) and transforms them into SOC incidents.

## 📊 Scoring System
Suricata alert (+1), SSH activity (+1), failed login (+3), successful login (+8), command executed (+5), suspicious command (+12).

## 🚨 Severity Levels
Score <10 = Low, 10–24 = Medium, 25–29 = High, ≥30 = Critical.

## 🔗 Attack Chain Detection
The system reconstructs attacker behavior such as reconnaissance, bruteforce, exploitation, and post-exploitation. Example: ssh_intrusion_to_post_exploitation.

## 🧬 MITRE ATT&CK Mapping
Login success → T1078 (Valid Accounts), Command execution → T1059, File download → T1105, Bruteforce → T1110, Network scan → T1046.

## 📦 Example Incident
{"attack_chain":"ssh_intrusion_to_post_exploitation","src_ip":"192.168.1.18","attack_stage":"post_exploitation","severity":"critical","score":49,"mitre":["T1078 - Valid Accounts","T1059 - Command Execution","T1105 - Ingress Tool Transfer"]}

## 📊 Dashboards
Wazuh Dashboard: alerts timeline, top IPs, attack stages, commands, MITRE mapping.
Custom SOC Dashboard: real-time attack visualization, incident feed, attack map, active threats, response status.

## 🚨 Discord Alerting
Critical alerts are sent in real-time via webhook with key information (IP, stage, score, reason).

## 🛡️ Automated Response
When a threat exceeds a threshold, the system automatically blocks the IP using iptables. Wazuh logs the action and a Discord alert is triggered. Safety mechanisms prevent blocking local or whitelisted IPs.

## 🧪 Attack Simulation
The system is tested using SSH attack scenarios: connection attempts, login success, command execution (ls, chmod, curl), and suspicious behavior. These actions trigger detection, correlation, alerting, and response mechanisms.

## 📁 Project Structure
SOC-Project/
├── correlator/ (correlator.py)
├── dashboard/ (app.py)
├── scripts/ (attack simulation)
├── wazuh/ (ossec.conf, rules, integrations)
├── README.md

## 🚀 Key Features
- Multi-source log correlation
- MITRE ATT&CK integration
- Attack chain detection
- Real-time dashboards
- Discord alerting
- Automated IP blocking
- Full SOC pipeline simulation

## 🎯 Conclusion
This project demonstrates a full SOC workflow from detection to automated response using real cybersecurity tools. It highlights practical Blue Team skills including log analysis, correlation, threat detection, SIEM usage, and automation. The system successfully detects and blocks malicious behavior, proving the effectiveness of the implemented SOC architecture.
