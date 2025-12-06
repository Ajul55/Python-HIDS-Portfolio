# 🛡️ Mini-SIEM: Python-Based Intrusion Detection System
> A lightweight, custom-built Log Analysis Engine mapped to MITRE ATT&CK.

## 📌 Project Overview
As a cybersecurity enthusiast running a low-spec environment (4GB RAM Linux Mint), I could not deploy heavy enterprise SIEMs like Splunk or Wazuh. Instead of giving up, I engineered my own **signature-based detection engine** in Python.

This tool monitors Linux system logs in real-time, applies Regex patterns to identify anomalies (Brute Force, Persistence), and generates structured JSON alerts for analysis.

## 🚀 Key Features
* **Real-Time Log Ingestion:** "Tails" the `/var/log/auth.log` file efficiently without consuming high CPU/RAM.
* **MITRE ATT&CK Integration:** All alerts are tagged with standard T-Codes (e.g., `T1110` for Brute Force).
* **Logic-Based Detection:** Uses a dictionary-based "Scoreboard" to track failed attempts over time (Thresholding).
* **Structured Output:** Generates alerts in JSON format for easy integration with other tools.

## 🛠️ Technology Stack
* **Language:** Python 3.x
* **Libraries:** `re` (Regex), `json`, `time`
* **OS:** Linux Mint (Compatible with Ubuntu/Debian)

## 📸 Proof of Detection
*See `alerts.json` for full logs.*

```json
{
    "timestamp": "Sat Dec  6 10:37:07 2025",
    "rule_name": "SSH Brute Force Attack",
    "mitre_id": "T1110",
    "source_ip": "127.0.0.1",
    "severity": "High",
    "message": "Threshold reached: 5 attempts."
}
