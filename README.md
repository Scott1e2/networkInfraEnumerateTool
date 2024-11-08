# networkInfraEnumerateTool
creating a tool to find security gaps in the network internal testing 



# DETIALS of the Network Infrastructure Security Tool

## Overview
This tool is designed to identify security gaps and vulnerabilities in network infrastructure, with a focus on securing data in transit. It scans network ranges, inspects protocol configurations, performs firewall audits, and ensures encryption standards, helping proactively reduce attack surfaces.

## Features
- **Advanced Protocol and Service Analysis**: Scans a wide range of protocols (e.g., HTTP, HTTPS, FTP, SSH, RDP) and checks for weak configurations.
- **TLS/SSL Encryption Audits**: Verifies TLS versions, certificate validity, and encryption strength, and alerts on weak ciphers.
- **Firewall and Access Control Reviews**: Detects high-risk open ports and analyzes firewall rules to prevent unauthorized access.
- **Threat Modeling and Attack Mapping**: Maps vulnerabilities to MITRE ATT&CK tactics, generating threat scenarios and recommendations.
- **Risk Scoring and Reporting**: Assesses and scores vulnerabilities, providing prioritized, actionable reports.

## Requirements
- **Python 3.8+**
- Install dependencies using `requirements.txt`:
    ```bash
    pip install -r requirements.txt
    ```

## Installation
1. **Clone the Repository**:
    ```bash
    git clone https://github.com/your-repository/network-infrastructure-security-tool.git
    cd network-infrastructure-security-tool
    ```

2. **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure Settings**:
    - Open `config.json` to define network ranges, protocols, encryption standards, and alert thresholds.

## Usage
1. **Run Network Scanner**:
    ```bash
    python network_scanner.py
    ```
   - This script scans IP ranges for open ports, checks TLS configurations, and reviews firewall rules.

2. **Generate Vulnerability Report**:
    ```bash
    python network_report.py
    ```
   - Generates detailed risk scores and remediation guidance in `network_report.txt` (plaintext) and `network_report.json` (JSON).

## Configuration
- **config.json**: Stores network configuration settings, thresholds, and protocol preferences.
    - **network_ranges**: Defines IP ranges to scan (e.g., "192.168.1.0/24").
    - **protocols_to_scan**: Lists protocols to analyze (e.g., HTTP, HTTPS, SSH).
    - **encryption_standards**: Sets minimum TLS version, accepted ciphers, and certificate expiry alert threshold.
    - **alert_thresholds**: Configures alerts for public exposure, weak encryption, open ports, anomaly detection, and firewall audits.

## Advanced Features
1. **Threat Modeling with MITRE Mapping**:
   - Each detected vulnerability is mapped to MITRE ATT&CK tactics to help understand potential attacker actions.

2. **Enhanced Risk Scoring**:
   - Vulnerabilities are scored based on severity and exploitability, enabling prioritization of high-risk issues.

3. **Real-Time Alerting and Anomaly Detection**:
   - Alerts for unexpected open ports and changes in critical firewall configurations.

## Example Configuration and Sample Output
- **config.json** (Example):
    ```json
    {
        "network_ranges": ["192.168.1.0/24", "10.0.0.0/24"],
        "protocols_to_scan": ["HTTP", "HTTPS", "FTP", "SSH", "RDP"],
        "encryption_standards": {
            "minimum_tls_version": "TLS 1.2",
            "accepted_ciphers": ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "TLS_RSA_WITH_AES_256_GCM_SHA384"],
            "certificate_expiry_days": 30
        },
        "alert_thresholds": {
            "public_exposure": true,
            "weak_encryption": true,
            "open_ports": [21, 22, 80, 443, 3389],
            "anomaly_detection": true,
            "firewall_audit": true
        }
    }
    ```

- **Sample Output (network_report.txt)**:
    ```
    Network Security Report
    ===========================
    Total Vulnerabilities: 3
    Total Risk Score: 22

    Description: Open port 80 detected on critical server.
    Severity: High
    Risk Score: 21
    MITRE ATT&CK Tactic: TA0001 - Initial Access
    Recommendation: Close or secure port 80 on critical infrastructure.
    ```
