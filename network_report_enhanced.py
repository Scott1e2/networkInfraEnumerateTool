
# network_report.py - Enhanced Vulnerability Scoring and Threat Modeling for Network Security Tool

import json

# Define enhanced scoring criteria and threat mapping
SEVERITY_SCORES = {
    "critical": 10,
    "high": 7,
    "medium": 5,
    "low": 2,
}
MITRE_MAPPING = {
    "open_ports": "TA0001 - Initial Access",
    "weak_encryption": "TA0005 - Defense Evasion",
    "public_exposure": "TA0002 - Execution",
    "expired_cert": "TA0008 - Credential Access",
    "firewall_misconfig": "TA0004 - Privilege Escalation"
}

# Calculate risk score based on severity and exploitability
def calculate_risk_score(vulnerabilities):
    total_score = 0
    for vuln in vulnerabilities:
        severity = vuln.get("severity", "low")
        exploitability = vuln.get("exploitability", 1)
        score = SEVERITY_SCORES.get(severity, 2) * exploitability
        vuln["risk_score"] = score
        vuln["mitre_tactic"] = MITRE_MAPPING.get(vuln.get("type"), "Unknown")
        total_score += score
    return total_score

# Generate report with risk scores, threat scenarios, and remediation guidance
def generate_report(vulnerabilities, output_format="text"):
    report_data = {
        "total_vulnerabilities": len(vulnerabilities),
        "total_risk_score": calculate_risk_score(vulnerabilities),
        "vulnerabilities": vulnerabilities
    }
    
    if output_format == "text":
        with open("network_report.txt", "w") as report_file:
            report_file.write("Network Security Report\n")
            report_file.write("===========================\n")
            report_file.write(f"Total Vulnerabilities: {report_data['total_vulnerabilities']}\n")
            report_file.write(f"Total Risk Score: {report_data['total_risk_score']}\n\n")
            
            for vuln in vulnerabilities:
                report_file.write(f"Description: {vuln['description']}\n")
                report_file.write(f"Severity: {vuln['severity']}\n")
                report_file.write(f"Risk Score: {vuln['risk_score']}\n")
                report_file.write(f"MITRE ATT&CK Tactic: {vn['mitre_tactic']}\n")
                report_file.write(f"Recommendation: {vuln['remediation']}\n\n")
    
    elif output_format == "json":
        with open("network_report.json", "w") as report_file:
            json.dump(report_data, report_file, indent=4)

# Example vulnerability data for testing
vulnerabilities = [
    {
        "description": "Open port 80 detected on critical server.",
        "severity": "high",
        "exploitability": 3,
        "type": "open_ports",
        "remediation": "Close or secure port 80 on critical infrastructure."
    },
    {
        "description": "Weak cipher detected on TLS connection.",
        "severity": "medium",
        "exploitability": 2,
        "type": "weak_encryption",
        "remediation": "Upgrade to a stronger TLS cipher suite."
    },
    {
        "description": "TLS certificate for critical server is expired.",
        "severity": "critical",
        "exploitability": 3,
        "type": "expired_cert",
        "remediation": "Update TLS certificate to maintain secure encryption."
    },
    {
        "description": "Firewall rule allows public access to sensitive ports.",
        "severity": "high",
        "exploitability": 3,
        "type": "firewall_misconfig",
        "remediation": "Restrict public access and review firewall rules."
    }
]

# Generate example report
if __name__ == "__main__":
    generate_report(vulnerabilities, output_format="text")
    generate_report(vulnerabilities, output_format="json")
