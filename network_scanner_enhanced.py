
# network_scanner.py - Enhanced Scanning Script for Network Infrastructure Security Tool

import json
import socket
import ssl
from scapy.all import *
from datetime import datetime, timedelta

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Scan for open ports within configured network ranges
def scan_open_ports(ip, ports):
    open_ports = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    return open_ports

# Perform TLS/SSL security checks
def check_tls_encryption(ip, port):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((ip, port)) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as secure_sock:
                tls_version = secure_sock.version()
                cipher = secure_sock.cipher()
                cert = secure_sock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                days_to_expiry = (expiry_date - datetime.now()).days

                # Output protocol and cipher information
                print(f"[INFO] {ip}:{port} uses {tls_version} with cipher {cipher}")

                # Check for weak TLS versions and ciphers
                if tls_version < config["encryption_standards"]["minimum_tls_version"]:
                    print(f"[WARNING] {ip}:{port} uses a deprecated TLS version ({tls_version}).")
                if cipher[0] not in config["encryption_standards"]["accepted_ciphers"]:
                    print(f"[WARNING] {ip}:{port} uses a weak cipher: {cipher[0]}.")

                # Check for upcoming certificate expiration
                if days_to_expiry < config["encryption_standards"]["certificate_expiry_days"]:
                    print(f"[WARNING] TLS certificate for {ip}:{port} expires in {days_to_expiry} days.")

    except Exception as e:
        print(f"[ERROR] Failed to check TLS/SSL on {ip}:{port} - {e}")

# Verify firewall rules and public access exposure
def check_firewall_rules(ip, open_ports):
    try:
        # Placeholder firewall rule check
        for port in open_ports:
            if port in config["alert_thresholds"]["open_ports"]:
                print(f"[ALERT] Open port {port} on {ip} requires review (high-risk port).")
        # Additional logic could include reviewing iptables, firewalld, etc.
    except Exception as e:
        print(f"[ERROR] Firewall audit failed on {ip} - {e}")

# Run network scan across specified IP ranges and protocols
def run_advanced_network_scan():
    for network in config["network_ranges"]:
        ip_list = list(IPNetwork(network))
        for ip in ip_list:
            open_ports = scan_open_ports(str(ip), config["alert_thresholds"]["open_ports"])
            if open_ports:
                print(f"[INFO] Open ports on {ip}: {open_ports}")
                check_firewall_rules(str(ip), open_ports)
                for port in open_ports:
                    if port in [443, 8443]:  # Common HTTPS/TLS ports
                        check_tls_encryption(str(ip), port)

if __name__ == "__main__":
    print("[INFO] Starting enhanced network scan...")
    run_advanced_network_scan()
