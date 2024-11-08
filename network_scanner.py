
# network_scanner.py - Core Scanning Script for Network Infrastructure Security Tool

import json
import socket
from scapy.all import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from configparser import ConfigParser

# Load configuration from config.json
with open("config.json", "r") as config_file:
    config = json.load(config_file)

# Example function to scan for open ports within configured network ranges
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

# Check if the TLS/SSL configuration meets minimum standards
def check_tls_encryption(ip, port):
    try:
        # Establish SSL/TLS connection and retrieve protocol information
        conn = socket.create_connection((ip, port))
        context = ssl.create_default_context()
        with context.wrap_socket(conn, server_hostname=ip) as secure_sock:
            tls_version = secure_sock.version()
            cipher = secure_sock.cipher()
            print(f"[INFO] {ip}:{port} uses {tls_version} with cipher {cipher}")
            
            # Check minimum TLS version and accepted ciphers from config
            if tls_version < config["encryption_standards"]["minimum_tls_version"]:
                print(f"[WARNING] {ip}:{port} uses a deprecated TLS version ({tls_version}).")
            if cipher[0] not in config["encryption_standards"]["accepted_ciphers"]:
                print(f"[WARNING] {ip}:{port} uses a weak cipher: {cipher[0]}.")
    except Exception as e:
        print(f"[ERROR] Failed to check TLS/SSL on {ip}:{port} - {e}")

# Scan specified network ranges and protocols
def run_network_scan():
    for network in config["network_ranges"]:
        ip_list = list(IPNetwork(network))
        for ip in ip_list:
            open_ports = scan_open_ports(str(ip), config["alert_thresholds"]["open_ports"])
            if open_ports:
                print(f"[INFO] Open ports on {ip}: {open_ports}")
                for port in open_ports:
                    if port == 443:  # HTTPS
                        check_tls_encryption(str(ip), port)

if __name__ == "__main__":
    print("[INFO] Starting network scan...")
    run_network_scan()
