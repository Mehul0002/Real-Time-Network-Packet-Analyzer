#!/usr/bin/env python3
"""
Utilities module for the Packet Analyzer.
Includes CSV export functionality and other helper functions.
"""

import csv
import os
from datetime import datetime

def export_to_csv(packets, filename="packets.csv"):
    """Export captured packets to a CSV file."""
    if not packets:
        return

    # Define CSV headers
    headers = [
        "Timestamp", "Protocol", "Source IP", "Destination IP",
        "Source Port", "Destination Port", "Length", "Flags",
        "Anomaly", "Anomaly Reasons"
    ]

    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=headers)
            writer.writeheader()

            for packet in packets:
                row = {
                    "Timestamp": packet.get("timestamp", ""),
                    "Protocol": packet.get("protocol", ""),
                    "Source IP": packet.get("src_ip", ""),
                    "Destination IP": packet.get("dst_ip", ""),
                    "Source Port": packet.get("src_port", ""),
                    "Destination Port": packet.get("dst_port", ""),
                    "Length": packet.get("length", ""),
                    "Flags": packet.get("flags", ""),
                    "Anomaly": "Yes" if packet.get("anomaly") else "No",
                    "Anomaly Reasons": "; ".join(packet.get("anomaly_reasons", []))
                }
                writer.writerow(row)

        print(f"Packets exported to {filename}")

    except Exception as e:
        print(f"Error exporting to CSV: {e}")

def format_packet_summary(packets):
    """Generate a summary of captured packets."""
    if not packets:
        return "No packets captured."

    total_packets = len(packets)
    protocols = {}
    anomalies = 0
    total_bytes = 0

    for packet in packets:
        proto = packet.get("protocol", "Unknown")
        protocols[proto] = protocols.get(proto, 0) + 1

        if packet.get("anomaly"):
            anomalies += 1

        total_bytes += packet.get("length", 0)

    summary = f"""
Packet Capture Summary:
Total Packets: {total_packets}
Total Bytes: {total_bytes}
Anomalies Detected: {anomalies}

Protocol Distribution:
"""

    for proto, count in sorted(protocols.items()):
        summary += f"{proto}: {count} packets\n"

    return summary.strip()

def validate_ip_address(ip):
    """Validate if a string is a valid IP address."""
    import re
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(pattern, ip):
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def get_network_interfaces():
    """Get list of available network interfaces."""
    try:
        import psutil
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family.name == 'AF_INET':
                    interfaces.append({
                        'name': name,
                        'ip': addr.address,
                        'netmask': addr.netmask
                    })
        return interfaces
    except ImportError:
        return []

def calculate_packet_rate(packets, time_window=60):
    """Calculate packets per second over a time window."""
    if not packets:
        return 0

    # Sort packets by timestamp
    sorted_packets = sorted(packets, key=lambda x: x.get('timestamp', ''))

    # Get timestamps (assuming format "YYYY-MM-DD HH:MM:SS")
    timestamps = []
    for packet in sorted_packets:
        try:
            ts_str = packet.get('timestamp', '')
            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
            timestamps.append(ts.timestamp())
        except:
            continue

    if len(timestamps) < 2:
        return 0

    # Calculate rate
    time_span = timestamps[-1] - timestamps[0]
    if time_span == 0:
        return 0

    return len(timestamps) / time_span
