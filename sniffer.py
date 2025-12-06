#!/usr/bin/env python3
"""
Packet Sniffer module using Scapy.
Runs in a separate thread to capture network packets in real time.
"""

import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
from PyQt5.QtCore import QThread, pyqtSignal

class PacketSniffer(QThread):
    """Thread for capturing network packets using Scapy."""

    packet_captured = pyqtSignal(dict)  # Signal emitted when a packet is captured
    status_updated = pyqtSignal(str)    # Signal for status updates

    def __init__(self):
        super().__init__()
        self.running = False

    def run(self):
        """Main thread execution for packet sniffing."""
        self.running = True
        self.status_updated.emit("Starting packet capture...")

        try:
            # Start sniffing with a callback
            sniff(prn=self.process_packet, store=0, stop_filter=self.should_stop)
        except Exception as e:
            self.status_updated.emit(f"Error during capture: {str(e)}")
        finally:
            self.status_updated.emit("Capture stopped")

    def process_packet(self, packet):
        """Process a captured packet and emit signal with packet data."""
        if not self.running:
            return

        packet_data = self.extract_packet_info(packet)
        if packet_data:
            self.packet_captured.emit(packet_data)

    def extract_packet_info(self, packet):
        """Extract relevant information from a Scapy packet."""
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))

            # Basic packet info
            length = len(packet)
            protocol = "Unknown"
            src_ip = dst_ip = ""
            src_port = dst_port = None
            flags = ""

            # Extract IP layer
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto

                # Determine protocol name
                if protocol == 6:
                    protocol = "TCP"
                elif protocol == 17:
                    protocol = "UDP"
                elif protocol == 1:
                    protocol = "ICMP"
                else:
                    protocol = f"IP({protocol})"

                # Extract port information
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    flags = str(packet[TCP].flags)
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

            elif ARP in packet:
                protocol = "ARP"
                src_ip = packet[ARP].psrc
                dst_ip = packet[ARP].pdst

            # Raw packet data (first 200 bytes for display)
            raw_data = str(packet)[:200] + "..." if len(str(packet)) > 200 else str(packet)

            return {
                'timestamp': timestamp,
                'protocol': protocol,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'length': length,
                'flags': flags,
                'raw': raw_data
            }

        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None

    def should_stop(self, packet):
        """Stop filter for sniff function."""
        return not self.running

    def stop(self):
        """Stop the sniffing thread."""
        self.running = False
