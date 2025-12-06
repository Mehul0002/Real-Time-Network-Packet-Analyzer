#!/usr/bin/env python3
"""
Packet Table Widget for displaying captured packets.
"""

from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem, QHeaderView
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor

class PacketTable(QTableWidget):
    """Table widget for displaying network packets."""

    def __init__(self):
        super().__init__()
        self.packets = []
        self.filtered_packets = []
        self.init_table()

    def init_table(self):
        """Initialize the table structure."""
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels([
            "Timestamp", "Protocol", "Source IP", "Dest IP",
            "Source Port", "Dest Port", "Length"
        ])

        # Set column widths
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)  # Timestamp
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Protocol
        header.setSectionResizeMode(2, QHeaderView.Stretch)  # Source IP
        header.setSectionResizeMode(3, QHeaderView.Stretch)  # Dest IP
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Source Port
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)  # Dest Port
        header.setSectionResizeMode(6, QHeaderView.ResizeToContents)  # Length

        # Enable sorting
        self.setSortingEnabled(True)

        # Set row selection
        self.setSelectionBehavior(QTableWidget.SelectRows)

    def add_packet(self, packet_data, is_anomaly=False):
        """Add a packet to the table."""
        self.packets.append(packet_data)

        row_position = self.rowCount()
        self.insertRow(row_position)

        # Set data
        self.setItem(row_position, 0, QTableWidgetItem(packet_data['timestamp']))
        self.setItem(row_position, 1, QTableWidgetItem(packet_data['protocol']))
        self.setItem(row_position, 2, QTableWidgetItem(packet_data['src_ip']))
        self.setItem(row_position, 3, QTableWidgetItem(packet_data['dst_ip']))
        self.setItem(row_position, 4, QTableWidgetItem(str(packet_data.get('src_port', ''))))
        self.setItem(row_position, 5, QTableWidgetItem(str(packet_data.get('dst_port', ''))))
        self.setItem(row_position, 6, QTableWidgetItem(str(packet_data['length'])))

        # Highlight anomalies
        if is_anomaly:
            for col in range(self.columnCount()):
                item = self.item(row_position, col)
                if item:
                    item.setBackground(QColor(255, 100, 100))  # Light red

        # Store packet data for details view
        self.item(row_position, 0).setData(Qt.UserRole, packet_data)

    def get_packet_data(self, row):
        """Get packet data for a given row."""
        if 0 <= row < self.rowCount():
            item = self.item(row, 0)
            if item:
                return item.data(Qt.UserRole)
        return None

    def get_all_packets(self):
        """Get all captured packets."""
        return self.packets

    def apply_filters(self, ip_filter="", protocol_filter="All", port_filter="", anomaly_only=False):
        """Apply filters to the table display."""
        self.setRowCount(0)  # Clear current display

        for packet in self.packets:
            # IP filter
            if ip_filter and ip_filter not in packet['src_ip'] and ip_filter not in packet['dst_ip']:
                continue

            # Protocol filter
            if protocol_filter != "All" and packet['protocol'] != protocol_filter:
                continue

            # Port filter
            if port_filter:
                src_port = str(packet.get('src_port', ''))
                dst_port = str(packet.get('dst_port', ''))
                if port_filter not in src_port and port_filter not in dst_port:
                    continue

            # Anomaly filter
            if anomaly_only and not packet.get('anomaly', False):
                continue

            # Add to filtered display
            is_anomaly = packet.get('anomaly', False)
            self.add_packet(packet, is_anomaly)
