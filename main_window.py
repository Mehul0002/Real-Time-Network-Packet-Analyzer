#!/usr/bin/env python3
"""
Main Window for the Real-Time Network Packet Analyzer.
Handles the overall layout, filters, buttons, and status bar.
"""

import sys
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QSplitter,
    QTableWidget, QTextEdit, QLineEdit, QComboBox, QPushButton,
    QLabel, QStatusBar, QFrame, QGroupBox, QCheckBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont

from ui.packet_table import PacketTable
from core.sniffer import PacketSniffer
from core.analyzer import PacketAnalyzer

class MainWindow(QMainWindow):
    """Main application window."""

    def __init__(self):
        super().__init__()
        self.sniffer_thread = None
        self.analyzer = PacketAnalyzer()
        self.init_ui()
        self.setup_connections()

    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Real-Time Network Packet Analyzer")
        self.setGeometry(100, 100, 1200, 800)

        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main layout
        main_layout = QVBoxLayout(central_widget)

        # Filters bar
        filters_group = QGroupBox("Filters")
        filters_layout = QHBoxLayout(filters_group)

        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Filter by IP (src or dst)")
        filters_layout.addWidget(QLabel("IP:"))
        filters_layout.addWidget(self.ip_filter)

        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["All", "TCP", "UDP", "ICMP", "ARP", "HTTP", "HTTPS"])
        filters_layout.addWidget(QLabel("Protocol:"))
        filters_layout.addWidget(self.protocol_filter)

        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("Filter by Port")
        filters_layout.addWidget(QLabel("Port:"))
        filters_layout.addWidget(self.port_filter)

        self.anomaly_only = QCheckBox("Show Anomalies Only")
        filters_layout.addWidget(self.anomaly_only)

        filters_layout.addStretch()
        main_layout.addWidget(filters_group)

        # Splitter for table and details
        splitter = QSplitter(Qt.Horizontal)

        # Packet table
        self.packet_table = PacketTable()
        splitter.addWidget(self.packet_table)

        # Packet details panel
        details_group = QGroupBox("Packet Details")
        details_layout = QVBoxLayout(details_group)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFont(QFont("Courier New", 10))
        details_layout.addWidget(self.details_text)

        # AI Explain button
        self.explain_button = QPushButton("AI Explain Packet")
        self.explain_button.setEnabled(False)
        details_layout.addWidget(self.explain_button)

        splitter.addWidget(details_group)
        splitter.setSizes([700, 500])

        main_layout.addWidget(splitter)

        # Bottom controls
        controls_layout = QHBoxLayout()

        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)

        self.export_button = QPushButton("Export to CSV")
        self.export_button.setEnabled(False)

        controls_layout.addWidget(self.start_button)
        controls_layout.addWidget(self.stop_button)
        controls_layout.addStretch()
        controls_layout.addWidget(self.export_button)

        main_layout.addLayout(controls_layout)

        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label)

        # Connect table selection to details update
        self.packet_table.itemSelectionChanged.connect(self.update_packet_details)

    def setup_connections(self):
        """Setup signal-slot connections."""
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.export_button.clicked.connect(self.export_to_csv)
        self.explain_button.clicked.connect(self.explain_packet)
        self.ip_filter.textChanged.connect(self.apply_filters)
        self.protocol_filter.currentTextChanged.connect(self.apply_filters)
        self.port_filter.textChanged.connect(self.apply_filters)
        self.anomaly_only.stateChanged.connect(self.apply_filters)

    def start_capture(self):
        """Start packet capture in a separate thread."""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            return

        self.sniffer_thread = PacketSniffer()
        self.sniffer_thread.packet_captured.connect(self.on_packet_captured)
        self.sniffer_thread.status_updated.connect(self.update_status)
        self.sniffer_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.export_button.setEnabled(True)
        self.status_label.setText("Capturing packets...")

    def stop_capture(self):
        """Stop packet capture."""
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText("Capture stopped")

    def on_packet_captured(self, packet_data):
        """Handle captured packet data."""
        # Analyze for anomalies
        anomaly = self.analyzer.analyze_packet(packet_data)

        # Add to table
        self.packet_table.add_packet(packet_data, anomaly)

        # Apply filters
        self.apply_filters()

    def update_packet_details(self):
        """Update the packet details panel when a packet is selected."""
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            self.details_text.clear()
            self.explain_button.setEnabled(False)
            return

        row = selected_items[0].row()
        packet_data = self.packet_table.get_packet_data(row)

        # Format packet details
        details = f"Timestamp: {packet_data['timestamp']}\n"
        details += f"Protocol: {packet_data['protocol']}\n"
        details += f"Source IP: {packet_data['src_ip']}\n"
        details += f"Destination IP: {packet_data['dst_ip']}\n"
        details += f"Source Port: {packet_data.get('src_port', 'N/A')}\n"
        details += f"Destination Port: {packet_data.get('dst_port', 'N/A')}\n"
        details += f"Length: {packet_data['length']} bytes\n"
        details += f"Flags: {packet_data.get('flags', 'N/A')}\n"
        details += f"Anomaly: {'Yes' if packet_data.get('anomaly') else 'No'}\n\n"
        details += f"Raw Data:\n{packet_data.get('raw', 'N/A')}"

        self.details_text.setPlainText(details)
        self.explain_button.setEnabled(True)

    def explain_packet(self):
        """Provide AI-like explanation of the selected packet."""
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        packet_data = self.packet_table.get_packet_data(row)

        # Simple heuristic-based explanation
        explanation = self.analyzer.explain_packet(packet_data)
        self.details_text.append(f"\n\n--- AI Explanation ---\n{explanation}")

    def apply_filters(self):
        """Apply current filters to the packet table."""
        ip_filter = self.ip_filter.text().strip()
        protocol_filter = self.protocol_filter.currentText()
        port_filter = self.port_filter.text().strip()
        anomaly_only = self.anomaly_only.isChecked()

        self.packet_table.apply_filters(ip_filter, protocol_filter, port_filter, anomaly_only)

    def export_to_csv(self):
        """Export captured packets to CSV file."""
        from core.utils import export_to_csv
        packets = self.packet_table.get_all_packets()
        if packets:
            export_to_csv(packets)
            self.status_label.setText("Packets exported to packets.csv")
        else:
            self.status_label.setText("No packets to export")

    def update_status(self, message):
        """Update status bar message."""
        self.status_label.setText(message)

    def closeEvent(self, event):
        """Handle application close event."""
        self.stop_capture()
        event.accept()
