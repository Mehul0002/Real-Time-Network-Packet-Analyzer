# Real-Time Network Packet Analyzer

A comprehensive GUI desktop application for real-time network packet analysis, built with Python, Scapy, and PyQt5. Features packet capture, filtering, anomaly detection, and export capabilities.

## Features

- **Real-time Packet Capture**: Capture network packets in real time using Scapy
- **Interactive GUI**: Modern dark-themed interface with PyQt5
- **Packet Filtering**: Filter by IP address, protocol, and port
- **Anomaly Detection**: Rule-based and heuristic-based anomaly detection
- **Packet Details**: Detailed view of captured packets
- **AI Packet Explanation**: Simple AI-like explanation of packet contents and potential security risks
- **CSV Export**: Export captured packets to CSV for further analysis
- **Multi-threading**: Non-blocking UI with background packet capture
- **Cross-platform**: Works on Windows, Linux, and macOS

## Project Structure

```
packet-analyzer/
├── main.py                 # Application entry point
├── ui/
│   ├── main_window.py      # Main GUI window
│   ├── packet_table.py     # Packet display table
│   └── styles.qss          # Dark theme stylesheet
├── core/
│   ├── sniffer.py          # Packet capture logic
│   ├── analyzer.py         # Anomaly detection
│   └── utils.py            # Utilities (CSV export, etc.)
├── assets/
│   └── icon.png            # Application icon
├── requirements.txt        # Python dependencies
└── README.md              # This file
```

## Installation

### Prerequisites

- Python 3.7+
- Administrative privileges (for packet capture)

### Setup Instructions

1. **Clone or download the project**:
   ```bash
   cd your-projects-directory
   # Copy the packet-analyzer folder here
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv packet_analyzer_env
   # On Windows:
   packet_analyzer_env\Scripts\activate
   # On Linux/macOS:
   source packet_analyzer_env/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Npcap (Windows)**:
   - Download and install Npcap from https://npcap.com/
   - Ensure "WinPcap API-compatible mode" is enabled during installation

5. **Linux Dependencies**:
   ```bash
   # Ubuntu/Debian:
   sudo apt-get install python3-dev libpcap-dev

   # CentOS/RHEL:
   sudo yum install python3-devel libpcap-devel
   ```

## Usage

### Running the Application

1. **With admin privileges** (required for packet capture):
   ```bash
   # Windows (run as Administrator):
   python main.py

   # Linux/macOS:
   sudo python main.py
   ```

2. **GUI Overview**:
   - **Filters Bar**: Filter packets by IP, protocol, port, or show anomalies only
   - **Packet Table**: Displays captured packets with timestamp, protocol, IPs, ports, length
   - **Packet Details**: Shows detailed information about selected packet
   - **Controls**: Start/Stop capture, Export to CSV, AI Explain button

### Interface Layout

```
┌─────────────────────────────────────────────────────────────┐
│ Filters: [IP] [Protocol ▼] [Port] [☐ Show Anomalies Only]   │
├─────────────────────┬───────────────────────────────────────┤
│ Packet Table        │ Packet Details                       │
│ ┌─────────────────┐ │ ┌───────────────────────────────────┐ │
│ │ Timestamp       │ │ │ Timestamp: 2023-...              │ │
│ │ Protocol        │ │ │ Protocol: TCP                     │ │
│ │ Source IP       │ │ │ Source IP: 192.168.1.100         │ │
│ │ Dest IP         │ │ │ Dest IP: 10.0.0.1                 │ │
│ │ Source Port     │ │ │ Source Port: 443                  │ │
│ │ Dest Port       │ │ │ Dest Port: 80                     │ │
│ │ Length          │ │ │ Length: 1500 bytes                │ │
│ └─────────────────┘ │ │ Flags: SA                         │ │
│                     │ │ Anomaly: No                       │ │
│ [Start Capture]     │ │                                   │ │
│ [Stop Capture]      │ │ Raw Data: ...                     │ │
│ [Export to CSV]     │ │                                   │ │
│                     │ │ [AI Explain Packet]               │ │
└─────────────────────┴───────────────────────────────────────┘
│ Status: Capturing packets...                              │
└─────────────────────────────────────────────────────────────┘
```

## Anomaly Detection

### Rule-Based Detection

The analyzer uses several rules to detect anomalous packets:

1. **Large Packet Size**: Packets larger than 1500 bytes (potential fragmentation or oversized payloads)
2. **Suspicious Ports**: Traffic to/from known vulnerable ports (22/SSH, 3389/RDP, 445/SMB, etc.)
3. **High Packet Rate**: More than 100 packets per minute from a single IP
4. **Protocol Anomalies**: Unusual protocol combinations or malformed packets

### Simple ML Component

The analyzer includes basic heuristic-based detection:

- **Traffic Pattern Analysis**: Monitors packet frequency and size distributions
- **IP Reputation**: Flags traffic from known suspicious IP ranges
- **Port Scanning Detection**: Identifies sequential port access patterns

### Anomaly Highlighting

- Anomalous packets are highlighted in red in the packet table
- Anomaly reasons are logged and can be exported to CSV

## AI Packet Explanation

The "AI Explain Packet" feature provides simple heuristic-based analysis:

- **Protocol Analysis**: Explains the purpose of TCP/UDP/ICMP traffic
- **Port Analysis**: Identifies common services (HTTP=80, HTTPS=443, SSH=22, etc.)
- **Security Assessment**: Flags potentially suspicious activity
- **Traffic Context**: Provides context about the packet's role in network communication

Example explanation:
```
This is a TCP SYN packet from 192.168.1.100:54321 to 10.0.0.1:80.
This appears to be an HTTP request initiation. The packet size is normal.
Potential security risk: None detected. This looks like standard web browsing traffic.
```

## Technical Implementation

### How Packet Sniffing Works

1. **Scapy Integration**: Uses Scapy's `sniff()` function with a custom callback
2. **Threading**: Capture runs in a separate QThread to prevent UI freezing
3. **Signal-Slot Mechanism**: Thread-safe communication using PyQt5 signals
4. **Packet Parsing**: Extracts relevant fields (IP, ports, protocol, flags, payload)

### Multi-threading Architecture

```
Main Thread (UI)
    ↓
PacketSniffer Thread
    ↓ (signals)
UI Updates
```

- **PacketSniffer**: Inherits from QThread, emits `packet_captured` signal
- **MainWindow**: Receives signals and updates UI safely
- **Analyzer**: Processes packets in main thread for anomaly detection

### GUI Thread Safety

- All UI updates occur in the main thread
- Background thread only emits signals with packet data
- No direct UI manipulation from worker threads

## Security Concepts Demonstrated

1. **Network Monitoring**: Real-time traffic analysis
2. **Intrusion Detection**: Anomaly-based threat identification
3. **Packet Analysis**: Deep packet inspection techniques
4. **Traffic Pattern Recognition**: Statistical analysis of network behavior
5. **Protocol Analysis**: Understanding network protocol structures

## Troubleshooting

### Permission Issues

**Windows**:
- Run as Administrator
- Ensure Npcap is installed correctly

**Linux**:
- Use `sudo` to run the application
- Check if libpcap is installed: `sudo apt-get install libpcap-dev`

### No Packets Captured

- Check network interface permissions
- Try running on different network interfaces
- Ensure firewall/antivirus isn't blocking the application

### Performance Issues

- Limit capture duration for large networks
- Use filters to reduce packet processing load
- Close other network-intensive applications

## Development

### Adding New Features

1. **New Filters**: Extend `apply_filters()` in `main_window.py`
2. **Additional Protocols**: Update `extract_packet_info()` in `sniffer.py`
3. **Enhanced Analysis**: Modify `analyze_packet()` in `analyzer.py`

### Code Style

- Follow PEP 8 conventions
- Use type hints where possible
- Document functions with docstrings
- Handle exceptions gracefully

## License

This project is open-source. Feel free to modify and distribute.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## Screenshots

*(Add screenshots of the application in action)*

## Future Enhancements

- Advanced ML models for anomaly detection
- Packet replay functionality
- Network interface selection
- Real-time graphs and statistics
- Plugin system for custom analyzers
- Encrypted traffic analysis (TLS inspection)
