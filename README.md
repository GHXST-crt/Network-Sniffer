# Enhanced Packet Sniffer

## Overview

The Enhanced Packet Sniffer is a powerful network analysis tool designed to capture and analyze network traffic in real-time. This tool provides advanced functionalities such as Deep Packet Inspection (DPI), packet reassembly, protocol decoding, traffic bottleneck tracking, and firewall testing. It features a user-friendly graphical interface similar to Wireshark, making it an essential tool for network administrators and security professionals.

## Features

- **Real-time Packet Capturing**: Capture network packets in real-time.
- **Deep Packet Inspection (DPI)**: Perform detailed analysis of different network protocols.
- **Packet Reassembly**: Handle and reassemble fragmented packets.
- **Advanced Filtering**: Robust filtering system to display only relevant packets.
- **Protocol Decoding**: Decode and display information for a wide range of network protocols.
- **Traffic Bottleneck Tracking**: Identify network traffic bottlenecks.
- **Firewall Testing**: Test the efficacy of firewalls and network security.
- **Save/Load Packets**: Save captured packets to a file and load them for later analysis.
- **User-friendly UI**: Intuitive and visually appealing interface similar to Wireshark.

## Requirements

- Python 3.7+
- Scapy
- Tkinter
- Matplotlib
- PyDivert (For Windows packet capturing)
- WinPcap or npcap (For Windows packet capturing)

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/yourusername/enhanced-packet-sniffer.git
    cd enhanced-packet-sniffer
    ```

2. **Install the required Python packages:**

    ```sh
    pip install -r requirements.txt
    ```

3. **Install WinPcap or npcap:**

    Download and install npcap from [Npcap](https://nmap.org/npcap/) if you don't have it installed already.

## Usage

1. **Run the application:**

    ```sh
    python enhanced_packet_sniffer.py
    ```

2. **Interface:**

    - **File**: Save, Load, and Export captured packets.
    - **Capture**: Start and stop packet capturing.
    - **Analyze**: Access advanced filtering, protocol decoding, and DPI functionalities.
    - **Tools**: Track network bottlenecks and test firewall efficacy.
    - **Settings**: Configure application settings (coming soon).

## Directory Structure

enhanced-packet-sniffer/
│
├── enhanced_packet_sniffer.py
├── advanced_filtering.py
├── dpi_module.py
├── packet_reassembly.py
├── protocol_decoding.py
├── bottleneck_tracking.py
├── firewall_testing.py
├── requirements.txt
└── README.md

## Modules

- **advanced_filtering.py**: Implements advanced filtering mechanisms.
- **dpi_module.py**: Contains functions for Deep Packet Inspection.
- **packet_reassembly.py**: Handles packet reassembly.
- **protocol_decoding.py**: Decodes various network protocols.
- **bottleneck_tracking.py**: Tracks network traffic bottlenecks.
- **firewall_testing.py**: Tests firewall efficacy.

## Contributing

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Commit your changes (`git commit -m 'Add some feature'`).
5. Push to the branch (`git push origin feature-branch`).
6. Open a pull request.

## License

This project is licensed under the Mozilla Public License 2.0 - see the LICENSE file for details

## Contact

For any inquiries or issues, please contact Zuveb Kamdoli at [zuvebkamdoli.lord@gmail.com].
