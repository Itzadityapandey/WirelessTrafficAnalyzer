# Wireless Traffic Analyzer

## Overview
Wireless Traffic Analyzer is a simple network packet sniffer built using Python, PyQt6, and Scapy. This tool allows users to monitor network traffic, capture TCP packets, and display packet details in a GUI.

## Features
- Select network interface for monitoring
- Start and stop packet sniffing
- Capture and display TCP packet details (source/destination IP and port)
- Verbose mode for additional packet information
- User-friendly PyQt6-based GUI

## Installation
### Prerequisites
Ensure you have Python 3 installed on your system. You also need administrator/root privileges to run the sniffer.

### Install Dependencies
Run the following command to install the required Python packages:
```bash
pip install scapy PyQt6
```

## Usage
### Running the Application
Run the following command to start the Wireless Traffic Analyzer:
```bash
python main.py
```

### Steps to Use
1. Select a network interface from the dropdown list.
2. (Optional) Enable "Verbose Mode" for additional packet details.
3. Click "Start Sniffing" to begin capturing network packets.
4. Click "Stop Sniffing" to halt packet capture.
5. View captured packet details in the log area.



## Permissions
This application requires administrator/root privileges to capture packets. Run it with elevated privileges:
```bash
sudo python main.py   # On Linux/macOS
```
For Windows, run the script in an administrator command prompt.

## Known Issues
- The application may not detect all interfaces on Windows due to permission restrictions.
- Running without administrator/root privileges may result in permission errors.

## Contributing
Contributions are welcome! Feel free to fork this repository, make improvements, and submit a pull request.

## License
This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.



