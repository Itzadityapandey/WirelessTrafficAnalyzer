# Wireless Traffic Analyzer

Wireless Traffic Analyzer is a Python-based GUI application for analyzing and capturing network traffic. The project leverages `Scapy` for packet sniffing and `PyQt6` for an interactive user interface. It provides detailed insights into TCP packets traveling through a selected network interface.

---

## 📂 Project Structure

The project consists of the following files:

1. **`main.py`**  
   - This is the primary entry point for the application.  
   - It provides the graphical user interface (GUI) using `PyQt6`, allowing users to select a network interface, start/stop packet sniffing, and view live packet logs.

2. **`sniffer.py`**  
   - Contains the core logic for packet capturing using `Scapy`.  
   - Handles TCP/IP packet parsing and formats the output for the GUI.

3. **`requirements.txt`**  
   - Lists all the Python dependencies required for the project to run.  
   - Includes libraries like `PyQt6` and `Scapy`.

---

## ✨ Features

- **GUI-Based Interface**: Easy-to-use interface for selecting network interfaces and starting/stopping sniffing.  
- **Live Packet Capture**: Captures and logs live TCP/IP packets in real-time.  
- **Verbose Mode**: Optional verbose mode for capturing non-TCP/IPv4 packets with additional details.  
- **Error Handling**: Provides clear error messages for invalid configurations or permission issues.

---

## 🔧 Installation and Setup

Follow these steps to set up and run the project:

1. **Clone the Repository**  
   ```bash
   git clone https://github.com/your-username/wireless-traffic-analyzer.git
   cd wireless-traffic-analyzer
Install Dependencies
Ensure Python 3.7+ is installed. Then, install the required libraries using pip:

bash
Copy code
pip install -r requirements.txt
Run the Application
Execute the main.py file to launch the application:

bash
Copy code
python main.py
Permissions

Linux/macOS: Run with root/admin privileges:
bash
Copy code
sudo python main.py
Windows: Open the terminal as an administrator and then run the script.
📖 Usage
Launch the application using python main.py.
Select a network interface from the dropdown menu.
(Optional) Enable Verbose Mode to capture additional packet details.
Click Start Sniffing to begin capturing packets.
View live logs of captured packets in the text area.
Click Stop Sniffing to end the session.
🧾 Requirements
Python 3.7+
PyQt6
Scapy
datetime
Install all dependencies with:

bash
Copy code
pip install -r requirements.txt
🚨 Troubleshooting
Permission Denied:
Run the application as administrator (Windows) or with sudo (Linux/macOS).

No Interfaces Found:
Ensure your network interfaces are properly configured and accessible. Use the get_if_list() function from Scapy to debug interface availability.

Invalid Interface Selected:
Verify that the selected interface is valid and actively connected to a network.

🖼️ Screenshots
GUI - Interface Selection
(Include a screenshot of the dropdown interface selection here)

GUI - Live Packet Logs
(Include a screenshot of captured packet logs here)

🤝 Contributing
We welcome contributions!

To contribute:

Fork the repository.
Create a feature branch.
Submit a pull request with detailed explanations.
Feel free to open issues for bug reports or feature requests.

📜 License
This project is licensed under the MIT License. See the LICENSE file for details.

🙋‍♂️ Acknowledgements
Scapy Documentation
PyQt6 Documentation
Inspired by tools like Wireshark.
Happy coding! 🚀
