import sys
from scapy.all import get_if_list
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit,
    QCheckBox, QLabel, QComboBox, QWidget
)
from PyQt6.QtCore import QThread, pyqtSignal
from datetime import datetime
# Add matplotlib imports for graphing
from matplotlib.backends.backend_qt6agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure


class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(str)

    def __init__(self, interface, verbose=False):
        super().__init__()
        self.interface = interface
        self.verbose = verbose
        self.running = False

    def handle_packet(self, packet):
        """Handles incoming packets and emits log messages with suspicious traffic highlighting."""
        from scapy.layers.inet import TCP, IP
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_entry = f"[{timestamp}] TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
            # Highlight suspicious traffic (unusual ports) including non active ports
            common_ports = [80, 443, 22, 53, 21]  # HTTP, HTTPS, SSH, DNS, FTP
            if dst_port not in common_ports and src_port not in common_ports:
                log_entry += " [Unusual Port]"
            self.packet_captured.emit(log_entry + "\n")
        elif self.verbose:
            # Log non-TCP/IP packets in verbose mode
            summary = packet.summary()
            self.packet_captured.emit(f"[{timestamp}] Non-TCP Packet: {summary}\n")

    def run(self):
        """Starts the packet sniffing thread."""
        from scapy.all import sniff
        self.running = True
        try:
            sniff(
                iface=self.interface,
                prn=self.handle_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except PermissionError:
            self.packet_captured.emit(
                "Error: Permission denied. Run as administrator/root."
            )
        except Exception as e:
            self.packet_captured.emit(f"Error: {str(e)}")

    def stop(self):
        """Stops the packet sniffing thread."""
        self.running = False


class PacketSnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Wireless Traffic Analyzer")
        self.setGeometry(100, 100, 800, 600)

        # UI Components
        self.layout = QVBoxLayout()
        self.interface_label = QLabel("Select Network Interface:")
        self.interface_dropdown = QComboBox()
        self.verbose_checkbox = QCheckBox("Verbose Mode")
        self.start_button = QPushButton("Start Sniffing")
        self.stop_button = QPushButton("Stop Sniffing")
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        # Add matplotlib canvas for real-time graphing
        self.figure = Figure()
        self.canvas = FigureCanvas(self.figure)
        self.ax = self.figure.add_subplot(111)
        self.packet_times = []  # Store timestamps for graphing

        # Add available network interfaces
        self.interface_dropdown.addItems(self.get_available_interfaces())

        # Layout setup
        self.layout.addWidget(self.interface_label)
        self.layout.addWidget(self.interface_dropdown)
        self.layout.addWidget(self.verbose_checkbox)
        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.stop_button)
        self.layout.addWidget(self.log_area)
        self.layout.addWidget(self.canvas)  # Add graph to layout

        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

        # Thread for packet sniffing
        self.sniffer_thread = None

        # Button actions
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)

        # Disable stop button initially
        self.stop_button.setEnabled(False)

    def get_available_interfaces(self):
        """Fetches a list of available network interfaces."""
        try:
            return get_if_list()
        except Exception as e:
            return [f"Error fetching interfaces: {e}"]

    def start_sniffing(self):
        """Starts the packet sniffing process."""
        interface = self.interface_dropdown.currentText()
        if "Error" in interface or not interface:
            self.log_area.append("Error: No valid interface selected.\n")
            return

        verbose = self.verbose_checkbox.isChecked()
        self.log_area.append(f"Starting sniffer on interface: {interface}\n")

        self.sniffer_thread = PacketSnifferThread(interface, verbose)
        self.sniffer_thread.packet_captured.connect(self.update_log)
        self.sniffer_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        # Clear graph when starting
        self.packet_times.clear()
        self.ax.clear()
        self.ax.set_title("Packet Rate Over Time")
        self.canvas.draw()

    def stop_sniffing(self):
        """Stops the packet sniffing process."""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.log_area.append("Sniffer stopped.\n")

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_log(self, message):
        """Updates the log area and graph with captured packet details."""
        self.log_area.append(message)
        # Update graph for TCP packets
        if "TCP Packet" in message:
            current_time = datetime.now()
            self.packet_times.append(current_time)
            if len(self.packet_times) > 100:  # Limit to 100 points for performance
                self.packet_times.pop(0)
            self.ax.clear()
            self.ax.plot(self.packet_times, range(len(self.packet_times)), "b-")
            self.ax.set_title("Packet Rate Over Time")
            self.ax.set_xlabel("Time")
            self.ax.set_ylabel("Packet Count")
            self.canvas.draw()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec())
