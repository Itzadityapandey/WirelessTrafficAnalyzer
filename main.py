import sys
from scapy.all import get_if_list
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit,
    QCheckBox, QLabel, QComboBox, QWidget
)
from PyQt6.QtCore import QThread, pyqtSignal
from datetime import datetime


class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(str)

    def __init__(self, interface, verbose=False):
        super().__init__()
        self.interface = interface
        self.verbose = verbose
        self.running = False

    def handle_packet(self, packet):
        """Handles incoming packets and emits log messages."""
        from scapy.layers.inet import TCP, IP
        if packet.haslayer(TCP) and packet.haslayer(IP):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_entry = (
                f"[{timestamp}] TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
            )
            self.packet_captured.emit(log_entry)

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

        # Add available network interfaces
        self.interface_dropdown.addItems(self.get_available_interfaces())

        # Layout setup
        self.layout.addWidget(self.interface_label)
        self.layout.addWidget(self.interface_dropdown)
        self.layout.addWidget(self.verbose_checkbox)
        self.layout.addWidget(self.start_button)
        self.layout.addWidget(self.stop_button)
        self.layout.addWidget(self.log_area)

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

    def stop_sniffing(self):
        """Stops the packet sniffing process."""
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.log_area.append("Sniffer stopped.\n")

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def update_log(self, message):
        """Updates the log area with captured packet details."""
        self.log_area.append(message)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec())
