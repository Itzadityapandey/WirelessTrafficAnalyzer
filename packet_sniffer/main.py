import sys
from scapy.all import *
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton, QTextEdit,
    QCheckBox, QLabel, QLineEdit, QWidget, QComboBox
)
from PyQt6.QtCore import QThread, pyqtSignal

class PacketSnifferThread(QThread):
    packet_captured = pyqtSignal(str)

    def __init__(self, interface, verbose=False):
        super().__init__()
        self.interface = interface
        self.verbose = verbose
        self.running = False

    def handle_packet(self, packet):
        if packet.haslayer(TCP) and packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            log_entry = f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n"
            self.packet_captured.emit(log_entry)

    def run(self):
        self.running = True
        try:
            sniff(
                iface=self.interface,
                prn=self.handle_packet,
                store=0,
                stop_filter=lambda _: not self.running,
                verbose=self.verbose
            )
        except PermissionError:
            self.packet_captured.emit("Error: Permission denied. Run as administrator/root.")
        except Exception as e:
            self.packet_captured.emit(f"Error: {str(e)}")

    def stop(self):
        self.running = False

class PacketSnifferApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packet Sniffer")
        self.setGeometry(100, 100, 800, 600)

        # UI Components
        self.layout = QVBoxLayout()
        self.interface_label = QLabel("Network Interface:")
        self.verbose_checkbox = QCheckBox("Verbose Mode")
        self.start_button = QPushButton("Start Sniffing")
        self.stop_button = QPushButton("Stop Sniffing")
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)

        # Interface dropdown (auto-detect interfaces)
        self.interface_dropdown = QComboBox()
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

        # Threading for packet sniffing
        self.sniffer_thread = None

        # Button actions
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)

    def get_available_interfaces(self):
        try:
            return get_if_list()
        except Exception as e:
            return ["Error fetching interfaces"]

    def start_sniffing(self):
        interface = self.interface_dropdown.currentText()
        verbose = self.verbose_checkbox.isChecked()
        self.log_area.append(f"Starting sniffer on interface: {interface}\n")

        self.sniffer_thread = PacketSnifferThread(interface, verbose)
        self.sniffer_thread.packet_captured.connect(self.update_log)
        self.sniffer_thread.start()

    def stop_sniffing(self):
        if self.sniffer_thread and self.sniffer_thread.isRunning():
            self.sniffer_thread.stop()
            self.sniffer_thread.wait()
            self.log_area.append("Sniffer stopped.\n")

    def update_log(self, message):
        self.log_area.append(message)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSnifferApp()
    window.show()
    sys.exit(app.exec())
