from scapy.all import sniff, TCP, IP, get_if_list
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
        """Handles and formats captured packets."""
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
        else:
            log_entry = f"Non-TCP/IPv4 packet captured: {packet.summary()}\n"
            if self.verbose:
                self.packet_captured.emit(log_entry)

    def run(self):
        self.running = True
        try:
            # Validate interface
            if self.interface not in get_if_list():
                self.packet_captured.emit(f"Error: Interface '{self.interface}' not found.")
                return

            # Start sniffing
            sniff(
                iface=self.interface,
                prn=self.handle_packet,
                store=False,
                stop_filter=lambda _: not self.running
            )
        except PermissionError:
            self.packet_captured.emit("Error: Permission denied. Run as administrator/root.")
        except ValueError as ve:
            self.packet_captured.emit(f"Error: Invalid interface selected. {ve}")
        except Exception as e:
            self.packet_captured.emit(f"Error: {str(e)}")

    def stop(self):
        """Stops the sniffing process."""
        self.running = False
