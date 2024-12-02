
from scapy.all import sniff, TCP, IP
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
