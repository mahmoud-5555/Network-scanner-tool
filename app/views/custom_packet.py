import tkinter as tk
from tkinter import ttk, scrolledtext
import random
from scapy.all import srp, Ether, IP, TCP, UDP, ICMP, Raw
from models import network_scanner 


class CustomPacketScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen
        super().__init__(parent)

        self.controller = controller

        # Title
        tk.Label(self, text="Custom Packet Creator", font=("Arial", 18)).pack(pady=10)

        # Destination IP input
        tk.Label(self, text="Destination IP:").pack(anchor="w", padx=20)
        self.dst_ip_entry = tk.Entry(self, width=30)
        self.dst_ip_entry.pack(padx=20, pady=5)

        # Packet Type dropdown
        tk.Label(self, text="Packet Type:").pack(anchor="w", padx=20)
        self.packet_type_var = tk.StringVar()
        self.packet_type_var.set("ICMP")  # Default value
        ttk.OptionMenu(self, self.packet_type_var, "ICMP", "ICMP", "TCP SYN", "UDP", "Custom").pack(padx=20, pady=5)

        # Source Port input
        tk.Label(self, text="Source Port (optional):").pack(anchor="w", padx=20)
        self.src_port_entry = tk.Entry(self, width=30)
        self.src_port_entry.pack(padx=20, pady=5)

        # Destination Port input
        tk.Label(self, text="Destination Port (optional):").pack(anchor="w", padx=20)
        self.dst_port_entry = tk.Entry(self, width=30)
        self.dst_port_entry.pack(padx=20, pady=5)

        # Payload input
        tk.Label(self, text="Payload (optional):").pack(anchor="w", padx=20)
        self.payload_entry = tk.Text(self, width=50, height=5)
        self.payload_entry.pack(padx=20, pady=5)

        # Send Packet button
        tk.Button(self, text="Send Packet", command=self.send_packet).pack(pady=10)
        home_button = tk.Button(self, text="Back to Home", command=lambda: controller.show_frame(HomeScreen))
        home_button.pack(pady=10)

        # Output area
        tk.Label(self, text="Output:").pack(anchor="w", padx=20)
        self.output_text = scrolledtext.ScrolledText(self, width=80, height=20)
        self.output_text.pack(padx=20, pady=10)

    def send_packet(self):
        # Get user inputs
        dst_ip = self.dst_ip_entry.get().strip()
        packet_type = self.packet_type_var.get()
        src_port = self.src_port_entry.get().strip()
        dst_port = self.dst_port_entry.get().strip()
        payload = self.payload_entry.get("1.0", tk.END).strip()

        # Validate inputs
        if not dst_ip:
            self.output_text.insert(tk.END, "[!] Destination IP is required.\n")
            return

        if packet_type == "TCP SYN" and not dst_port:
            self.output_text.insert(tk.END, "[!] Destination Port is required for TCP SYN packets.\n")
            return
        elif packet_type == "UDP" and not dst_port:
            self.output_text.insert(tk.END, "[!] Destination Port is required for UDP packets.\n")
            return
    
        elif packet_type == "TCP SYN" and dst_port:
            packet_type = 'tcp_syn'

        elif packet_type == "Custom" and not payload:
            self.output_text.insert(tk.END, "[!] Payload is required for Custom packets.\n")
            return
        

        src_port = int(src_port) if src_port else None
        dst_port = int(dst_port) if dst_port else None
        payload = payload if payload else None

        try:
            # Call the function to create and send a packet
            sent_packets, received_packets = network_scanner.create_and_send_packet(
                dst_ip=dst_ip,
                packet_type=packet_type.lower(),
                src_port=src_port,
                dst_port=dst_port,
                payload=payload
            )

            # Display results in the output text box
            self.output_text.insert(tk.END, f"[+] Sent packets: {sent_packets}\n")
            self.output_text.insert(tk.END, f"[+] Received packets: {received_packets}\n")

        except Exception as e:
            self.output_text.insert(tk.END, f"[!] Error: {e}\n")