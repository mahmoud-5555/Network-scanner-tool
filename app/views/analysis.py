import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import json
from scapy.all import conf


class AnalysisScreen(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        
        self.controller = controller
        
        # Title
        tk.Label(self, text="Packet Capture", font=("Arial", 18)).pack(pady=10)

        # Target IP input
        tk.Label(self, text="Target IP:").pack(anchor="w", padx=20)
        self.target_ip_entry = tk.Entry(self, width=30)
        self.target_ip_entry.pack(padx=20, pady=5)

        # Protocol dropdown
        tk.Label(self, text="Protocol:").pack(anchor="w", padx=20)
        self.protocol_var = tk.StringVar()
        self.protocol_var.set("None")  # Default value
        ttk.OptionMenu(self, self.protocol_var, "None", "TCP", "UDP", "ICMP").pack(padx=20, pady=5)

        # Duration input
        tk.Label(self, text="Duration (seconds):").pack(anchor="w", padx=20)
        self.duration_entry = tk.Entry(self, width=30)
        self.duration_entry.insert(0, "10")  # Default duration
        self.duration_entry.pack(padx=20, pady=5)

        # Packet count input
        tk.Label(self, text="Packet Count:").pack(anchor="w", padx=20)
        self.packet_count_entry = tk.Entry(self, width=30)
        self.packet_count_entry.insert(0, "100")  # Default count
        self.packet_count_entry.pack(padx=20, pady=5)

        # Start capture button
        tk.Button(self, text="Start Capture", command=self.start_capture).pack(pady=10)

        # Output area
        tk.Label(self, text="Captured Packets:").pack(anchor="w", padx=20)
        self.output_text = scrolledtext.ScrolledText(self, width=80, height=20)
        self.output_text.pack(padx=20, pady=10)

    def start_capture(self):
        # Get user inputs
        target_ip = self.target_ip_entry.get().strip() or None
        protocol = self.protocol_var.get()
        protocol = None if protocol == "None" else protocol
        try:
            duration = int(self.duration_entry.get().strip())
            packet_count = int(self.packet_count_entry.get().strip())
        except ValueError:
            self.output_text.insert(tk.END, "[!] Please enter valid numbers for duration and packet count.\n")
            return
        
        # Clear output area
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, "[+] Starting packet capture...\n")
        
        # Run capture in a separate thread to avoid GUI freezing
        threading.Thread(
            target=self.run_packet_capture,
            args=(target_ip, protocol, duration, packet_count),
            daemon=True
        ).start()

    def run_packet_capture(self, target_ip, protocol, duration, packet_count):
        try:
            # Call the packet_capture method from the controller's NetworkScanner instance
            results, json_output = self.controller.network_scanner.packet_capture(
                target_ip=target_ip,
                protocol=protocol,
                duration=duration,
                packet_count=packet_count
            )

            # Display results in the output text box
            self.output_text.insert(tk.END, json_output + "\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"[!] Error: {e}\n")
