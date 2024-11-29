import tkinter as tk


class CustomPacketScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen
    
        super().__init__(parent)

        label = tk.Label(self, text="Custom Packet Creation", font=("Helvetica", 20))
        label.pack(pady=20)

        # Input fields for custom packet
        tk.Label(self, text="Destination IP Address:").pack(pady=5)
        self.ip_entry = tk.Entry(self, width=30)
        self.ip_entry.pack(pady=5)

        tk.Label(self, text="Protocol (e.g., ICMP, TCP):").pack(pady=5)
        self.protocol_entry = tk.Entry(self, width=30)
        self.protocol_entry.pack(pady=5)

        tk.Label(self, text="Port (if applicable):").pack(pady=5)
        self.port_entry = tk.Entry(self, width=30)
        self.port_entry.pack(pady=5)

        tk.Button(self, text="Send Packet", 
                  command=self.send_packet).pack(pady=10)

        tk.Button(self, text="Back", 
                  command=lambda: controller.show_frame(HomeScreen)).pack(pady=10)

        self.result_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.result_label.pack(pady=10)

    def send_packet(self):
        # Placeholder for sending the packet logic
        ip = self.ip_entry.get()
        protocol = self.protocol_entry.get()
        port = self.port_entry.get()
        self.result_label.config(
            text=f"Sending {protocol} packet to {ip}:{port if port else 'N/A'} (Placeholder)"
        )