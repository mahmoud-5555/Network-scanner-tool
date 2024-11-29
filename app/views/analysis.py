import tkinter as tk


class AnalysisScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen
        super().__init__(parent)

        label = tk.Label(self, text="Packet Analysis", font=("Helvetica", 20))
        label.pack(pady=20)

        # Input for target IP and protocol filter
        tk.Label(self, text="Target IP Address:").pack(pady=5)
        self.ip_entry = tk.Entry(self, width=30)
        self.ip_entry.pack(pady=5)

        tk.Label(self, text="Filter by Protocol (e.g., TCP, UDP, ICMP):").pack(pady=5)
        self.filter_entry = tk.Entry(self, width=30)
        self.filter_entry.pack(pady=5)

        # Start/Stop Capture Buttons
        tk.Button(self, text="Start Capture", command=self.start_capture).pack(pady=10)
        tk.Button(self, text="Stop Capture", command=self.stop_capture).pack(pady=10)

        # Results Display
        self.result_label = tk.Label(self, text="No packets captured yet...", font=("Helvetica", 12))
        self.result_label.pack(pady=10)

        tk.Button(self, text="Back", 
                  command=lambda: controller.show_frame(HomeScreen)).pack(pady=10)

    def start_capture(self):
        # Placeholder for packet capturing logic
        target_ip = self.ip_entry.get()
        protocol_filter = self.filter_entry.get()
        self.result_label.config(
            text=f"Capturing packets for {target_ip} with filter: {protocol_filter} (Placeholder)"
        )

    def stop_capture(self):
        # Placeholder for stopping packet capture logic
        self.result_label.config(text="Packet capture stopped.")
