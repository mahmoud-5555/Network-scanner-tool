import tkinter as tk


class DiscoveryScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen
        super().__init__(parent)

        label = tk.Label(self, text="Network Discovery", font=("Helvetica", 20))
        label.pack(pady=20)

        # Input for subnet
        tk.Label(self, text="Enter Subnet (e.g., 192.168.1.0/24):").pack(pady=5)
        subnet_entry = tk.Entry(self, width=30)
        subnet_entry.pack(pady=5)

        # Start Scan Button
        tk.Button(self, text="Start Scan", 
                  command=lambda: self.perform_scan(subnet_entry.get())).pack(pady=10)

        # Back Button
        tk.Button(self, text="Back", 
                  command=lambda: controller.show_frame(HomeScreen)).pack(pady=10)

        # Results Display
        self.result_label = tk.Label(self, text="", font=("Helvetica", 12))
        self.result_label.pack(pady=10)

    def perform_scan(self, subnet):
        # Placeholder for ARP scan logic
        results = f"Scanning subnet: {subnet}...\nActive devices: \n1. 192.168.1.1 (MAC: 00:11:22:33:44:55)"
        self.result_label.config(text=results)