import tkinter as tk
from tkinter import ttk
from scapy.all import conf
import threading
from models import network_scanner


class DiscoveryScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen

        super().__init__(parent)
        
        # Title label
        label = tk.Label(self, text="Network Discovery", font=("Helvetica", 20))
        label.pack(pady=20)
        
        # Subnet entry
        self.subnet_label = tk.Label(self, text="Enter Subnet (e.g., 192.168.1.0/24):")
        self.subnet_label.pack(pady=5)
        self.subnet_entry = tk.Entry(self, width=30)
        self.subnet_entry.pack(pady=5)
        self.subnet_entry.insert(0, "10.9.0.0/24")  # Default value
        
        # Button to trigger ARP scan
        scan_button = tk.Button(self, text="Start ARP Scan", command=self.run_scan)
        scan_button.pack(pady=10)
        home_button = tk.Button(self, text="Back to Home", command=lambda: controller.show_frame(HomeScreen))
        home_button.pack(pady=10)
        
        # Treeview to display results
        self.results_tree = ttk.Treeview(self, columns=("IP Address", "MAC Address"), show="headings")
        self.results_tree.heading("IP Address", text="IP Address")
        self.results_tree.heading("MAC Address", text="MAC Address")
        self.results_tree.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Text widget for tabulated results
        self.result_text = tk.Text(self, height=10, wrap="none")
        self.result_text.pack(fill="both", expand=True, padx=20, pady=10)

    def run_scan(self):
        # Use a thread to avoid freezing the UI
        threading.Thread(target=self.perform_scan).start()

    def perform_scan(self):
        # Get subnet from entry
        subnet = self.subnet_entry.get().strip()
        if not subnet:
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, "Error: Please enter a valid subnet.")
            return
        
        # Update scanner's subnet
        network_scanner.subnet = subnet
        
        try:
            # Perform the ARP scan
            results, formatted_table = network_scanner.arp_scan()
            
            # Update Treeview with results
            self.results_tree.delete(*self.results_tree.get_children())  # Clear previous results
            for item in results:
                self.results_tree.insert("", "end", values=(item["IP Address"], item["MAC Address"]))

            # Update Text widget with formatted table
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, formatted_table)
        except Exception as e:
            # Handle errors (e.g., invalid subnet or permissions)
            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"Error: {str(e)}")
