import tkinter as tk
from tkinter import scrolledtext
import json
import os
from models import network_scanner

class PerformanceScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen

        super().__init__(parent)
        self.controller = controller
        self.log_dir = "logs"
        os.makedirs(self.log_dir, exist_ok=True)
        self.logger = self.setup_logger()

        # Title
        tk.Label(self, text="Network Performance Metrics", font=("Arial", 18)).pack(pady=10)

        # Target URL input
        tk.Label(self, text="Target URL:").pack(anchor="w", padx=20)
        self.target_url_entry = tk.Entry(self, width=30)
        self.target_url_entry.insert(0, "10.9.0.5")  # Default target URL
        self.target_url_entry.pack(padx=20, pady=5)

        # Duration input
        tk.Label(self, text="Duration (seconds):").pack(anchor="w", padx=20)
        self.duration_entry = tk.Entry(self, width=30)
        self.duration_entry.insert(0, "10")  # Default duration
        self.duration_entry.pack(padx=20, pady=5)

        # Measure Performance button
        tk.Button(self, text="Measure Performance", command=self.measure_network_performance).pack(pady=10)
        home_button = tk.Button(self, text="Back to Home", command=lambda: controller.show_frame(HomeScreen))
        home_button.pack(pady=10)

        # Output area
        tk.Label(self, text="Output:").pack(anchor="w", padx=20)
        self.output_text = scrolledtext.ScrolledText(self, width=80, height=20)
        self.output_text.pack(padx=20, pady=10)

    def setup_logger(self):
        import logging
        logger = logging.getLogger("PerformanceLogger")
        logger.setLevel(logging.INFO)
        handler = logging.FileHandler(os.path.join(self.log_dir, "performance.log"))
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logger.addHandler(handler)
        return logger

    def measure_network_performance(self):
        target_url = self.target_url_entry.get().strip()
        duration = int(self.duration_entry.get().strip())

        self.logger.info("Starting network performance measurement...")

        try:
            performance_metrics = network_scanner.measure_network_performance(target_url, duration)

            self.logger.info(
                f"Network Performance: Download: {performance_metrics['throughput_Mbps']:.2f} Mbps, "
                f"Upload: {performance_metrics['data_rate_Mbps']:.2f} Mbps, Latency: {performance_metrics['latency_ms']}, "
                f"Jitter: {performance_metrics['jitter_ms']:.2f} ms"
            )

            performance_file = os.path.join(self.log_dir, "network_performance.json")
            with open(performance_file, "w") as file:
                json.dump(performance_metrics, file, indent=2)

            self.logger.info(f"Network performance metrics logged to: {performance_file}")

            self.output_text.insert(tk.END, json.dumps(performance_metrics, indent=2) + "\n")
        except Exception as e:
            self.logger.error(f"Error measuring network performance: {e}")
            self.output_text.insert(tk.END, f"[!] Error: {e}\n")
