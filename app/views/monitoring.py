import tkinter as tk


class MonitoringScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen
    
        super().__init__(parent)

        label = tk.Label(self, text="Traffic Monitoring", font=("Helvetica", 20))
        label.pack(pady=20)

        # Start/Stop Buttons
        tk.Button(self, text="Start Monitoring", command=self.start_monitoring).pack(pady=10)
        tk.Button(self, text="Stop Monitoring", command=self.stop_monitoring).pack(pady=10)

        # Live Traffic Display
        self.traffic_label = tk.Label(self, text="No traffic being monitored...", font=("Helvetica", 12))
        self.traffic_label.pack(pady=10)

        # Log Traffic Button
        tk.Button(self, text="Log Traffic to File", command=self.log_traffic).pack(pady=10)

        tk.Button(self, text="Back", 
                  command=lambda: controller.show_frame(HomeScreen)).pack(pady=10)

    def start_monitoring(self):
        # Placeholder for starting traffic monitoring logic
        self.traffic_label.config(text="Monitoring traffic... (Placeholder)")

    def stop_monitoring(self):
        # Placeholder for stopping traffic monitoring logic
        self.traffic_label.config(text="Traffic monitoring stopped.")

    def log_traffic(self):
        # Placeholder for logging traffic to a file
        with open("traffic_log.txt", "w") as file:
            file.write("Logged traffic data (Placeholder)")
        self.traffic_label.config(text="Traffic logged to traffic_log.txt")
