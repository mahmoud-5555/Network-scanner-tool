import tkinter as tk


class PerformanceScreen(tk.Frame):
    def __init__(self, parent, controller):
        from views.home import HomeScreen

        super().__init__(parent)

        label = tk.Label(self, text="Performance Metrics", font=("Helvetica", 20))
        label.pack(pady=20)

        # Metrics Display
        self.metrics_label = tk.Label(self, text="Calculating metrics...", font=("Helvetica", 12))
        self.metrics_label.pack(pady=10)

        # Button to calculate metrics
        tk.Button(self, text="Calculate Metrics", command=self.calculate_metrics).pack(pady=10)

        # Button to save metrics to a file
        tk.Button(self, text="Save Metrics to File", command=self.save_metrics).pack(pady=10)

        tk.Button(self, text="Back",
                  command=lambda: controller.show_frame(HomeScreen)).pack(pady=10)

    def calculate_metrics(self):
        # Placeholder for performance calculation logic
        metrics = """
        Data Rate: 100 Mbps
        Throughput: 98 Mbps
        Latency: 20 ms
        Jitter: 5 ms
        """
        self.metrics_label.config(text=metrics)

    def save_metrics(self):
        # Placeholder for saving metrics to a file
        with open("performance_metrics.txt", "w") as file:
            file.write(self.metrics_label.cget("text"))
        self.metrics_label.config(text="Metrics saved to performance_metrics.txt")
