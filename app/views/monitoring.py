import os
import logging
import tkinter as tk
from tkinter import ttk, messagebox
from models import network_scanner

class MonitoringScreen(tk.Frame):
    def __init__(self, parent, log_dir="logs"):
        super().__init__(parent)
        self.parent = parent
        self.log_dir = log_dir
        self.logger = None  # Placeholder for the logger instance

        # Set up the frame layout
        self.create_widgets()

    def create_widgets(self):
        """Set up GUI components for logging management."""

        # Logging Directory Configuration
        directory_frame = ttk.LabelFrame(self, text="Logging Directory")
        directory_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(directory_frame, text="Directory:").pack(side="left", padx=5)
        self.dir_entry = ttk.Entry(directory_frame, width=40)
        self.dir_entry.insert(0, self.log_dir)
        self.dir_entry.pack(side="left", padx=5)
        ttk.Button(directory_frame, text="Create Directory", command=network_scanner._setup_logging_directory).pack(side="left", padx=5)

        # Logger Configuration
        logger_frame = ttk.LabelFrame(self, text="Logger Configuration")
        logger_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(logger_frame, text="Logger Name:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.logger_name_entry = ttk.Entry(logger_frame, width=20)
        self.logger_name_entry.grid(row=0, column=1, padx=5, pady=5)

        ttk.Label(logger_frame, text="Log Filename:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.filename_entry = ttk.Entry(logger_frame, width=20)
        self.filename_entry.grid(row=1, column=1, padx=5, pady=5)

        ttk.Label(logger_frame, text="Log Level:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.log_level_combo = ttk.Combobox(logger_frame, values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"], width=17)
        self.log_level_combo.set("INFO")
        self.log_level_combo.grid(row=2, column=1, padx=5, pady=5)

        ttk.Button(logger_frame, text="Configure Logger", command=network_scanner._configure_logger).grid(row=3, column=0, columnspan=2, pady=10)

        # Log Display
        log_display_frame = ttk.LabelFrame(self, text="Log Output")
        log_display_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.log_display = tk.Text(log_display_frame, wrap="word", state="disabled", height=10)
        self.log_display.pack(fill="both", expand=True, padx=5, pady=5)

    

    def _display_log(self, message):
        """Display a log message in the GUI."""
        self.log_display.config(state="normal")
        self.log_display.insert("end", message + "\n")
        self.log_display.config(state="disabled")
        self.log_display.see("end")

