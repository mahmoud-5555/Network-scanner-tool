""" This module for home screen for """
import tkinter as tk
from views.discovery import DiscoveryScreen
from views.analysis import AnalysisScreen
from views.custom_packet import CustomPacketScreen
from views.monitoring import MonitoringScreen
from views.performance import PerformanceScreen
from config import settings
import tkinter as tk


class App(tk.Tk):
    """represent the app class with all screens"""
    def __init__(self):
        super().__init__()
        self.geometry(settings.screen_size)
        self.title(settings.app_title)

        
        

        # Container to hold all frames (screens)
        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        # Dictionary to store screens
        self.frames = {}

         # Initialize screens
        for F in (HomeScreen, DiscoveryScreen, AnalysisScreen, 
          CustomPacketScreen, MonitoringScreen, PerformanceScreen):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # the menu bar of the program 
         
        menu_bar = tk.Menu(self)
        menu_bar.add_command(label="About")
        menu_bar.add_command(label="Help")
        menu_bar.add_command(label="Quit",command=self.quit)
        self.config(menu=menu_bar)
    
    
        self.show_frame(HomeScreen)

    def show_frame(self, frame_class):
        """Switch to the specified frame."""
        frame = self.frames[frame_class]
        frame.tkraise()  # Bring the frame to the front



class HomeScreen(tk.Frame):
   def __init__(self, parent, controller):
        super().__init__(parent)

        label = tk.Label(self, text="Network Scanner Tool", font=("Helvetica", 20))
        label.pack(pady=20)

        # Buttons to navigate to other screens
        tk.Button(self, text="Network Discovery", width=20, 
                  command=lambda: controller.show_frame(DiscoveryScreen)).pack(pady=10)
        tk.Button(self, text="Packet Analysis", width=20, 
                  command=lambda: controller.show_frame(AnalysisScreen)).pack(pady=10)
        tk.Button(self, text="Custom Packet", width=20, 
                  command=lambda: controller.show_frame(CustomPacketScreen)).pack(pady=10)
        tk.Button(self, text="Traffic Monitoring", width=20, 
                  command=lambda: controller.show_frame(MonitoringScreen)).pack(pady=10)
        tk.Button(self, text="Performance Metrics", width=20, 
                  command=lambda: controller.show_frame(PerformanceScreen)).pack(pady=10)

