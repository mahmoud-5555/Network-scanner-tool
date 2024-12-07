""" This module for home screen for """
import tkinter as tk
from models.NetworkScanne import NetworkScanner
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



def main():
    # Create an instance of NetworkScanner with a specific log directory
    scanner = NetworkScanner(subnet="10.9.0.0/24", log_dir="network_logs")

    while True:
        # Display the menu
        print("\n[+] Network Scanner Menu")
        print("1. ARP Scan")
        print("2. Measure Network Performance")
        print("3. Capture Packets")
        print("4. Create and Send Custom Packets")
        print("5. Exit")

        # Get user input for the action
        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == '1':
            # Perform the ARP scan
            print(f"\n[+] Scanning subnet: {scanner.subnet}")
            _, formatted_table = scanner.arp_scan()
            # Display the ARP scan results
            scanner.display_results(formatted_table)

        elif choice == '2':
            # Measure Network Performance
            print("\n[+] Measuring Network Performance")
            try:
                performance_metrics = scanner.measure_network_performance()
                print("\n[+] Network Performance Metrics:")
                for key, value in performance_metrics.items():
                    if isinstance(value, list):
                        print(f"  {key}: {value}")
                    else:
                        print(f"  {key}: {value:.2f}")
            except Exception as e:
                print(f"[!] Error measuring network performance: {e}")

        elif choice == '3':
            # Packet Capture Demonstration with Logging
            print("\n[+] Starting Packet Capture Demonstration")
            try:
                # Capture packets with optional filtering and logging
                protocol = input("Enter protocol to capture (TCP/UDP/ICMP or leave blank): ").strip().lower() or None
                duration = int(input("Enter capture duration (seconds, default 10): ") or "10")

                packet_list, json_packets = scanner.packet_capture(
                    protocol=protocol,
                    duration=duration,
                    log_to_file=True  # Enable file logging
                )

                # Print summary
                print(f"[+] Captured {len(packet_list)} packets")
                print("[+] Check network_logs directory for detailed packet capture logs")
            except Exception as e:
                print(f"[!] Error during packet capture: {e}")

        elif choice == '4':
            # Packet Creation and Transmission
            print("\n[+] Starting Packet Creation and Transmission")
            dst_ip = input("Enter destination IP for test packet (e.g., 10.9.0.5): ").strip()
            packet_type = input("Enter packet type (ICMP, TCP_SYN, UDP, or Custom): ").strip().lower()

            try:
                if packet_type == 'tcp_syn':
                    dst_port = int(input("Enter destination port for TCP SYN packet: "))
                    sent_packets, received_packets = scanner.create_and_send_packet(
                        dst_ip=dst_ip,
                        packet_type='tcp_syn',
                        dst_port=dst_port
                    )
                elif packet_type == 'udp':
                    dst_port = int(input("Enter destination port for UDP packet: "))
                    payload = input("Enter optional payload for UDP packet (press Enter to skip): ").strip() or None
                    sent_packets, received_packets = scanner.create_and_send_packet(
                        dst_ip=dst_ip,
                        packet_type='udp',
                        dst_port=dst_port,
                        payload=payload
                    )
                elif packet_type == 'custom':
                    payload = input("Enter custom packet payload: ").strip()
                    sent_packets, received_packets = scanner.create_and_send_packet(
                        dst_ip=dst_ip,
                        packet_type='custom',
                        payload=payload
                    )
                else:  # default to ICMP
                    sent_packets, received_packets = scanner.create_and_send_packet(
                        dst_ip=dst_ip,
                        packet_type='icmp'
                    )

                # Display packet transmission results
                if sent_packets and received_packets:
                    print(f"[+] Sent {len(sent_packets)} packet(s)")
                    print(f"[+] Received {len(received_packets)} response(s)")
                else:
                    print("[!] No packets sent or no responses received")

            except Exception as e:
                print(f"[!] Error during packet transmission: {e}")

        elif choice == '5':
            # Exit the program
            print("\n[+] Exiting...")
            break

        else:
            # Handle invalid choice
            print("[!] Invalid choice, please select a valid option from the menu.")

