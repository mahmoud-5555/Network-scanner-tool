import scapy.all as scapy
from tabulate import tabulate
import json
import random
import os
from datetime import datetime
import logging
import speedtest
import subprocess
import concurrent.futures



class NetworkScanner:
    def __init__(self, subnet='10.9.0.0/24', log_dir='network_logs'):
        # Configure scapy for non-root packet capture
        scapy.conf.promisc = True  # Enable promiscuous mode
        self.subnet = subnet
        
        # Setup logging directory
        self.log_dir = log_dir
        self._setup_logging_directory()
        
        # Configure main logging
        self.logger = self._configure_logger('network_scanner', 'network_scanner.log')
        
        # Packet-specific logger
        self.packet_logger = self._configure_logger('packet_capture', 'packet_capture.log')
        

    def _setup_logging_directory(self):
        """Create logging directory if it doesn't exist."""
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            print(f"[+] Logging directory created: {self.log_dir}")
        except Exception as e:
            print(f"[!] Error creating logging directory: {e}")

    def _configure_logger(self, name, filename, level=logging.INFO):
        """
        Configure and return a logger with file and console output.
        
        :param name: Name of the logger
        :param filename: Log file name
        :param level: Logging level
        :return: Configured logger
        """
        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Clear any existing handlers to prevent duplicate logs
        logger.handlers.clear()
        
        # File handler
        log_path = os.path.join(self.log_dir, filename)
        file_handler = logging.FileHandler(log_path)
        file_handler.setLevel(level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(level)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s', 
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    def measure_network_performance(self, target_url="10.9.0.5", duration=10):
        """
        Measure network performance including data rate, throughput, latency, and jitter.
        
        :param target_url: URL to measure performance against (default: Google's homepage).
        :param duration: Time duration to collect measurements.
        :return: Dictionary with performance metrics.
        """
        self.logger.info("Starting network performance measurement...")
        
        # Initialize performance metrics
        performance_metrics = {
            "latency_ms": [],
            "jitter_ms": 0,
            "throughput_Mbps": 0,
            "data_rate_Mbps": 0
        }
        
        try:
            # Measure latency and jitter
            start_time = datetime.now()
            latencies = []
            for _ in range(5):  # Perform 5 ping tests
                ping_start = datetime.now()
                response = subprocess.run(
                    ["ping", "-c", "1", target_url],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                ping_end = datetime.now()
                
                if response.returncode == 0:
                    latency = (ping_end - ping_start).total_seconds() * 1000  # Convert to milliseconds
                    latencies.append(latency)
                    self.logger.info(f"Ping latency: {latency:.2f} ms")
                else:
                    self.logger.warning("Ping failed.")
            
            performance_metrics["latency_ms"] = latencies
            if len(latencies) > 1:
                performance_metrics["jitter_ms"] = max(latencies) - min(latencies)
            
            # Measure throughput and data rate using speedtest
            st = speedtest.Speedtest()
            st.get_best_server()
            download_speed = st.download() / 1e6  # Convert to Mbps
            upload_speed = st.upload() / 1e6  # Convert to Mbps
            performance_metrics["throughput_Mbps"] = download_speed
            performance_metrics["data_rate_Mbps"] = upload_speed
            
            end_time = datetime.now()
            elapsed_time = (end_time - start_time).total_seconds()
            self.logger.info(
                f"Network Performance: Download: {download_speed:.2f} Mbps, "
                f"Upload: {upload_speed:.2f} Mbps, Latency: {performance_metrics['latency_ms']}, "
                f"Jitter: {performance_metrics['jitter_ms']:.2f} ms, Duration: {elapsed_time:.2f} seconds"
            )
        except Exception as e:
            self.logger.error(f"Error measuring network performance: {e}")
        
        # Save performance metrics to a log file
        performance_file = os.path.join(self.log_dir, "network_performance.json")
        with open(performance_file, "w") as file:
            json.dump(performance_metrics, file, indent=2)
        
        self.logger.info(f"Network performance metrics logged to: {performance_file}")
        return performance_metrics


    def arp_scan(self):
        """Perform ARP scan on the specified subnet."""
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=self.subnet)

        # Create Ethernet frame with broadcast address
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine ARP request and Ethernet frame
        arp_request_broadcast = broadcast / arp_request

        # Log the ARP scan
        self.logger.info(f"Performing ARP scan on subnet: {self.subnet}")

        # Send the request and get the response
        answered_list = scapy.srp(arp_request_broadcast, iface="br-25d5e6d47089", timeout=1, verbose=False)[0]

        # Parse the results
        results = []
        for sent, received in answered_list:
            device_info = {
                'IP Address': received.psrc,
                'MAC Address': received.hwsrc
            }
            results.append(device_info)
            
            # Log each discovered device
            self.logger.info(f"Discovered device: IP {received.psrc} - MAC {received.hwsrc}")

        # Create a formatted table for easy display
        formatted_table = tabulate(results, headers='keys', tablefmt='grid')

        return results, formatted_table

    def packet_capture(self, 
                       target_ip=None, 
                       protocol=None, 
                       duration=10, 
                       packet_count=100, 
                       log_to_file=True):
        """
        Enhanced packet capture with detailed logging.
        
        :param target_ip: Optional IP to filter
        :param protocol: Protocol to filter (TCP/UDP/ICMP)
        :param duration: Capture duration in seconds
        :param packet_count: Maximum number of packets to capture
        :param log_to_file: Whether to log packets to a timestamped file
        :return: Tuple of packet details and JSON representation
        """
        # Prepare capture filter
        capture_filter = ""

        if target_ip:
            capture_filter += f"host {target_ip} "

        if protocol:
            # Ensure protocol is lowercase and valid
            protocol = protocol.lower()
            if protocol in ['tcp', 'udp', 'icmp']:
                capture_filter += protocol
            else:
                self.logger.error(f"Invalid protocol specified: {protocol}")
                return [], "[]"

        # Strip extra whitespace from the filter string
        capture_filter = capture_filter.strip()

        # Explicitly specify the network interface
        default_interface = "br-25d5e6d47089"
        self.logger.info(f"Using interface: {default_interface}")
        self.logger.info(f"Capture filter: {capture_filter or 'No filter'}")

        # Prepare logging file if requested
        log_file = None
        if log_to_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"packet_capture_{timestamp}.pcap"
            log_path = os.path.join(self.log_dir, log_filename)
            
            # Use scapy's PCAP writer for comprehensive packet logging
            log_file = scapy.wrpcap(log_path, [], append=True)
            self.logger.info(f"Logging packets to: {log_path}")

        try:
            # Capture packets
            self.packet_logger.info("Starting packet capture")
            packets = scapy.sniff(
                iface=default_interface,
                filter=capture_filter,
                timeout=duration,
                count=packet_count
            )

            # Log packets to PCAP if file is open
            if log_to_file and log_file is not None:
                scapy.wrpcap(log_path, packets, append=True)
                self.packet_logger.info(f"Logged {len(packets)} packets to {log_path}")

            # Analyze and format packets
            packet_details = []
            for packet in packets:
                packet_info = {
                    'timestamp': str(packet.time),
                    'protocol': 'Unknown',
                    'src_ip': 'N/A',
                    'dst_ip': 'N/A',
                    'src_port': None,
                    'dst_port': None,
                    'packet_size': len(packet)
                }

                # Detailed packet analysis
                if packet.haslayer(scapy.IP):
                    packet_info['src_ip'] = packet[scapy.IP].src
                    packet_info['dst_ip'] = packet[scapy.IP].dst

                    if packet.haslayer(scapy.TCP):
                        packet_info['protocol'] = 'TCP'
                        packet_info['src_port'] = packet[scapy.TCP].sport
                        packet_info['dst_port'] = packet[scapy.TCP].dport
                    elif packet.haslayer(scapy.UDP):
                        packet_info['protocol'] = 'UDP'
                        packet_info['src_port'] = packet[scapy.UDP].sport
                        packet_info['dst_port'] = packet[scapy.UDP].dport
                    elif packet.haslayer(scapy.ICMP):
                        packet_info['protocol'] = 'ICMP'

                packet_details.append(packet_info)
                
                # Log each packet's details
                self.packet_logger.info(
                    f"Captured Packet: {packet_info['protocol']} "
                    f"from {packet_info['src_ip']}:{packet_info.get('src_port', 'N/A')} "
                    f"to {packet_info['dst_ip']}:{packet_info.get('dst_port', 'N/A')} "
                    f"Size: {packet_info['packet_size']} bytes"
                )

            # Create JSON output for easy parsing
            json_output = json.dumps(packet_details, indent=2)

            return packet_details, json_output

        except Exception as e:
            self.logger.error(f"Packet capture error: {e}")
            return [], "[]"

    def create_and_send_packet(self, 
                                dst_ip, 
                                packet_type='icmp', 
                                src_port=None, 
                                dst_port=None, 
                                payload=None):
        """
        Create and send custom network packets.
        
        Parameters:
        - dst_ip (str): Destination IP address
        - packet_type (str): Type of packet to create 
          Options: 'icmp' (ping), 'tcp_syn', 'udp', 'custom'
        - src_port (int, optional): Source port for TCP/UDP packets
        - dst_port (int, optional): Destination port for TCP/UDP packets
        - payload (str, optional): Custom payload for the packet
        
        Returns:
        - tuple: (sent packets, received packets)
        """
        # Validate IP address
        try:
            scapy.IP(dst=dst_ip)
        except Exception:
            self.logger.error(f"Invalid destination IP: {dst_ip}")
            return None, None

        # Interface to use
        interface = "br-25d5e6d47089"

        # Generate a random source MAC address
        src_mac = ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
        dst_mac = "ff:ff:ff:ff:ff:ff"  # Broadcast MAC for demonstration

        # Log packet creation
        self.logger.info(f"Creating {packet_type.upper()} packet to {dst_ip}")

        # ICMP Ping Packet
        if packet_type.lower() == 'icmp':
            packet = (
                scapy.Ether(src=src_mac, dst=dst_mac) /  # Ethernet II header
                scapy.IP(dst=dst_ip) /  # IP header
                scapy.ICMP()  # ICMP payload
            )

        # TCP SYN Packet (for port scanning/connection testing)
        elif packet_type.lower() == 'tcp_syn':
            if not dst_port:
                self.logger.warning("No destination port specified for TCP SYN")
                return None, None
            
            # Use random source port if not specified
            if not src_port:
                src_port = random.randint(1024, 65535)
            
            packet = (
                scapy.Ether(src=src_mac, dst=dst_mac) /  # Ethernet II header
                scapy.IP(dst=dst_ip) /  # IP header
                scapy.TCP(dport=dst_port, sport=src_port, flags="S")  # TCP SYN packet
            )

        # UDP Packet
        elif packet_type.lower() == 'udp':
            if not dst_port:
                self.logger.warning("No destination port specified for UDP")
                return None, None
            
            # Use random source port if not specified
            if not src_port:
                src_port = random.randint(1024, 65535)
            
            # Add optional payload
            if payload:
                packet = (
                    scapy.Ether(src=src_mac, dst=dst_mac) /  # Ethernet II header
                    scapy.IP(dst=dst_ip) /  # IP header
                    scapy.UDP(dport=dst_port, sport=src_port) /  # UDP header
                    scapy.Raw(load=payload)  # Payload
                )
            else:
                packet = (
                    scapy.Ether(src=src_mac, dst=dst_mac) /  # Ethernet II header
                    scapy.IP(dst=dst_ip) /  # IP header
                    scapy.UDP(dport=dst_port, sport=src_port)  # UDP header
                )

        # Custom Packet (for advanced users)
        elif packet_type.lower() == 'custom':
            if payload is None:
                self.logger.warning("No payload specified for custom packet")
                return None, None
            
            try:
                # Attempt to create a custom packet from payload
                packet = (
                    scapy.Ether(src=src_mac, dst=dst_mac) /  # Ethernet II header
                    scapy.IP(dst=dst_ip) /  # IP header
                    scapy.Raw(load=payload)  # Custom payload
                )
            except Exception as e:
                self.logger.error(f"Error creating custom packet: {e}")
                return None, None

        else:
            self.logger.error(f"Unsupported packet type: {packet_type}")
            return None, None

        # Send packet and capture response
        try:
            # Send packet and wait for response
            sent_packets, received_packets = scapy.srp(
                packet, 
                iface=interface, 
                timeout=2, 
                verbose=False
            )
            
            # Log transmission results
            self.logger.info(f"Packet Transmission: Sent {len(sent_packets)} packet(s)")
            if received_packets:
                self.logger.info(f"Received {len(received_packets)} response(s)")
            
            return sent_packets, received_packets

        except Exception as e:
            self.logger.error(f"Packet transmission error: {e}")
            return None, None

    def display_results(self, formatted_table):
        print("\n[+] Active Devices in Network:")
        print(formatted_table)