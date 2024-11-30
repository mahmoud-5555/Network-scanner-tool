#!/usr/bin/env python3
import scapy.all as scapy
from tabulate import tabulate
import json


class NetworkScanner:
    def __init__(self, subnet='10.9.0.0/24'):
        # Configure scapy for non-root packet capture
        scapy.conf.promisc = True  # Enable promiscuous mode
        self.subnet = subnet

    def arp_scan(self):
        # Create ARP request packet
        arp_request = scapy.ARP(pdst=self.subnet)

        # Create Ethernet frame with broadcast address
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # Combine ARP request and Ethernet frame
        arp_request_broadcast = broadcast / arp_request

        # Send the request and get the response
        answered_list = scapy.srp(arp_request_broadcast,iface="br-25d5e6d47089" ,timeout=1, verbose=False)[0]

        # Parse the results
        results = []
        for sent, received in answered_list:
            results.append({
                'IP Address': received.psrc,
                'MAC Address': received.hwsrc
            })

        # Create a formatted table for easy display
        formatted_table = tabulate(results, headers='keys', tablefmt='grid')

        return results, formatted_table

    def packet_capture(self, target_ip=None, protocol=None, duration=10, packet_count=100):
        # Prepare capture filter
        capture_filter = ""
        
        if target_ip:
            capture_filter += f"host {target_ip} "
        
        if protocol:
            if protocol.lower() in ['tcp', 'udp', 'icmp']:
                capture_filter += protocol.upper()  # Ensure the protocol is in uppercase
            else:
                print("[!] Invalid protocol specified. Valid options are TCP, UDP, ICMP.")

        # Explicitly specify the network interface
        default_interface = "br-25d5e6d47089"  
        print(f"[+] Using interface: {default_interface}")

        # Capture packets
        try:
            print(f"[+] Starting packet capture with filter: {capture_filter or 'No filter'}")
            packets = scapy.sniff(
                iface=default_interface,  # Specify the interface explicitly
                filter=capture_filter,    # Apply filter if provided
                timeout=duration,         # Capture for the specified duration
                count=packet_count        # Capture the specified number of packets
            )
        except Exception as e:
            print(f"[!] Error during packet capture: {e}")
            return [], "[]"

        # Analyze and format packets
        packet_details = []
        for packet in packets:
            # Basic packet information extraction
            packet_info = {
                'timestamp': str(packet.time),
                'protocol': 'Unknown',
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'src_port': None,
                'dst_port': None
            }

            # Check for IP layer
            if packet.haslayer(scapy.IP):
                packet_info['src_ip'] = packet[scapy.IP].src
                packet_info['dst_ip'] = packet[scapy.IP].dst

                # Determine protocol
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

        # Create JSON output for easy parsing
        json_output = json.dumps(packet_details, indent=2)

        return packet_details, json_output

    def display_results(self, formatted_table):
        print("\n[+] Active Devices in Network:")
        print(formatted_table)


def main():
    # Option to hardcode the subnet or prompt the user for it
    subnet = input("Enter the subnet to scan (e.g., 10.9.0.0/24): ") or "10.9.0.0/24"

    # Create an instance of NetworkScanner
    scanner = NetworkScanner(subnet=subnet)

    # Perform the ARP scan
    print(f"\n[+] Scanning subnet: {subnet}")
    _, formatted_table = scanner.arp_scan()

    # Display the ARP scan results
    scanner.display_results(formatted_table)

    # Prompt for protocol to capture (TCP/UDP/ICMP or leave blank for all)
    protocol = input("Enter the protocol to capture (TCP/UDP/ICMP or leave blank for all): ").strip().lower()
    if protocol == "":
        protocol = None  # If empty, capture all protocols

    # Packet capture demonstration
    print("\n[+] Starting Packet Capture Demonstration")
    try:
        # Capture packets with the specified protocol for 5 seconds
        packet_list, json_packets = scanner.packet_capture(protocol=protocol, duration=5)

        # Print packet count and raw JSON
        print(f"[+] Captured {len(packet_list)} packets")
        print("[+] Packet Details (JSON Format):")
        print(json_packets)
    except Exception as e:
        print(f"[!] Error during packet capture: {e}")


if __name__== "__main__":
    main()