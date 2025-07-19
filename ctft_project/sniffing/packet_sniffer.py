#!/usr/bin/env python3
"""
PySniff: Python-Based Packet Sniffer
A comprehensive network packet analyzer for CTFT project
"""

from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP
import json
import time
import os
from datetime import datetime
from colorama import init, Fore, Style
import threading
import signal
import sys

# Initialize colorama for colored output
init(autoreset=True)

class PacketSniffer:
    def __init__(self):
        self.blacklist = self.load_blacklist()
        self.alert_ports = {4444, 23, 3389, 22, 80, 443, 8080}  # Common malware ports
        self.suspicious_patterns = [
            b'GET /admin',
            b'POST /login',
            b'cmd.exe',
            b'powershell',
            b'wget',
            b'curl'
        ]
        self.packet_count = 0
        self.alert_count = 0
        self.running = True
        
        # Create log file if it doesn't exist
        self.log_file = "sniffing/packet_log.json"
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def load_blacklist(self):
        """Load IP blacklist from file or use default"""
        blacklist_file = "sniffing/ip_blacklist.txt"
        if os.path.exists(blacklist_file):
            try:
                with open(blacklist_file, 'r') as f:
                    return set(line.strip() for line in f if line.strip())
            except:
                pass
        return {"185.21.214.72", "192.168.1.200", "10.0.0.100"}
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}[*] Stopping packet sniffer...")
        self.running = False
        self.print_summary()
        sys.exit(0)
    
    def analyze_packet(self, packet):
        """Analyze packet for suspicious patterns"""
        alerts = []
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Check blacklisted IPs
            if ip_src in self.blacklist or ip_dst in self.blacklist:
                alerts.append(f"Blacklisted IP: {ip_src} -> {ip_dst}")
            
            # Check for suspicious ports
            if TCP in packet:
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                if sport in self.alert_ports or dport in self.alert_ports:
                    alerts.append(f"Suspicious port: {sport} -> {dport}")
                    
            elif UDP in packet:
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                if sport in self.alert_ports or dport in self.alert_ports:
                    alerts.append(f"Suspicious port: {sport} -> {dport}")
            
            # Check payload for suspicious patterns
            if packet.haslayer('Raw'):
                payload = bytes(packet['Raw'])
                for pattern in self.suspicious_patterns:
                    if pattern in payload:
                        alerts.append(f"Suspicious payload pattern: {pattern.decode()}")
        
        return alerts
    
    def packet_callback(self, packet):
        """Callback function for each captured packet"""
        if not self.running:
            return
            
        self.packet_count += 1
        
        # Basic packet info
        packet_info = {
            "timestamp": datetime.now().isoformat(),
            "packet_number": self.packet_count,
            "length": len(packet)
        }
        
        # Extract IP information
        if IP in packet:
            packet_info.update({
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "protocol": packet[IP].proto,
                "ttl": packet[IP].ttl
            })
            
            # Extract port information
            if TCP in packet:
                packet_info.update({
                    "src_port": packet[TCP].sport,
                    "dst_port": packet[TCP].dport,
                    "flags": str(packet[TCP].flags)
                })
            elif UDP in packet:
                packet_info.update({
                    "src_port": packet[UDP].sport,
                    "dst_port": packet[UDP].dport
                })
        
        # Analyze for suspicious activity
        alerts = self.analyze_packet(packet)
        if alerts:
            self.alert_count += 1
            packet_info["alerts"] = alerts
            self.print_alert(packet_info, alerts)
        
        # Log packet
        self.log_packet(packet_info)
        
        # Print packet summary every 10 packets
        if self.packet_count % 10 == 0:
            self.print_status()
    
    def print_alert(self, packet_info, alerts):
        """Print alert information"""
        print(f"\n{Fore.RED}[ALERT #{self.alert_count}] Suspicious Activity Detected!")
        print(f"{Fore.RED}Source: {packet_info.get('src_ip', 'N/A')}:{packet_info.get('src_port', 'N/A')}")
        print(f"{Fore.RED}Destination: {packet_info.get('dst_ip', 'N/A')}:{packet_info.get('dst_port', 'N/A')}")
        for alert in alerts:
            print(f"{Fore.RED}  - {alert}")
        print(f"{Fore.RED}Timestamp: {packet_info['timestamp']}")
        print("-" * 60)
    
    def print_status(self):
        """Print current status"""
        print(f"{Fore.CYAN}[STATUS] Packets: {self.packet_count} | Alerts: {self.alert_count} | Time: {datetime.now().strftime('%H:%M:%S')}")
    
    def log_packet(self, packet_info):
        """Log packet to JSON file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(packet_info) + '\n')
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Failed to log packet: {e}")
    
    def print_summary(self):
        """Print final summary"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}PySniff Session Summary")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}Total Packets Captured: {self.packet_count}")
        print(f"{Fore.GREEN}Total Alerts Generated: {self.alert_count}")
        print(f"{Fore.GREEN}Log File: {self.log_file}")
        print(f"{Fore.GREEN}Session Duration: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.GREEN}{'='*60}")
    
    def start_sniffing(self, interface=None, filter=None):
        """Start packet sniffing"""
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}PySniff - Python Packet Sniffer")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}Interface: {interface or 'Default'}")
        print(f"{Fore.GREEN}Filter: {filter or 'All packets'}")
        print(f"{Fore.GREEN}Blacklist: {len(self.blacklist)} IPs loaded")
        print(f"{Fore.GREEN}Alert Ports: {len(self.alert_ports)} ports monitored")
        print(f"{Fore.GREEN}Press Ctrl+C to stop")
        print(f"{Fore.GREEN}{'='*60}\n")
        
        try:
            # Force Layer 3 capture mode for Windows compatibility
            from scapy.all import conf
            conf.use_pcap = False
            
            print(f"{Fore.GREEN}[INFO] Using Layer 3 capture mode")
            print(f"{Fore.GREEN}[INFO] This mode captures IP packets without requiring WinPcap")
            
            # Use standard sniff with Layer 3 configuration
            sniff(
                prn=self.packet_callback,
                store=0,
                iface=interface,
                filter=filter
            )
        except KeyboardInterrupt:
            self.signal_handler(signal.SIGINT, None)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Packet capture failed: {e}")
            print(f"{Fore.YELLOW}[INFO] This usually means:")
            print(f"{Fore.YELLOW}  1. Run as Administrator")
            print(f"{Fore.YELLOW}  2. Install Npcap from: https://npcap.com/")
            print(f"{Fore.YELLOW}  3. Or use the web dashboard for network monitoring")
            self.running = False

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="PySniff - Python Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to sniff")
    parser.add_argument("-f", "--filter", help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    sniffer = PacketSniffer()
    sniffer.start_sniffing(interface=args.interface, filter=args.filter)

if __name__ == "__main__":
    main() 