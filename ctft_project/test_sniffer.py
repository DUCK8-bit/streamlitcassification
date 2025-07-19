#!/usr/bin/env python3
"""
Simple test script for the packet sniffer
"""

import time
import threading
from sniffing.packet_sniffer import PacketSniffer

def test_packet_sniffer():
    """Test the packet sniffer for 10 seconds"""
    print("Starting packet sniffer test...")
    
    # Create sniffer instance
    sniffer = PacketSniffer()
    
    # Start sniffing in a separate thread
    thread = threading.Thread(target=sniffer.start_sniffing)
    thread.daemon = True
    thread.start()
    
    # Let it run for 10 seconds
    print("Running for 10 seconds... Press Ctrl+C to stop early")
    try:
        time.sleep(10)
    except KeyboardInterrupt:
        print("\nStopping early...")
    
    # Stop the sniffer
    sniffer.running = False
    
    # Print summary
    sniffer.print_summary()
    
    print("Test completed!")

if __name__ == "__main__":
    test_packet_sniffer() 