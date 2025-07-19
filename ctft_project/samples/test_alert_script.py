#!/usr/bin/env python3
"""
Test script to trigger dynamic analyzer alerts
This script performs various activities that should trigger alerts
"""

import os
import time
import subprocess
import socket
import threading

def test_suspicious_commands():
    """Test suspicious command line patterns"""
    print("Testing suspicious command patterns...")
    
    # These should trigger alerts in the dynamic analyzer
    suspicious_commands = [
        "powershell.exe -Command 'Get-Process'",
        "cmd.exe /c dir",
        "wget http://example.com",
        "curl -O http://example.com/file",
        "nc -l 4444",
        "netcat -l 4444"
    ]
    
    for cmd in suspicious_commands:
        print(f"Running: {cmd}")
        try:
            # Just print the command, don't actually execute
            print(f"  [SIMULATED] Would execute: {cmd}")
        except Exception as e:
            print(f"  Error: {e}")
        time.sleep(1)

def test_high_cpu_usage():
    """Test high CPU usage to trigger alerts"""
    print("Testing high CPU usage...")
    
    # Simulate CPU-intensive work
    for i in range(1000000):
        _ = i * i
        if i % 100000 == 0:
            print(f"CPU test iteration: {i}")

def test_network_activity():
    """Test network connections to suspicious ports"""
    print("Testing network activity...")
    
    # Try to connect to suspicious ports (this will fail but should be detected)
    suspicious_ports = [4444, 23, 3389, 22, 8080]
    
    for port in suspicious_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            print(f"Connection test to port {port}: {'SUCCESS' if result == 0 else 'FAILED'}")
            sock.close()
        except Exception as e:
            print(f"Network test error for port {port}: {e}")

def test_file_operations():
    """Test file operations in suspicious locations"""
    print("Testing file operations...")
    
    suspicious_paths = [
        os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'test.exe'),
        os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'test.dll'),
        os.path.join(os.environ.get('TEMP', 'C:\\temp'), 'test.bat')
    ]
    
    for file_path in suspicious_paths:
        try:
            with open(file_path, 'w') as f:
                f.write("Test content for alert detection")
            print(f"Created test file: {file_path}")
            
            # Clean up
            os.remove(file_path)
            print(f"Removed test file: {file_path}")
        except Exception as e:
            print(f"File operation error: {e}")

def main():
    """Main test function"""
    print("🚨 Starting Alert Test Script")
    print("=" * 50)
    
    # Run tests in sequence
    test_suspicious_commands()
    test_high_cpu_usage()
    test_network_activity()
    test_file_operations()
    
    print("=" * 50)
    print("✅ Alert test script completed")
    print("Check the dynamic analyzer for triggered alerts!")

if __name__ == "__main__":
    main() 