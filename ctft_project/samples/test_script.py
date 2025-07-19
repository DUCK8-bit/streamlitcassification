#!/usr/bin/env python3
"""
Test Script for PyMal Dynamic Analyzer
This script demonstrates various suspicious behaviors for testing purposes
"""

import socket
import time
import os
import subprocess
import sys
import threading

def simulate_network_activity():
    """Simulate suspicious network connections"""
    print("[TEST] Simulating network activity...")
    
    # Try to connect to suspicious ports
    suspicious_ports = [4444, 9000, 8080]
    for port in suspicious_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect(('127.0.0.1', port))
            print(f"[TEST] Connected to localhost:{port}")
            sock.close()
        except:
            print(f"[TEST] Failed to connect to localhost:{port}")
    
    # Simulate HTTP request
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect(('httpbin.org', 80))
        request = "GET / HTTP/1.1\r\nHost: httpbin.org\r\n\r\n"
        sock.send(request.encode())
        response = sock.recv(1024)
        print(f"[TEST] HTTP request sent, received {len(response)} bytes")
        sock.close()
    except Exception as e:
        print(f"[TEST] HTTP request failed: {e}")

def simulate_file_operations():
    """Simulate suspicious file operations"""
    print("[TEST] Simulating file operations...")
    
    # Create files in suspicious locations
    suspicious_files = [
        "temp_malware.exe",
        "backdoor.dll",
        "keylogger.bat",
        "payload.ps1"
    ]
    
    for filename in suspicious_files:
        try:
            with open(filename, 'w') as f:
                f.write(f"# Fake malware file: {filename}\n")
                f.write("# This is just a test file for dynamic analysis\n")
            print(f"[TEST] Created file: {filename}")
        except Exception as e:
            print(f"[TEST] Failed to create {filename}: {e}")
    
    # Read system files (suspicious behavior)
    system_files = [
        "/etc/passwd",  # Unix
        "C:\\Windows\\System32\\drivers\\etc\\hosts",  # Windows
        "/proc/version"  # Linux
    ]
    
    for filepath in system_files:
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r') as f:
                    content = f.read(100)  # Read first 100 chars
                print(f"[TEST] Read system file: {filepath}")
            except Exception as e:
                print(f"[TEST] Failed to read {filepath}: {e}")

def simulate_process_creation():
    """Simulate suspicious process creation"""
    print("[TEST] Simulating process creation...")
    
    # Try to create child processes
    commands = [
        ["echo", "Hello from child process"],
        ["whoami"],
        ["hostname"],
        ["dir"] if os.name == 'nt' else ["ls"]
    ]
    
    for cmd in commands:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            print(f"[TEST] Executed: {' '.join(cmd)}")
            if result.stdout:
                print(f"[TEST] Output: {result.stdout.strip()}")
        except Exception as e:
            print(f"[TEST] Failed to execute {' '.join(cmd)}: {e}")

def simulate_memory_operations():
    """Simulate memory-intensive operations"""
    print("[TEST] Simulating memory operations...")
    
    # Allocate large amounts of memory
    try:
        large_data = []
        for i in range(1000):
            large_data.append("X" * 1000)  # 1MB of data
        print("[TEST] Allocated ~1MB of memory")
        time.sleep(1)
        del large_data  # Clean up
    except Exception as e:
        print(f"[TEST] Memory allocation failed: {e}")

def simulate_cpu_intensive_work():
    """Simulate CPU-intensive operations"""
    print("[TEST] Simulating CPU-intensive work...")
    
    # Perform CPU-intensive calculations
    start_time = time.time()
    for i in range(1000000):
        _ = i * i  # Simple calculation
    end_time = time.time()
    print(f"[TEST] CPU-intensive work completed in {end_time - start_time:.2f} seconds")

def simulate_suspicious_strings():
    """Simulate suspicious strings in memory"""
    print("[TEST] Simulating suspicious strings...")
    
    suspicious_strings = [
        "cmd.exe",
        "powershell",
        "wget",
        "curl",
        "nc",
        "netcat",
        "reverse shell",
        "backdoor",
        "trojan",
        "keylogger",
        "spyware",
        "malware",
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory"
    ]
    
    # Store suspicious strings in memory
    stored_strings = []
    for s in suspicious_strings:
        stored_strings.append(s)
        print(f"[TEST] Stored suspicious string: {s}")
    
    return stored_strings  # Keep in memory

def main():
    """Main test function"""
    print("=" * 60)
    print("PyMal Dynamic Analysis Test Script")
    print("=" * 60)
    print("This script demonstrates various suspicious behaviors")
    print("for testing the dynamic analyzer.")
    print("=" * 60)
    
    # Run different tests
    tests = [
        ("Network Activity", simulate_network_activity),
        ("File Operations", simulate_file_operations),
        ("Process Creation", simulate_process_creation),
        ("Memory Operations", simulate_memory_operations),
        ("CPU Intensive Work", simulate_cpu_intensive_work),
        ("Suspicious Strings", simulate_suspicious_strings)
    ]
    
    for test_name, test_func in tests:
        print(f"\n[TEST] Running: {test_name}")
        try:
            test_func()
            time.sleep(1)  # Brief pause between tests
        except Exception as e:
            print(f"[TEST] Test {test_name} failed: {e}")
    
    print("\n" + "=" * 60)
    print("Test script completed!")
    print("Check the dynamic analyzer output for detected behaviors.")
    print("=" * 60)

if __name__ == "__main__":
    main() 