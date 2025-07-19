#!/usr/bin/env python3
"""
Sample Executable for PyMal Testing
This is a harmless sample script that can be compiled to test the static analyzer
"""

import os
import sys
import socket
import subprocess
import time
from datetime import datetime

def harmless_function():
    """A harmless function that does nothing suspicious"""
    print("This is a harmless function")
    return "Hello, World!"

def simulate_benign_activity():
    """Simulate benign system activity"""
    print(f"Current time: {datetime.now()}")
    print(f"Current directory: {os.getcwd()}")
    print(f"Python version: {sys.version}")
    
    # Simulate some harmless operations
    try:
        # Get hostname (harmless)
        hostname = socket.gethostname()
        print(f"Hostname: {hostname}")
        
        # Get current user (harmless)
        if os.name == 'nt':  # Windows
            user = os.environ.get('USERNAME', 'Unknown')
        else:  # Unix/Linux
            user = os.environ.get('USER', 'Unknown')
        print(f"Current user: {user}")
        
        # List current directory (harmless)
        files = os.listdir('.')
        print(f"Files in current directory: {len(files)}")
        
    except Exception as e:
        print(f"Error during benign activity: {e}")

def main():
    """Main function - demonstrates harmless behavior"""
    print("=" * 50)
    print("Sample Executable for PyMal Testing")
    print("=" * 50)
    print("This is a harmless sample program for testing the static analyzer.")
    print("It demonstrates normal, non-malicious behavior patterns.")
    print("=" * 50)
    
    # Call harmless functions
    result = harmless_function()
    print(f"Function result: {result}")
    
    simulate_benign_activity()
    
    print("\n" + "=" * 50)
    print("Sample program completed successfully!")
    print("This program is safe and contains no malicious code.")
    print("=" * 50)

if __name__ == "__main__":
    main() 