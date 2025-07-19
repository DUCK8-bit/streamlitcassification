#!/usr/bin/env python3
from colorama import Fore, Style
import ctypes
import os
import socket

def main():
    print(Fore.RED + "This is a malicious sample!" + Style.RESET_ALL)
    # Suspicious API usage
    ctypes.windll.kernel32.CreateRemoteThread
    os.system('powershell -Command "Start-Process notepad"')
    # Suspicious strings
    suspicious = [
        "cmd.exe", "powershell", "reverse shell", "keylogger", "backdoor", "malware"
    ]
    for s in suspicious:
        if "shell" in s:
            print("Suspicious string detected:", s)
    # Network activity
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 4444))
        s.close()
    except Exception:
        pass

if __name__ == "__main__":
    main() 