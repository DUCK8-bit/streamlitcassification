#!/usr/bin/env python3
"""
PyMal Dynamic Analyzer: Process Behavior Monitor
Monitors running processes for suspicious behavior patterns
"""

import psutil
import time
import os
import json
import threading
import signal
import sys
from datetime import datetime
from colorama import init, Fore, Style
import argparse
import subprocess

# Initialize colorama for colored output
init(autoreset=True)

class DynamicAnalyzer:
    def __init__(self):
        self.monitored_processes = {}
        self.suspicious_behaviors = []
        self.running = True
        self.log_file = "analysis/malware_reports/dynamic_analysis.json"
        
        # Create reports directory
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Suspicious behavior patterns
        self.suspicious_ports = {4444, 23, 3389, 22, 80, 443, 8080, 9000}
        self.suspicious_files = {'.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs'}
        self.suspicious_paths = {'temp', 'tmp', 'downloads', 'desktop'}
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n{Fore.YELLOW}[*] Stopping dynamic analyzer...")
        self.running = False
        self.generate_final_report()
        sys.exit(0)
    
    def log_behavior(self, behavior_data):
        """Log behavior to JSON file"""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(behavior_data) + '\n')
        except Exception as e:
            print(f"{Fore.YELLOW}[WARNING] Failed to log behavior: {e}")
    
    def analyze_network_activity(self, process):
        """Analyze network connections for suspicious activity"""
        try:
            connections = process.connections()
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    behavior = {
                        "timestamp": datetime.now().isoformat(),
                        "pid": process.pid,
                        "process_name": process.name(),
                        "behavior_type": "network_connection",
                        "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                        "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        "status": conn.status
                    }
                    
                    # Check for suspicious ports
                    if conn.raddr and conn.raddr.port in self.suspicious_ports:
                        behavior["suspicious"] = True
                        behavior["alert"] = f"Suspicious port: {conn.raddr.port}"
                        print(f"{Fore.RED}[ALERT] Suspicious network activity: {process.name()} -> {conn.raddr.ip}:{conn.raddr.port}")
                    
                    self.log_behavior(behavior)
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def analyze_file_activity(self, process):
        """Analyze file operations for suspicious activity"""
        try:
            open_files = process.open_files()
            for file_info in open_files:
                file_path = file_info.path.lower()
                behavior = {
                    "timestamp": datetime.now().isoformat(),
                    "pid": process.pid,
                    "process_name": process.name(),
                    "behavior_type": "file_access",
                    "file_path": file_info.path,
                    "file_handle": file_info.fd
                }
                
                # Check for suspicious file types
                file_ext = os.path.splitext(file_path)[1]
                if file_ext in self.suspicious_files:
                    behavior["suspicious"] = True
                    behavior["alert"] = f"Suspicious file type: {file_ext}"
                    print(f"{Fore.RED}[ALERT] Suspicious file access: {process.name()} -> {file_info.path}")
                
                # Check for suspicious paths
                for suspicious_path in self.suspicious_paths:
                    if suspicious_path in file_path:
                        behavior["suspicious"] = True
                        behavior["alert"] = f"Suspicious path: {suspicious_path}"
                        print(f"{Fore.YELLOW}[WARNING] Suspicious path access: {process.name()} -> {file_info.path}")
                
                self.log_behavior(behavior)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def analyze_process_creation(self, process):
        """Analyze child processes for suspicious activity"""
        try:
            children = process.children(recursive=True)
            for child in children:
                behavior = {
                    "timestamp": datetime.now().isoformat(),
                    "parent_pid": process.pid,
                    "parent_name": process.name(),
                    "behavior_type": "process_creation",
                    "child_pid": child.pid,
                    "child_name": child.name(),
                    "child_cmdline": " ".join(child.cmdline()) if child.cmdline() else "N/A"
                }
                
                # Check for suspicious child processes
                suspicious_processes = {'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'}
                if child.name().lower() in suspicious_processes:
                    behavior["suspicious"] = True
                    behavior["alert"] = f"Suspicious child process: {child.name()}"
                    print(f"{Fore.RED}[ALERT] Suspicious process creation: {process.name()} -> {child.name()}")
                
                self.log_behavior(behavior)
                
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def analyze_memory_usage(self, process):
        """Analyze memory usage patterns"""
        try:
            memory_info = process.memory_info()
            behavior = {
                "timestamp": datetime.now().isoformat(),
                "pid": process.pid,
                "process_name": process.name(),
                "behavior_type": "memory_usage",
                "rss": memory_info.rss,
                "vms": memory_info.vms,
                "percent": process.memory_percent()
            }
            
            # Check for excessive memory usage
            if process.memory_percent() > 50:  # More than 50% of system memory
                behavior["suspicious"] = True
                behavior["alert"] = f"High memory usage: {process.memory_percent():.1f}%"
                print(f"{Fore.YELLOW}[WARNING] High memory usage: {process.name()} ({process.memory_percent():.1f}%)")
            
            self.log_behavior(behavior)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def analyze_cpu_usage(self, process):
        """Analyze CPU usage patterns"""
        try:
            cpu_percent = process.cpu_percent(interval=1)
            behavior = {
                "timestamp": datetime.now().isoformat(),
                "pid": process.pid,
                "process_name": process.name(),
                "behavior_type": "cpu_usage",
                "cpu_percent": cpu_percent
            }
            
            # Check for excessive CPU usage
            if cpu_percent > 80:  # More than 80% CPU usage
                behavior["suspicious"] = True
                behavior["alert"] = f"High CPU usage: {cpu_percent:.1f}%"
                print(f"{Fore.YELLOW}[WARNING] High CPU usage: {process.name()} ({cpu_percent:.1f}%)")
            
            self.log_behavior(behavior)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    
    def monitor_process(self, pid):
        """Monitor a specific process for suspicious behavior"""
        try:
            process = psutil.Process(pid)
            print(f"{Fore.GREEN}[+] Monitoring process: {process.name()} (PID: {pid})")
            
            while self.running:
                try:
                    # Check if process is still running
                    if not process.is_running():
                        print(f"{Fore.YELLOW}[!] Process {process.name()} (PID: {pid}) has terminated")
                        break
                    
                    # Analyze different aspects
                    self.analyze_network_activity(process)
                    self.analyze_file_activity(process)
                    self.analyze_process_creation(process)
                    self.analyze_memory_usage(process)
                    self.analyze_cpu_usage(process)
                    
                    time.sleep(2)  # Check every 2 seconds
                    
                except psutil.NoSuchProcess:
                    print(f"{Fore.YELLOW}[!] Process {pid} no longer exists")
                    break
                except psutil.AccessDenied:
                    print(f"{Fore.YELLOW}[!] Access denied to process {pid}")
                    break
                    
        except psutil.NoSuchProcess:
            print(f"{Fore.RED}[ERROR] Process {pid} not found")
        except psutil.AccessDenied:
            print(f"{Fore.RED}[ERROR] Access denied to process {pid}")
    
    def monitor_system_processes(self):
        """Monitor all system processes for suspicious activity"""
        print(f"{Fore.GREEN}[+] Monitoring all system processes...")
        
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                    try:
                        # Check for suspicious process names
                        suspicious_names = {'malware.exe', 'trojan.exe', 'backdoor.exe', 'keylogger.exe'}
                        if proc.info['name'].lower() in suspicious_names:
                            print(f"{Fore.RED}[ALERT] Suspicious process detected: {proc.info['name']} (PID: {proc.info['pid']})")
                        
                        # Check for suspicious command lines
                        if proc.info['cmdline']:
                            cmdline = ' '.join(proc.info['cmdline']).lower()
                            suspicious_patterns = ['powershell', 'cmd.exe', 'wget', 'curl', 'nc', 'netcat']
                            for pattern in suspicious_patterns:
                                if pattern in cmdline:
                                    print(f"{Fore.YELLOW}[WARNING] Suspicious command line: {proc.info['name']} -> {cmdline}")
                        
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                time.sleep(5)  # Check every 5 seconds
                
            except KeyboardInterrupt:
                break
    
    def run_sample_analysis(self, sample_path):
        """Run a sample file and monitor its behavior"""
        if not os.path.exists(sample_path):
            print(f"{Fore.RED}[ERROR] Sample file not found: {sample_path}")
            return
        
        print(f"{Fore.GREEN}[+] Running sample analysis: {sample_path}")
        
        try:
            # Start the sample process
            if sample_path.endswith('.py'):
                proc = subprocess.Popen(['python', sample_path], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE)
            else:
                proc = subprocess.Popen([sample_path], 
                                      stdout=subprocess.PIPE, 
                                      stderr=subprocess.PIPE)
            
            print(f"{Fore.GREEN}[+] Sample process started (PID: {proc.pid})")
            
            # Monitor the process
            self.monitor_process(proc.pid)
            
            # Wait for process to complete
            stdout, stderr = proc.communicate()
            
            if stdout:
                print(f"{Fore.CYAN}[STDOUT] {stdout.decode()}")
            if stderr:
                print(f"{Fore.YELLOW}[STDERR] {stderr.decode()}")
            
            print(f"{Fore.GREEN}[+] Sample analysis completed")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to run sample: {e}")
    
    def generate_final_report(self):
        """Generate final analysis report"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}Dynamic Analysis Summary")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}Log File: {self.log_file}")
        print(f"{Fore.GREEN}Analysis Duration: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.GREEN}{'='*60}")
    
    def start_monitoring(self, pid=None, sample_path=None, system_wide=False):
        """Start the monitoring process"""
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}PyMal Dynamic Analyzer")
        print(f"{Fore.GREEN}{'='*60}")
        print(f"{Fore.GREEN}Monitoring Mode: {'System-wide' if system_wide else 'Process-specific'}")
        if pid:
            print(f"{Fore.GREEN}Target PID: {pid}")
        if sample_path:
            print(f"{Fore.GREEN}Sample Path: {sample_path}")
        print(f"{Fore.GREEN}Press Ctrl+C to stop")
        print(f"{Fore.GREEN}{'='*60}\n")
        
        try:
            if sample_path:
                self.run_sample_analysis(sample_path)
            elif pid:
                self.monitor_process(pid)
            elif system_wide:
                self.monitor_system_processes()
            else:
                print(f"{Fore.RED}[ERROR] No monitoring target specified")
                
        except KeyboardInterrupt:
            self.signal_handler(signal.SIGINT, None)

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="PyMal Dynamic Analyzer")
    parser.add_argument("-p", "--pid", type=int, help="Process ID to monitor")
    parser.add_argument("-s", "--sample", help="Sample file to run and monitor")
    parser.add_argument("-w", "--system-wide", action="store_true", help="Monitor all system processes")
    
    args = parser.parse_args()
    
    analyzer = DynamicAnalyzer()
    analyzer.start_monitoring(pid=args.pid, sample_path=args.sample, system_wide=args.system_wide)

if __name__ == "__main__":
    main() 