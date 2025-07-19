#!/usr/bin/env python3
"""
PySniff & PyMal Demo Script
Demonstrates the functionality of the CTFT project
"""

import sys
import os
import time
import subprocess
import threading
from pathlib import Path

def check_package(package_name):
    """Check if a package is available"""
    try:
        __import__(package_name)
        return True
    except ImportError:
        return False

def print_status(package, status, message=""):
    """Print package status with emoji"""
    if status:
        print(f"✅ {package}")
    else:
        print(f"❌ {package} - {message}")

def check_dependencies():
    """Check all required dependencies"""
    print("=" * 80)
    print("🔍 CHECKING DEPENDENCIES")
    print("=" * 80)
    
    packages = [
        ("scapy", "Packet capture and manipulation"),
        ("psutil", "System and process monitoring"),
        ("pefile", "PE file analysis"),
        ("streamlit", "Web dashboard"),
        ("pandas", "Data analysis"),
        ("matplotlib", "Data visualization"),
        ("colorama", "Terminal colors"),
        ("rich", "Rich terminal output")
    ]
    
    missing_packages = []
    
    for package, description in packages:
        if check_package(package):
            print_status(package, True)
        else:
            print_status(package, False, description)
            missing_packages.append(package)
    
    # Special handling for YARA
    if check_package("yara"):
        print_status("yara", True)
    else:
        print_status("yara", False, "Signature scanning disabled - will use fallback analysis")
    
    print()
    
    if missing_packages:
        print(f"❌ Missing packages: {', '.join(missing_packages)}")
        print("Please install missing packages with: pip install -r requirements.txt")
        return False
    else:
        print("✅ All core packages available!")
        return True

def run_packet_sniffer_demo():
    """Demonstrate packet sniffer functionality"""
    print("\n" + "=" * 80)
    print("📡 PACKET SNIFFER DEMO")
    print("=" * 80)
    
    try:
        from sniffing.packet_sniffer import PacketSniffer
        
        print("🚀 Starting packet sniffer demo...")
        print("📝 This will capture packets for 10 seconds")
        print("⚠️  Note: This requires administrator privileges on Windows")
        print()
        
        sniffer = PacketSniffer()
        
        # Start sniffing in a separate thread
        def sniff_packets():
            try:
                sniffer.start_sniffing()
            except PermissionError:
                print("❌ Permission denied. Run as administrator for packet capture.")
            except Exception as e:
                print(f"❌ Error during packet capture: {e}")
        
        thread = threading.Thread(target=sniff_packets)
        thread.daemon = True
        thread.start()
        
        # Wait for 10 seconds then stop
        time.sleep(10)
        sniffer.running = False
        
        print(f"✅ Packet sniffer demo completed!")
        print(f"📊 Captured {sniffer.packet_count} packets")
        print(f"🚨 Generated {sniffer.alert_count} alerts")
            
    except ImportError as e:
        print(f"❌ Error importing packet sniffer: {e}")
    except Exception as e:
        print(f"❌ Error in packet sniffer demo: {e}")

def run_static_analyzer_demo():
    """Demonstrate static analyzer functionality"""
    print("\n" + "=" * 80)
    print("🔍 STATIC ANALYZER DEMO")
    print("=" * 80)
    
    try:
        from analysis.static_analyzer import StaticAnalyzer
        
        print("🚀 Starting static analyzer demo...")
        
        # Create a sample file for analysis
        sample_file = "sample_analysis.exe"
        sample_content = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00\x00\x00\x00\x00@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00\x0e\x1f\xba\x0e\x00\xb4\t\xcd!\xb8\x01L\xcd!This program cannot be run in DOS mode.\r\r\n$\x00\x00\x00\x00\x00\x00\x00'
        
        with open(sample_file, 'wb') as f:
            f.write(sample_content)
        
        analyzer = StaticAnalyzer()
        results = analyzer.analyze_file(sample_file)
        
        if "error" not in results:
            print("✅ Static analysis completed successfully!")
            print(f"📁 File: {results['file_name']}")
            print(f"📏 Size: {results['file_size']:,} bytes")
            print(f"🏷️  Type: {results['file_type']}")
            print(f"⚠️  Risk Score: {results['risk_score']}/100")
            
            if results.get('suspicious_indicators'):
                print("🚨 Suspicious indicators found:")
                for indicator in results['suspicious_indicators'][:3]:
                    print(f"  - {indicator}")
            
            # Clean up
            os.remove(sample_file)
        else:
            print(f"❌ Analysis failed: {results['error']}")
            
    except ImportError as e:
        print(f"❌ Error importing static analyzer: {e}")
    except Exception as e:
        print(f"❌ Error in static analyzer demo: {e}")

def run_dynamic_analyzer_demo():
    """Demonstrate dynamic analyzer functionality"""
    print("\n" + "=" * 80)
    print("⚡ DYNAMIC ANALYZER DEMO")
    print("=" * 80)
    
    try:
        from analysis.dynamic_analyzer import DynamicAnalyzer
        
        print("🚀 Starting dynamic analyzer demo...")
        print("📝 This will monitor system activity for 5 seconds")
        
        analyzer = DynamicAnalyzer()
        
        # Start monitoring in a separate thread
        def monitor_system():
            try:
                analyzer.start_monitoring(system_wide=True)
            except Exception as e:
                print(f"❌ Error during system monitoring: {e}")
        
        thread = threading.Thread(target=monitor_system)
        thread.daemon = True
        thread.start()
        
        # Wait for 5 seconds then stop
        time.sleep(5)
        analyzer.running = False
        
        print(f"✅ Dynamic analyzer demo completed!")
        print("📊 System monitoring results saved to analysis/malware_reports/dynamic_analysis.json")
            
    except ImportError as e:
        print(f"❌ Error importing dynamic analyzer: {e}")
    except Exception as e:
        print(f"❌ Error in dynamic analyzer demo: {e}")

def run_dashboard_demo():
    """Demonstrate dashboard functionality"""
    print("\n" + "=" * 80)
    print("🌐 DASHBOARD DEMO")
    print("=" * 80)
    
    try:
        print("🚀 Starting dashboard demo...")
        print("📝 This will start the web dashboard")
        print("🌐 Dashboard will be available at: http://localhost:8501")
        print("⚠️  Press Ctrl+C to stop the dashboard")
        print()
        
        # Check if streamlit is available
        if not check_package("streamlit"):
            print("❌ Streamlit not available - skipping dashboard demo")
            return
        
        # Start dashboard in a separate process
        try:
            process = subprocess.Popen(
                [sys.executable, "-m", "streamlit", "run", "dashboard/app.py", "--server.port", "8501"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            print("✅ Dashboard started successfully!")
            print("🌐 Open your browser and navigate to: http://localhost:8501")
            print("⏳ Dashboard will run for 30 seconds...")
            
            # Wait for 30 seconds
            time.sleep(30)
            
            # Stop the dashboard
            process.terminate()
            process.wait(timeout=5)
            print("✅ Dashboard stopped")
            
        except subprocess.TimeoutExpired:
            process.kill()
            print("⚠️  Dashboard process terminated forcefully")
        except Exception as e:
            print(f"❌ Error starting dashboard: {e}")
            
    except Exception as e:
        print(f"❌ Error in dashboard demo: {e}")

def main():
    """Main demo function"""
    print("🚀 PySniff & PyMal - CTFT Project Demo")
    print("=" * 80)
    
    # Check dependencies first
    if not check_dependencies():
        print("\n❌ Some dependencies are missing. Please install them first.")
        return
    
    print("\n✅ All dependencies available! Starting demos...")
    
    # Run demos
    try:
        run_packet_sniffer_demo()
        time.sleep(2)
        
        run_static_analyzer_demo()
        time.sleep(2)
        
        run_dynamic_analyzer_demo()
        time.sleep(2)
        
        run_dashboard_demo()
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo error: {e}")
    
    print("\n" + "=" * 80)
    print("🎉 Demo completed!")
    print("=" * 80)
    print("📚 For more information, see:")
    print("  - README.md - Project overview")
    print("  - docs/user_manual.md - Detailed usage guide")
    print("  - docs/project_summary.md - Technical details")
    print()
    print("🔧 To run individual components:")
    print("  - Packet Sniffer: python sniffing/packet_sniffer.py")
    print("  - Static Analyzer: python analysis/static_analyzer.py <file>")
    print("  - Dynamic Analyzer: python analysis/dynamic_analyzer.py")
    print("  - Dashboard: streamlit run dashboard/app.py")

if __name__ == "__main__":
    main() 