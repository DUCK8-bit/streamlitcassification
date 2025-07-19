#!/usr/bin/env python3
"""
PyMal Static Analyzer: PE File Analysis Tool
Analyzes executable files for malware indicators
"""

import pefile
import sys
import os
import json
import hashlib
from datetime import datetime
from colorama import init, Fore, Style
import argparse

# Try to import yara, but don't fail if it's not available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print(f"{Fore.YELLOW}[!] YARA not available - signature scanning disabled")

# Initialize colorama for colored output
init(autoreset=True)

class StaticAnalyzer:
    def __init__(self):
        self.suspicious_imports = {
            'kernel32.dll': [
                'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
                'OpenProcess', 'CreateProcess', 'TerminateProcess',
                'GetProcAddress', 'LoadLibrary', 'FreeLibrary'
            ],
            'advapi32.dll': [
                'RegCreateKey', 'RegSetValue', 'RegDeleteKey',
                'CreateService', 'StartService', 'OpenService'
            ],
            'ws2_32.dll': [
                'connect', 'send', 'recv', 'socket', 'bind', 'listen'
            ],
            'urlmon.dll': [
                'URLDownloadToFile', 'URLDownloadToCacheFile'
            ],
            'wininet.dll': [
                'InternetOpen', 'InternetConnect', 'HttpOpenRequest',
                'HttpSendRequest', 'InternetReadFile'
            ]
        }
        
        self.suspicious_sections = [
            '.text', '.data', '.rdata', '.idata', '.edata', '.pdata', '.reloc'
        ]
        
        self.yara_rules = None
        self.load_yara_rules()
        
    def load_yara_rules(self):
        """Load YARA rules from file"""
        if not YARA_AVAILABLE:
            print(f"{Fore.YELLOW}[!] YARA not available - signature scanning disabled")
            return
            
        try:
            rules_file = "analysis/yara_rules.yar"
            if os.path.exists(rules_file):
                try:
                    self.yara_rules = yara.compile(rules_file)
                    print(f"{Fore.GREEN}[+] Loaded YARA rules from {rules_file}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Failed to load YARA rules: {e}")
            else:
                print(f"{Fore.YELLOW}[!] YARA rules file not found: {rules_file}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to load YARA rules: {e}")
    
    def calculate_hashes(self, filepath):
        """Calculate MD5, SHA1, and SHA256 hashes"""
        hashes = {}
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
                hashes['md5'] = hashlib.md5(data).hexdigest()
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to calculate hashes: {e}")
        return hashes
    
    def analyze_pe_header(self, pe):
        """Analyze PE header information"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}PE Header Analysis")
        print(f"{Fore.CYAN}{'='*60}")
        
        # Basic file info
        print(f"{Fore.WHITE}Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"{Fore.WHITE}Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"{Fore.WHITE}Time Date Stamp: {datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)}")
        print(f"{Fore.WHITE}Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
        
        # Optional header info
        print(f"{Fore.WHITE}Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"{Fore.WHITE}Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"{Fore.WHITE}Size of Image: {pe.OPTIONAL_HEADER.SizeOfImage}")
        print(f"{Fore.WHITE}Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
        
        # Check for suspicious characteristics
        if pe.FILE_HEADER.Characteristics & 0x2000:  # DLL
            print(f"{Fore.YELLOW}[!] File is a DLL")
        if pe.FILE_HEADER.Characteristics & 0x0002:  # Executable
            print(f"{Fore.GREEN}[+] File is executable")
    
    def analyze_sections(self, pe):
        """Analyze PE sections"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Section Analysis")
        print(f"{Fore.CYAN}{'='*60}")
        
        suspicious_sections = []
        
        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            print(f"{Fore.WHITE}Section: {section_name}")
            print(f"  Virtual Address: {hex(section.VirtualAddress)}")
            print(f"  Virtual Size: {section.Misc_VirtualSize}")
            print(f"  Raw Size: {section.SizeOfRawData}")
            print(f"  Characteristics: {hex(section.Characteristics)}")
            
            # Check for suspicious section characteristics
            if section.Characteristics & 0xE0000000:  # Executable
                print(f"  {Fore.YELLOW}[!] Section is executable")
                if section_name not in ['.text']:
                    suspicious_sections.append(section_name)
            
            if section.Characteristics & 0x80000000:  # Writable
                print(f"  {Fore.YELLOW}[!] Section is writable")
                if section_name not in ['.data', '.bss']:
                    suspicious_sections.append(section_name)
            
            print()
        
        if suspicious_sections:
            print(f"{Fore.RED}[ALERT] Suspicious sections detected: {suspicious_sections}")
    
    def analyze_imports(self, pe):
        """Analyze imported functions"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Import Analysis")
        print(f"{Fore.CYAN}{'='*60}")
        
        suspicious_imports = []
        
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                print(f"{Fore.WHITE}DLL: {dll_name}")
                
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode()
                        print(f"  - {func_name}")
                        
                        # Check for suspicious imports
                        if dll_name.lower() in self.suspicious_imports:
                            if func_name in self.suspicious_imports[dll_name.lower()]:
                                print(f"    {Fore.RED}[SUSPICIOUS] {func_name}")
                                suspicious_imports.append(f"{dll_name}.{func_name}")
                
                print()
        except AttributeError:
            print(f"{Fore.YELLOW}[!] No import directory found")
        
        if suspicious_imports:
            print(f"{Fore.RED}[ALERT] Suspicious imports detected:")
            for imp in suspicious_imports:
                print(f"{Fore.RED}  - {imp}")
    
    def analyze_exports(self, pe):
        """Analyze exported functions"""
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}Export Analysis")
        print(f"{Fore.CYAN}{'='*60}")
        
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    print(f"{Fore.WHITE}Export: {exp.name.decode()}")
        except AttributeError:
            print(f"{Fore.YELLOW}[!] No export directory found")
    
    def run_yara_scan(self, filepath):
        """Run YARA rules against the file"""
        if not YARA_AVAILABLE:
            print(f"{Fore.YELLOW}[!] YARA not available - signature scanning skipped")
            return
            
        if not self.yara_rules:
            print(f"{Fore.YELLOW}[!] No YARA rules loaded - signature scanning skipped")
            return
        
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.CYAN}YARA Rule Scan")
        print(f"{Fore.CYAN}{'='*60}")
        
        try:
            matches = self.yara_rules.match(filepath)
            if matches:
                print(f"{Fore.RED}[ALERT] YARA rules matched:")
                matched_rules = []
                for match in matches:
                    print(f"{Fore.RED}  Rule: {match.rule}")
                    matched_rules.append(match.rule)
                    for string in match.strings:
                        # string is a tuple: (offset, identifier, value)
                        value = string[2]
                        if isinstance(value, bytes):
                            try:
                                value = value.decode(errors='replace')
                            except Exception:
                                value = str(value)
                        print(f"{Fore.RED}    String: {value}")
                # Save matched rules for report export
                self.last_yara_matched_rules = matched_rules
            else:
                print(f"{Fore.GREEN}[+] No YARA rule matches found")
                self.last_yara_matched_rules = []
        except Exception as e:
            print(f"{Fore.YELLOW}[!] YARA scan failed: {e}")
    
    def analyze_file(self, filepath):
        """Main analysis function"""
        try:
            if not os.path.exists(filepath):
                print(f"{Fore.RED}[ERROR] File not found: {filepath}")
                return None
            
            print(f"{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}PyMal Static Analyzer")
            print(f"{Fore.GREEN}{'='*60}")
            print(f"{Fore.GREEN}File: {filepath}")
            print(f"{Fore.GREEN}Size: {os.path.getsize(filepath)} bytes")
            print(f"{Fore.GREEN}Analysis Time: {datetime.now()}")
            print(f"{Fore.GREEN}{'='*60}\n")
            
            # Calculate hashes
            hashes = self.calculate_hashes(filepath)
            print(f"{Fore.CYAN}File Hashes:")
            print(f"{Fore.WHITE}MD5: {hashes.get('md5', 'N/A')}")
            print(f"{Fore.WHITE}SHA1: {hashes.get('sha1', 'N/A')}")
            print(f"{Fore.WHITE}SHA256: {hashes.get('sha256', 'N/A')}\n")
            
            try:
                pe = pefile.PE(filepath)
                
                # Run analysis
                self.analyze_pe_header(pe)
                self.analyze_sections(pe)
                self.analyze_imports(pe)
                self.analyze_exports(pe)
                self.run_yara_scan(filepath)
                
                # Generate report
                report = self.generate_report(filepath, pe, hashes)
                return report
                
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to analyze PE file: {e}")
                print(f"{Fore.YELLOW}[!] File might not be a valid PE file")
                return None
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Analysis failed: {e}")
            return None
    
    def generate_report(self, filepath, pe, hashes):
        """Generate analysis report"""
        try:
            report_file = f"analysis/malware_reports/static_analysis_{os.path.basename(filepath)}.json"
            os.makedirs(os.path.dirname(report_file), exist_ok=True)
            # Add YARA matches if available
            yara_matches = getattr(self, 'last_yara_matched_rules', [])
            report = {
                "file_info": {
                    "path": filepath,
                    "size": os.path.getsize(filepath),
                    "hashes": hashes,
                    "analysis_time": datetime.now().isoformat()
                },
                "pe_info": {
                    "machine": hex(pe.FILE_HEADER.Machine),
                    "sections": pe.FILE_HEADER.NumberOfSections,
                    "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                    "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                    "subsystem": pe.OPTIONAL_HEADER.Subsystem
                },
                "yara_matches": yara_matches
            }
            with open(report_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n{Fore.GREEN}[+] Analysis report saved: {report_file}")
            return report
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to save report: {e}")
            return None

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="PyMal Static Analyzer")
    parser.add_argument("file", help="PE file to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    analyzer = StaticAnalyzer()
    analyzer.analyze_file(args.file)

if __name__ == "__main__":
    main() 