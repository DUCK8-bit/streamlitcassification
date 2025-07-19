#!/usr/bin/env python3
"""
Static Malware Analyzer
Performs static analysis on executable files without requiring YARA
"""

import os
import hashlib
import pefile
import struct
from typing import Dict, List, Any, Optional
import json
from datetime import datetime

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("⚠️  YARA not available - signature scanning disabled")

class StaticAnalyzer:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.yara_rules = {}
        self.load_yara_rules()
    
    def load_yara_rules(self):
        """Load YARA rules if available"""
        if not YARA_AVAILABLE:
            print("⚠️  YARA not available - skipping rule loading")
            return
            
        if not os.path.exists(self.rules_dir):
            print(f"⚠️  Rules directory {self.rules_dir} not found")
            return
            
        try:
            for rule_file in os.listdir(self.rules_dir):
                if rule_file.endswith('.yar'):
                    rule_path = os.path.join(self.rules_dir, rule_file)
                    try:
                        self.yara_rules[rule_file] = yara.compile(rule_path)
                        print(f"✅ Loaded rule: {rule_file}")
                    except Exception as e:
                        print(f"❌ Failed to load rule {rule_file}: {e}")
        except Exception as e:
            print(f"❌ Error loading rules: {e}")
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """Perform static analysis on a file"""
        if not os.path.exists(file_path):
            return {"error": f"File not found: {file_path}"}
        
        results = {
            "file_path": file_path,
            "file_name": os.path.basename(file_path),
            "file_size": os.path.getsize(file_path),
            "analysis_time": datetime.now().isoformat(),
            "file_type": self._detect_file_type(file_path),
            "hashes": self._calculate_hashes(file_path),
            "pe_info": {},
            "suspicious_indicators": [],
            "yara_matches": [],
            "risk_score": 0
        }
        
        # PE file analysis
        if results["file_type"] == "PE":
            results["pe_info"] = self._analyze_pe_file(file_path)
            results["suspicious_indicators"] = self._check_suspicious_indicators(file_path, results["pe_info"])
        
        # YARA scanning (if available)
        if YARA_AVAILABLE and self.yara_rules:
            results["yara_matches"] = self._scan_with_yara(file_path)
        
        # Calculate risk score
        results["risk_score"] = self._calculate_risk_score(results)
        
        return results
    
    def _detect_file_type(self, file_path: str) -> str:
        """Detect file type based on magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
                
            if magic.startswith(b'MZ'):
                return "PE"
            elif magic.startswith(b'\x7fELF'):
                return "ELF"
            elif magic.startswith(b'\xfe\xed\xfa'):
                return "Mach-O"
            else:
                return "Unknown"
        except Exception:
            return "Unknown"
    
    def _calculate_hashes(self, file_path: str) -> Dict[str, str]:
        """Calculate various hashes of the file"""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            hashes["md5"] = hashlib.md5(data).hexdigest()
            hashes["sha1"] = hashlib.sha1(data).hexdigest()
            hashes["sha256"] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            hashes["error"] = str(e)
        
        return hashes
    
    def _analyze_pe_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze PE file structure"""
        pe_info = {}
        try:
            pe = pefile.PE(file_path)
            
            # Basic PE info
            pe_info["machine"] = hex(pe.FILE_HEADER.Machine)
            pe_info["timestamp"] = pe.FILE_HEADER.TimeDateStamp
            pe_info["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
            pe_info["subsystem"] = pe.OPTIONAL_HEADER.Subsystem
            pe_info["dll_characteristics"] = hex(pe.OPTIONAL_HEADER.DllCharacteristics)
            
            # Sections
            pe_info["sections"] = []
            for section in pe.sections:
                section_info = {
                    "name": section.Name.decode('utf-8').rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics)
                }
                pe_info["sections"].append(section_info)
            
            # Imports
            pe_info["imports"] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8')
                    functions = [func.name.decode('utf-8') if func.name else f"Ordinal_{func.ordinal}" 
                               for func in entry.imports]
                    pe_info["imports"].append({
                        "dll": dll_name,
                        "functions": functions
                    })
            
            # Exports
            pe_info["exports"] = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    pe_info["exports"].append(exp.name.decode('utf-8') if exp.name else f"Ordinal_{exp.ordinal}")
            
            pe.close()
            
        except Exception as e:
            pe_info["error"] = str(e)
        
        return pe_info
    
    def _check_suspicious_indicators(self, file_path: str, pe_info: Dict[str, Any]) -> List[str]:
        """Check for suspicious indicators in PE files"""
        indicators = []
        
        try:
            # Check for suspicious DLL imports
            suspicious_dlls = [
                "kernel32.dll", "user32.dll", "advapi32.dll", "ws2_32.dll",
                "ole32.dll", "oleaut32.dll", "shell32.dll", "urlmon.dll"
            ]
            
            suspicious_functions = [
                "CreateProcess", "CreateRemoteThread", "VirtualAllocEx",
                "WriteProcessMemory", "SetWindowsHookEx", "RegCreateKey",
                "InternetOpenUrl", "URLDownloadToFile", "ShellExecute"
            ]
            
            if "imports" in pe_info:
                for import_info in pe_info["imports"]:
                    dll = import_info["dll"].lower()
                    if dll in suspicious_dlls:
                        for func in import_info["functions"]:
                            if func in suspicious_functions:
                                indicators.append(f"Suspicious API: {func} from {dll}")
            
            # Check for packed/obfuscated indicators
            if "sections" in pe_info:
                section_names = [s["name"].lower() for s in pe_info["sections"]]
                if any(name in ["upx", "pack", "crypt", "protect"] for name in section_names):
                    indicators.append("Possible packing detected")
                
                # Check for unusual section characteristics
                for section in pe_info["sections"]:
                    if section["raw_size"] == 0 and section["virtual_size"] > 0:
                        indicators.append("Zero raw size section detected")
            
            # Check for suspicious characteristics
            if "dll_characteristics" in pe_info:
                chars = int(pe_info["dll_characteristics"], 16)
                if chars & 0x0040:  # DYNAMIC_BASE
                    indicators.append("ASLR enabled")
                if chars & 0x0100:  # NX_COMPAT
                    indicators.append("DEP enabled")
            
        except Exception as e:
            indicators.append(f"Error checking indicators: {e}")
        
        return indicators
    
    def _scan_with_yara(self, file_path: str) -> List[Dict[str, Any]]:
        """Scan file with YARA rules"""
        matches = []
        
        if not YARA_AVAILABLE:
            return matches
            
        try:
            for rule_name, rule in self.yara_rules.items():
                try:
                    rule_matches = rule.match(file_path)
                    for match in rule_matches:
                        matches.append({
                            "rule": rule_name,
                            "match": match.rule,
                            "strings": [str(s) for s in match.strings],
                            "tags": match.tags
                        })
                except Exception as e:
                    print(f"Error scanning with rule {rule_name}: {e}")
        except Exception as e:
            print(f"Error in YARA scanning: {e}")
        
        return matches
    
    def _calculate_risk_score(self, results: Dict[str, Any]) -> int:
        """Calculate risk score based on analysis results"""
        score = 0
        
        # Base score for PE files
        if results["file_type"] == "PE":
            score += 10
        
        # Suspicious indicators
        score += len(results["suspicious_indicators"]) * 15
        
        # YARA matches
        score += len(results["yara_matches"]) * 25
        
        # PE-specific checks
        if "pe_info" in results and "imports" in results["pe_info"]:
            suspicious_count = 0
            for import_info in results["pe_info"]["imports"]:
                if import_info["dll"].lower() in ["kernel32.dll", "user32.dll"]:
                    suspicious_count += len(import_info["functions"])
            score += min(suspicious_count * 2, 50)
        
        return min(score, 100)  # Cap at 100
    
    def generate_report(self, results: Dict[str, Any], output_file: str = None) -> str:
        """Generate a detailed analysis report"""
        report = []
        report.append("=" * 60)
        report.append("STATIC MALWARE ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"File: {results['file_name']}")
        report.append(f"Path: {results['file_path']}")
        report.append(f"Size: {results['file_size']:,} bytes")
        report.append(f"Type: {results['file_type']}")
        report.append(f"Analysis Time: {results['analysis_time']}")
        report.append(f"Risk Score: {results['risk_score']}/100")
        report.append("")
        
        # Hashes
        report.append("FILE HASHES:")
        report.append("-" * 20)
        for hash_type, hash_value in results["hashes"].items():
            if hash_type != "error":
                report.append(f"{hash_type.upper()}: {hash_value}")
        report.append("")
        
        # PE Information
        if results["file_type"] == "PE" and "pe_info" in results:
            pe_info = results["pe_info"]
            report.append("PE FILE INFORMATION:")
            report.append("-" * 20)
            report.append(f"Machine: {pe_info.get('machine', 'N/A')}")
            report.append(f"Subsystem: {pe_info.get('subsystem', 'N/A')}")
            report.append(f"Characteristics: {pe_info.get('characteristics', 'N/A')}")
            report.append("")
            
            # Sections
            if "sections" in pe_info:
                report.append("SECTIONS:")
                report.append("-" * 20)
                for section in pe_info["sections"]:
                    report.append(f"  {section['name']}: VA={section['virtual_address']}, "
                                f"Size={section['virtual_size']:,}")
                report.append("")
            
            # Imports
            if "imports" in pe_info:
                report.append("IMPORTS:")
                report.append("-" * 20)
                for import_info in pe_info["imports"]:
                    report.append(f"  {import_info['dll']}:")
                    for func in import_info["functions"][:5]:  # Show first 5 functions
                        report.append(f"    - {func}")
                    if len(import_info["functions"]) > 5:
                        report.append(f"    ... and {len(import_info['functions']) - 5} more")
                report.append("")
        
        # Suspicious Indicators
        if results["suspicious_indicators"]:
            report.append("SUSPICIOUS INDICATORS:")
            report.append("-" * 20)
            for indicator in results["suspicious_indicators"]:
                report.append(f"⚠️  {indicator}")
            report.append("")
        
        # YARA Matches
        if results["yara_matches"]:
            report.append("YARA RULE MATCHES:")
            report.append("-" * 20)
            for match in results["yara_matches"]:
                report.append(f"🔍 Rule: {match['rule']}")
                report.append(f"   Match: {match['match']}")
                if match["strings"]:
                    report.append(f"   Strings: {', '.join(match['strings'][:3])}")
                report.append("")
        
        # Risk Assessment
        report.append("RISK ASSESSMENT:")
        report.append("-" * 20)
        if results["risk_score"] >= 80:
            report.append("🔴 HIGH RISK - Strong indicators of malicious behavior")
        elif results["risk_score"] >= 50:
            report.append("🟡 MEDIUM RISK - Some suspicious indicators detected")
        elif results["risk_score"] >= 20:
            report.append("🟢 LOW RISK - Few suspicious indicators")
        else:
            report.append("🟢 VERY LOW RISK - No significant indicators detected")
        
        report_text = "\n".join(report)
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report_text)
                print(f"✅ Report saved to: {output_file}")
            except Exception as e:
                print(f"❌ Error saving report: {e}")
        
        return report_text

def main():
    """Main function for command-line usage"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python static_analyzer.py <file_path> [output_file]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    analyzer = StaticAnalyzer()
    results = analyzer.analyze_file(file_path)
    
    if "error" in results:
        print(f"❌ Error: {results['error']}")
        sys.exit(1)
    
    report = analyzer.generate_report(results, output_file)
    print(report)

if __name__ == "__main__":
    main() 