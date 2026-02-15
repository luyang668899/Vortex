#!/usr/bin/env python3
# SecurityScanner.py
#
# A comprehensive security vulnerability scanner
#
# Author: Your Name
# Date: 2024

import os
import sys
import json
from collections import defaultdict, Counter

# Ghidra imports
try:
    from ghidra.app.decompiler import DecompInterface
    from ghidra.app.script import GhidraScript
    from ghidra.program.model.listing import Function, Variable
    from ghidra.program.model.symbol import Symbol, SourceType
    from ghidra.util.task import TaskMonitor
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.mem import MemoryAccessException
except ImportError:
    # Handle import errors when running outside Ghidra
    pass

class SecurityScanner(GhidraScript):
    def __init__(self):
        super().__init__()
        self.vulnerabilities = []
        self.decomp_interface = None
        self.security_patterns = {
            'buffer_overflow': {
                'patterns': ['gets(', 'strcpy(', 'strcat(', 'sprintf(', 'vsprintf(', 'memcpy(', 'memmove('],
                'description': 'Potential buffer overflow vulnerability',
                'severity': 'high'
            },
            'format_string': {
                'patterns': ['printf(', 'fprintf(', 'sprintf(', 'snprintf(', 'vprintf(', 'vfprintf(', 'vsprintf(', 'vsnprintf('],
                'description': 'Potential format string vulnerability',
                'severity': 'high'
            },
            'integer_overflow': {
                'patterns': ['+', '-', '*', '/', '++', '--'],
                'description': 'Potential integer overflow vulnerability',
                'severity': 'medium'
            },
            'use_after_free': {
                'patterns': ['free(', 'delete', 'delete[]'],
                'description': 'Potential use-after-free vulnerability',
                'severity': 'high'
            },
            'double_free': {
                'patterns': ['free(', 'delete', 'delete[]'],
                'description': 'Potential double free vulnerability',
                'severity': 'high'
            },
            'null_pointer': {
                'patterns': ['*', '->'],
                'description': 'Potential null pointer dereference',
                'severity': 'medium'
            },
            'command_injection': {
                'patterns': ['system(', 'exec(', 'popen(', 'fork(', 'spawn('],
                'description': 'Potential command injection vulnerability',
                'severity': 'high'
            },
            'sql_injection': {
                'patterns': ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE'],
                'description': 'Potential SQL injection vulnerability',
                'severity': 'high'
            },
            'hardcoded_secrets': {
                'patterns': ['password', 'secret', 'key', 'token', 'credential'],
                'description': 'Potential hardcoded secret',
                'severity': 'high'
            },
            'uninitialized_variables': {
                'patterns': ['int ', 'char ', 'void ', 'float ', 'double ', 'long '],
                'description': 'Potential uninitialized variable',
                'severity': 'medium'
            }
        }
    
    def run(self):
        """Main script entry point"""
        self.scan_for_vulnerabilities()
        self.show_results()
    
    def scan_for_vulnerabilities(self):
        """Scan the program for security vulnerabilities"""
        self.clear_results()
        
        # Initialize decompiler interface
        self.decomp_interface = DecompInterface()
        self.decomp_interface.openProgram(currentProgram())
        
        # Get all functions in the program
        function_manager = currentProgram().getFunctionManager()
        functions = list(function_manager.getFunctions(True))
        
        self.monitor.initialize(len(functions))
        self.monitor.setMessage("Scanning for security vulnerabilities...")
        
        for i, func in enumerate(functions):
            if self.monitor.isCancelled():
                break
                
            self.monitor.setProgress(i)
            self.monitor.setMessage(f"Scanning function: {func.getName()}")
            
            # Scan function for vulnerabilities
            self.scan_function(func)
        
        # Clean up
        if self.decomp_interface:
            self.decomp_interface.dispose()
    
    def scan_function(self, func):
        """Scan a single function for vulnerabilities"""
        try:
            # Scan assembly instructions
            self.scan_assembly_instructions(func)
            
            # Scan decompiled code
            self.scan_decompiled_code(func)
        except Exception as e:
            self.log(f"Error scanning function {func.getName()}: {str(e)}")
    
    def scan_assembly_instructions(self, func):
        """Scan assembly instructions for vulnerabilities"""
        try:
            # Get function body
            body = func.getBody()
            if body is None:
                return
                
            # Get instruction iterator
            listing = currentProgram().getListing()
            instructions = listing.getInstructions(body, True)
            
            for instr in instructions:
                instr_str = instr.toString()
                address = instr.getAddress()
                
                # Check for potential vulnerabilities in assembly
                if 'call' in instr_str.lower():
                    # Check for calls to dangerous functions
                    if any(func_name in instr_str for func_name in ['gets', 'strcpy', 'strcat', 'sprintf', 'system']):
                        self.vulnerabilities.append({
                            'function': func.getName(),
                            'address': address,
                            'type': 'dangerous_function_call',
                            'description': f"Call to dangerous function: {instr_str}",
                            'severity': 'high',
                            'context': instr_str
                        })
        except Exception as e:
            self.log(f"Error scanning assembly instructions in {func.getName()}: {str(e)}")
    
    def scan_decompiled_code(self, func):
        """Scan decompiled code for vulnerabilities"""
        try:
            # Decompile the function
            results = self.decomp_interface.decompileFunction(func, 30, self.monitor)
            if not results.decompileCompleted():
                return
                
            # Get the decompiled code as a string
            decompiled_code = results.getDecompiledFunction().getC()
            
            # Check for each security pattern
            for vuln_type, pattern_info in self.security_patterns.items():
                for pattern in pattern_info['patterns']:
                    start_idx = 0
                    while True:
                        idx = decompiled_code.find(pattern, start_idx)
                        if idx == -1:
                            break
                            
                        # Extract context
                        context_start = max(0, idx - 50)
                        context_end = min(len(decompiled_code), idx + len(pattern) + 50)
                        context = decompiled_code[context_start:context_end].strip()
                        
                        # Create vulnerability entry
                        vulnerability = {
                            'function': func.getName(),
                            'address': func.getEntryPoint(),
                            'type': vuln_type,
                            'description': pattern_info['description'],
                            'severity': pattern_info['severity'],
                            'pattern': pattern,
                            'context': context
                        }
                        
                        # Add to vulnerabilities list
                        self.vulnerabilities.append(vulnerability)
                        
                        # Move to next occurrence
                        start_idx = idx + len(pattern)
        except Exception as e:
            self.log(f"Error scanning decompiled code in {func.getName()}: {str(e)}")
    
    def clear_results(self):
        """Clear previous scan results"""
        self.vulnerabilities.clear()
    
    def show_results(self):
        """Display scan results"""
        self.println("\n=== Security Vulnerability Scan Results ===")
        self.println(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        # Group vulnerabilities by severity
        severity_groups = defaultdict(list)
        for vuln in self.vulnerabilities:
            severity_groups[vuln['severity']].append(vuln)
        
        # Show high severity vulnerabilities first
        for severity in ['high', 'medium', 'low']:
            if severity in severity_groups:
                vulns = severity_groups[severity]
                self.println(f"\n=== {severity.upper()} Severity Vulnerabilities ({len(vulns)}) ===")
                
                # Group by type
                type_groups = defaultdict(list)
                for vuln in vulns:
                    type_groups[vuln['type']].append(vuln)
                
                for vuln_type, type_vulns in type_groups.items():
                    self.println(f"\n{self.security_patterns.get(vuln_type, {'description': vuln_type})['description']} ({len(type_vulns)} occurrences):")
                    
                    # Show first 5 occurrences
                    for i, vuln in enumerate(type_vulns[:5]):
                        self.println(f"  {i+1}. Function: {vuln['function']}")
                        self.println(f"     Address: {vuln['address']}")
                        self.println(f"     Context: {vuln['context'][:150]}...")
                    
                    if len(type_vulns) > 5:
                        self.println(f"     ... and {len(type_vulns) - 5} more occurrences")
        
        # Show summary
        self.println("\n=== Scan Summary ===")
        self.println(f"High severity: {len(severity_groups.get('high', []))}")
        self.println(f"Medium severity: {len(severity_groups.get('medium', []))}")
        self.println(f"Low severity: {len(severity_groups.get('low', []))}")
        self.println(f"Total: {len(self.vulnerabilities)}")
    
    def export_results(self, filename):
        """Export scan results to a JSON file"""
        try:
            results = {
                'vulnerabilities': self.vulnerabilities,
                'summary': {
                    'total': len(self.vulnerabilities),
                    'high_severity': len([v for v in self.vulnerabilities if v['severity'] == 'high']),
                    'medium_severity': len([v for v in self.vulnerabilities if v['severity'] == 'medium']),
                    'low_severity': len([v for v in self.vulnerabilities if v['severity'] == 'low'])
                },
                'scanned_functions': len([v['function'] for v in self.vulnerabilities]),
                'timestamp': self.get_current_timestamp()
            }
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
                
            self.println(f"Results exported to: {filename}")
        except Exception as e:
            self.println(f"Error exporting results: {str(e)}")
    
    def get_current_timestamp(self):
        """Get current timestamp"""
        import datetime
        return datetime.datetime.now().isoformat()

class SecurityScannerScript(GhidraScript):
    def run(self):
        """Main script entry point"""
        scanner = SecurityScanner()
        scanner.run()
        
        # Ask if user wants to export results
        if askYesNo("Export Results", "Do you want to export the scan results to a JSON file?"):
            filename = askString("Export Filename", "Enter filename for export:", "security_scan_results.json")
            if filename:
                scanner.export_results(filename)

# Export the main function for use as a Ghidra script
def run():
    script = SecurityScannerScript()
    script.run()

if __name__ == '__main__':
    run()
