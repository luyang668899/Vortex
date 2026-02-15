#!/usr/bin/env python3
# APIUsageAnalyzer.py
#
# A tool for analyzing program API usage patterns
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
except ImportError:
    # Handle import errors when running outside Ghidra
    pass

class APIUsageAnalyzer(GhidraScript):
    def __init__(self):
        super().__init__()
        self.api_usage_patterns = defaultdict(list)
        self.function_calls = defaultdict(list)
        self.decomp_interface = None
    
    def run(self):
        """Main script entry point"""
        self.analyze_api_usage()
        self.show_results()
    
    def analyze_api_usage(self):
        """Analyze API usage patterns in the program"""
        self.clear_results()
        
        # Initialize decompiler interface
        self.decomp_interface = DecompInterface()
        self.decomp_interface.openProgram(currentProgram())
        
        # Get all functions in the program
        function_manager = currentProgram().getFunctionManager()
        functions = list(function_manager.getFunctions(True))
        
        self.monitor.initialize(len(functions))
        self.monitor.setMessage("Analyzing API usage patterns...")
        
        for i, func in enumerate(functions):
            if self.monitor.isCancelled():
                break
                
            self.monitor.setProgress(i)
            self.monitor.setMessage(f"Analyzing function: {func.getName()}")
            
            # Analyze function calls
            self.analyze_function_calls(func)
            
            # Analyze decompiled code for API usage
            self.analyze_decompiled_code(func)
        
        # Clean up
        if self.decomp_interface:
            self.decomp_interface.dispose()
    
    def analyze_function_calls(self, func):
        """Analyze function calls in the given function"""
        try:
            # Get function body
            body = func.getBody()
            if body is None:
                return
                
            # Get instruction iterator
            listing = currentProgram().getListing()
            instructions = listing.getInstructions(body, True)
            
            for instr in instructions:
                # Check if this is a function call
                if instr.getFlowType().isCall():
                    # Get the called function
                    called_func = getFunctionAt(instr.getAddress())
                    if called_func:
                        call_info = {
                            'caller': func.getName(),
                            'caller_address': func.getEntryPoint(),
                            'callee': called_func.getName(),
                            'callee_address': called_func.getEntryPoint(),
                            'call_address': instr.getAddress(),
                            'instruction': instr.toString()
                        }
                        self.function_calls[func.getName()].append(call_info)
                        
                        # Check if this is an external API call
                        if called_func.isExternal():
                            api_info = call_info.copy()
                            api_info['is_external'] = True
                            self.api_usage_patterns[called_func.getName()].append(api_info)
        except Exception as e:
            self.log(f"Error analyzing function calls in {func.getName()}: {str(e)}")
    
    def analyze_decompiled_code(self, func):
        """Analyze decompiled code for API usage patterns"""
        try:
            # Decompile the function
            results = self.decomp_interface.decompileFunction(func, 30, self.monitor)
            if not results.decompileCompleted():
                return
                
            high_func = results.getHighFunction()
            if not high_func:
                return
                
            # Get the decompiled code as a string
            decompiled_code = results.getDecompiledFunction().getC()
            
            # Analyze for API usage patterns
            self.analyze_api_patterns(func, decompiled_code)
        except Exception as e:
            self.log(f"Error analyzing decompiled code for {func.getName()}: {str(e)}")
    
    def analyze_api_patterns(self, func, decompiled_code):
        """Analyze decompiled code for specific API usage patterns"""
        # Simple pattern matching for common API usage
        common_apis = [
            'malloc', 'free', 'calloc', 'realloc',  # Memory allocation
            'fopen', 'fclose', 'fread', 'fwrite', 'fprintf',  # File I/O
            'socket', 'connect', 'bind', 'listen', 'accept', 'send', 'recv',  # Network
            'CreateProcess', 'OpenProcess', 'CloseHandle',  # Windows API
            'system', 'exec', 'popen',  # Process creation
            'crypt', 'encrypt', 'decrypt', 'hash',  # Crypto
            'rand', 'srand', 'random',  # Random number generation
            'strcmp', 'strcpy', 'strcat', 'memcpy', 'memset'  # String/ memory operations
        ]
        
        for api in common_apis:
            if api in decompiled_code:
                pattern_info = {
                    'function': func.getName(),
                    'api': api,
                    'context': self.extract_context(decompiled_code, api, 100)  # Get 100 chars of context
                }
                self.api_usage_patterns[api].append(pattern_info)
    
    def extract_context(self, code, pattern, context_size):
        """Extract context around a pattern in code"""
        index = code.find(pattern)
        if index == -1:
            return ""
            
        start = max(0, index - context_size // 2)
        end = min(len(code), index + len(pattern) + context_size // 2)
        return code[start:end].strip()
    
    def clear_results(self):
        """Clear previous analysis results"""
        self.api_usage_patterns.clear()
        self.function_calls.clear()
    
    def show_results(self):
        """Display analysis results"""
        self.println("\n=== API Usage Analysis Results ===")
        self.println(f"Total functions analyzed: {len(self.function_calls)}")
        self.println(f"Total APIs detected: {len(self.api_usage_patterns)}")
        
        # Show top APIs by usage count
        self.println("\n=== Top API Usage Patterns ===")
        api_counts = {api: len(calls) for api, calls in self.api_usage_patterns.items()}
        sorted_apis = sorted(api_counts.items(), key=lambda x: x[1], reverse=True)[:20]
        
        for api, count in sorted_apis:
            self.println(f"{api}: {count} calls")
            # Show sample usage
            if self.api_usage_patterns[api]:
                sample = self.api_usage_patterns[api][0]
                self.println(f"  Sample usage in: {sample.get('function', 'N/A')}")
                if 'context' in sample:
                    self.println(f"  Context: {sample['context'][:150]}...")
        
        # Show external API calls
        self.println("\n=== External API Calls ===")
        external_apis = {}
        for api, calls in self.api_usage_patterns.items():
            external_calls = [call for call in calls if call.get('is_external', False)]
            if external_calls:
                external_apis[api] = external_calls
        
        for api, calls in external_apis.items():
            self.println(f"{api}: {len(calls)} external calls")
            for call in calls[:3]:  # Show first 3 calls
                self.println(f"  Call from: {call['caller']} at {call['call_address']}")
    
    def export_results(self, filename):
        """Export analysis results to a JSON file"""
        try:
            results = {
                'api_usage_patterns': dict(self.api_usage_patterns),
                'function_calls': dict(self.function_calls),
                'summary': {
                    'total_functions': len(self.function_calls),
                    'total_apis': len(self.api_usage_patterns),
                    'external_apis': len([api for api, calls in self.api_usage_patterns.items() 
                                         if any(call.get('is_external', False) for call in calls)])
                }
            }
            
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
                
            self.println(f"Results exported to: {filename}")
        except Exception as e:
            self.println(f"Error exporting results: {str(e)}")

class APIUsageAnalyzerScript(GhidraScript):
    def run(self):
        """Main script entry point"""
        analyzer = APIUsageAnalyzer()
        analyzer.run()
        
        # Ask if user wants to export results
        if askYesNo("Export Results", "Do you want to export the analysis results to a JSON file?"):
            filename = askString("Export Filename", "Enter filename for export:", "api_usage_analysis.json")
            if filename:
                analyzer.export_results(filename)

# Export the main function for use as a Ghidra script
def run():
    script = APIUsageAnalyzerScript()
    script.run()

if __name__ == '__main__':
    run()
