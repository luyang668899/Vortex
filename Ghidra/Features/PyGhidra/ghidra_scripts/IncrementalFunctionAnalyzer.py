## ###
# IP: GHIDRA
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
##
# Incremental Function Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import time
import pickle
import os
import hashlib
from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util import OptionDialog
from ghidra.program.model.listing import Function
from ghidra.program.model.mem import MemoryBlock


def analyze_functions_incrementally():
    """Analyze only modified functions for incremental updates"""
    
    print("=== Incremental Function Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    start_time = time.time()
    program_name = currentProgram.name
    program_hash = get_program_hash(currentProgram)
    
    print(f"Analyzing program: {program_name}")
    print(f"Program hash: {program_hash[:10]}...")
    
    # Load previous analysis data if available
    analysis_data = load_analysis_data(program_name)
    
    if analysis_data:
        print(f"Found previous analysis from {time.ctime(analysis_data['timestamp'])}")
        print(f"Previous program hash: {analysis_data['program_hash'][:10]}...")
        
        # Check if program has changed
        if analysis_data['program_hash'] == program_hash:
            print("Program has not changed. Using cached analysis results.")
            display_analysis_results(analysis_data)
            print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds (cached)")
            return
        else:
            print("Program has changed. Performing incremental analysis...")
    else:
        print("No previous analysis found. Performing full analysis...")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} total functions")
    
    # Process functions
    function_data = {}
    call_relationships = {}
    modified_functions = []
    
    # Create a task monitor for progress reporting
    monitor = ConsoleTaskMonitor()
    monitor.setMaximum(len(functions))
    
    processed_functions = 0
    analyzed_functions = 0
    
    for function in functions:
        # Check if user cancelled
        if monitor.isCancelled():
            print("Analysis cancelled by user")
            return
        
        # Skip thunk functions
        if function.isThunk():
            monitor.incrementProgress(1)
            continue
        
        func_name = function.getName()
        func_addr = function.getEntryPoint()
        func_key = (func_name, func_addr)
        
        # Calculate function hash to detect changes
        func_hash = get_function_hash(function)
        
        # Check if function has changed
        function_changed = True
        if analysis_data:
            if func_key in analysis_data['function_data']:
                prev_func_data = analysis_data['function_data'][func_key]
                if prev_func_data.get('hash') == func_hash:
                    # Function hasn't changed, use cached data
                    function_data[func_key] = prev_func_data
                    if func_key in analysis_data['call_relationships']:
                        call_relationships[func_key] = analysis_data['call_relationships'][func_key]
                    function_changed = False
        
        if function_changed:
            # Function has changed, analyze it
            modified_functions.append(func_name)
            analyzed_functions += 1
            
            # Store function info with hash
            function_data[func_key] = {
                "name": func_name,
                "address": str(func_addr),
                "isExternal": function.isExternal(),
                "size": function.getBody().getNumAddresses(),
                "hash": func_hash
            }
            
            # Process calls
            calls = process_function_calls(function, function_manager)
            if calls:
                call_relationships[func_key] = calls
        
        processed_functions += 1
        monitor.setProgress(processed_functions)
        
        # Report progress every 50 functions
        if processed_functions % 50 == 0:
            elapsed = time.time() - start_time
            rate = processed_functions / elapsed if elapsed > 0 else 0
            print(f"Processed {processed_functions}/{len(functions)} functions ({rate:.2f} funcs/sec)")
    
    # Calculate statistics
    non_thunk_functions = len(function_data)
    total_calls = sum(len(calls) for calls in call_relationships.values())
    
    # Create new analysis data
    new_analysis_data = {
        "timestamp": time.time(),
        "program_name": program_name,
        "program_hash": program_hash,
        "function_data": function_data,
        "call_relationships": call_relationships,
        "modified_functions": modified_functions
    }
    
    # Save analysis data
    save_analysis_data(program_name, new_analysis_data)
    
    # Display summary
    elapsed_time = time.time() - start_time
    print(f"\n=== Analysis Summary ===")
    print(f"Program: {program_name}")
    print(f"Total functions: {len(functions)}")
    print(f"Non-thunk functions: {non_thunk_functions}")
    print(f"Total function calls: {total_calls}")
    print(f"Modified functions: {len(modified_functions)}")
    print(f"Analyzed functions: {analyzed_functions}")
    print(f"Analysis time: {elapsed_time:.2f} seconds")
    
    if modified_functions:
        print(f"\nModified functions:")
        for func_name in modified_functions[:10]:  # Show first 10
            print(f"  - {func_name}")
        if len(modified_functions) > 10:
            print(f"  ... and {len(modified_functions) - 10} more")
    
    print("\n=== Analysis Complete ===")


def get_program_hash(program):
    """Generate a hash for the program to detect changes"""
    # Combine program name, size, and modification time
    program_info = f"{program.getName()}_{program.getMemory().getSize()}_{program.getLastChangeTime()}"
    return hashlib.sha256(program_info.encode()).hexdigest()


def get_function_hash(function):
    """Generate a hash for a function to detect changes"""
    if not function:
        return ""
    
    # Combine function name, address, size, and last change time
    func_info = f"{function.getName()}_{function.getEntryPoint()}_{function.getBody().getNumAddresses()}"
    
    # Add some instruction data to detect code changes
    instr = function.getEntryPoint()
    end_addr = function.getBody().getMaxAddress()
    
    # Sample first few instructions
    instr_samples = []
    sample_count = 0
    max_samples = 5
    
    while instr and instr <= end_addr and sample_count < max_samples:
        instr_obj = currentProgram.getListing().getInstructionAt(instr)
        if instr_obj:
            instr_samples.append(str(instr_obj))
            sample_count += 1
        instr = instr.add(1)
    
    func_info += "_".join(instr_samples)
    return hashlib.sha256(func_info.encode()).hexdigest()


def process_function_calls(function, function_manager):
    """Process function calls"""
    calls = []
    
    # Get instruction iterator
    instr_iterator = function.getBody().getAddresses(True)  # True for forward
    
    for instr_addr in instr_iterator:
        # Get instruction
        instr = currentProgram.getListing().getInstructionAt(instr_addr)
        if not instr:
            continue
        
        # Check if this is a call instruction
        flow_type = instr.getFlowType()
        if flow_type.isCall():
            # Get the called address
            refs = getReferencesFrom(instr_addr)
            for ref in refs:
                if ref.getReferenceType().isCall():
                    called_addr = ref.getToAddress()
                    if called_addr:
                        # Try to get the function at the called address
                        called_function = function_manager.getFunctionAt(called_addr)
                        if called_function and not called_function.isThunk():
                            calls.append((called_function.getName(), called_addr))
                        else:
                            calls.append((f"0x{called_addr}", called_addr))
                    break  # Only process first call reference
    
    return calls


def save_analysis_data(program_name, analysis_data):
    """Save analysis data to disk"""
    try:
        # Create cache directory if it doesn't exist
        cache_dir = os.path.join(os.path.expanduser("~"), ".ghidra_incremental_cache")
        os.makedirs(cache_dir, exist_ok=True)
        
        # Create cache file name based on program name
        cache_file = os.path.join(cache_dir, f"{program_name.replace(' ', '_')}_incremental.cache")
        
        # Save data
        with open(cache_file, 'wb') as f:
            pickle.dump(analysis_data, f)
        
        print(f"Analysis data saved to: {cache_file}")
        
    except Exception as e:
        print(f"Error saving analysis data: {e}")


def load_analysis_data(program_name):
    """Load analysis data from disk"""
    try:
        cache_dir = os.path.join(os.path.expanduser("~"), ".ghidra_incremental_cache")
        cache_file = os.path.join(cache_dir, f"{program_name.replace(' ', '_')}_incremental.cache")
        
        if os.path.exists(cache_file):
            with open(cache_file, 'rb') as f:
                analysis_data = pickle.load(f)
            return analysis_data
        
    except Exception as e:
        print(f"Error loading analysis data: {e}")
    
    return None


def display_analysis_results(analysis_data):
    """Display analysis results"""
    function_data = analysis_data.get('function_data', {})
    call_relationships = analysis_data.get('call_relationships', {})
    
    print(f"\n=== Cached Analysis Results ===")
    print(f"Program: {analysis_data.get('program_name', 'Unknown')}")
    print(f"Analysis time: {time.ctime(analysis_data.get('timestamp', time.time()))}")
    print(f"Non-thunk functions: {len(function_data)}")
    print(f"Total function calls: {sum(len(calls) for calls in call_relationships.values())}")
    
    if 'modified_functions' in analysis_data and analysis_data['modified_functions']:
        print(f"Modified functions: {len(analysis_data['modified_functions'])}")


# Run the analysis
if __name__ == "__main__":
    analyze_functions_incrementally()
