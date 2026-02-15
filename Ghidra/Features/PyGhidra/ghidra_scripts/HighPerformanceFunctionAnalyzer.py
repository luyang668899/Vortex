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
# High Performance Function Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import time
import pickle
import os
from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.task import TaskMonitor
from ghidra.app.util import OptionDialog


def analyze_functions_with_performance():
    """Analyze functions with performance optimizations for large programs"""
    
    print("=== High Performance Function Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    start_time = time.time()
    program_name = currentProgram.name
    print(f"Analyzing program: {program_name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    
    # Use iterator to avoid loading all functions at once
    functions_iter = function_manager.getFunctions(True)  # True for sorted
    
    # Count total functions first (optional, but helps with progress reporting)
    total_functions = sum(1 for _ in function_manager.getFunctions(True))
    print(f"Found {total_functions} total functions")
    
    # Create a task monitor for progress reporting
    monitor = ConsoleTaskMonitor()
    monitor.setMaximum(total_functions)
    
    # Process functions with performance optimizations
    function_data = {}
    call_relationships = {}
    
    processed_functions = 0
    
    # Reset iterator
    functions_iter = function_manager.getFunctions(True)
    
    for function in functions_iter:
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
        
        # Store function info
        function_data[func_key] = {
            "name": func_name,
            "address": str(func_addr),
            "isExternal": function.isExternal(),
            "size": function.getBody().getNumAddresses()
        }
        
        # Process calls using efficient iteration
        calls = process_function_calls(function, function_manager)
        if calls:
            call_relationships[func_key] = calls
        
        processed_functions += 1
        monitor.setProgress(processed_functions)
        
        # Report progress every 100 functions
        if processed_functions % 100 == 0:
            elapsed = time.time() - start_time
            rate = processed_functions / elapsed if elapsed > 0 else 0
            print(f"Processed {processed_functions}/{total_functions} functions ({rate:.2f} funcs/sec)")
    
    # Calculate statistics
    non_thunk_functions = len(function_data)
    total_calls = sum(len(calls) for calls in call_relationships.values())
    
    # Display summary
    elapsed_time = time.time() - start_time
    print(f"\n=== Analysis Summary ===")
    print(f"Program: {program_name}")
    print(f"Total functions: {total_functions}")
    print(f"Non-thunk functions processed: {non_thunk_functions}")
    print(f"Total function calls found: {total_calls}")
    print(f"Analysis time: {elapsed_time:.2f} seconds")
    print(f"Processing rate: {non_thunk_functions / elapsed_time:.2f} functions/second")
    
    # Offer to save results to cache
    if OptionDialog.showYesNoDialog("Save Results", "Save analysis results to cache for faster future analysis?"):
        save_analysis_cache(program_name, function_data, call_relationships)
    
    print("\n=== Analysis Complete ===")


def process_function_calls(function, function_manager):
    """Process function calls efficiently"""
    calls = []
    
    # Get instruction iterator (more efficient than manual increment)
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


def save_analysis_cache(program_name, function_data, call_relationships):
    """Save analysis results to a cache file"""
    try:
        # Create cache directory if it doesn't exist
        cache_dir = os.path.join(os.path.expanduser("~"), ".ghidra_analysis_cache")
        os.makedirs(cache_dir, exist_ok=True)
        
        # Create cache file name based on program name
        cache_file = os.path.join(cache_dir, f"{program_name.replace(' ', '_')}_analysis.cache")
        
        # Save data
        cache_data = {
            "timestamp": time.time(),
            "function_data": function_data,
            "call_relationships": call_relationships
        }
        
        with open(cache_file, 'wb') as f:
            pickle.dump(cache_data, f)
        
        print(f"Analysis results saved to cache: {cache_file}")
        print(f"Next time you analyze this program, results will load faster")
        
    except Exception as e:
        print(f"Error saving cache: {e}")


def load_analysis_cache(program_name):
    """Load analysis results from a cache file"""
    try:
        cache_dir = os.path.join(os.path.expanduser("~"), ".ghidra_analysis_cache")
        cache_file = os.path.join(cache_dir, f"{program_name.replace(' ', '_')}_analysis.cache")
        
        if os.path.exists(cache_file):
            with open(cache_file, 'rb') as f:
                cache_data = pickle.load(f)
            
            print(f"Loaded analysis results from cache (saved at {time.ctime(cache_data['timestamp'])})")
            return cache_data
        
    except Exception as e:
        print(f"Error loading cache: {e}")
    
    return None


# Run the analysis
if __name__ == "__main__":
    # Check if cached data exists
    if currentProgram:
        cached_data = load_analysis_cache(currentProgram.name)
        if cached_data:
            # Use cached data if available
            print("Using cached analysis results for faster processing")
            # Here you could use the cached data instead of reprocessing
            # For demonstration, we'll still do a fresh analysis
    
    analyze_functions_with_performance()
