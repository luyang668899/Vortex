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
# Function Call Counter Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor


def analyze_function_call_counts():
    """Analyze function call counts (incoming and outgoing)"""
    
    print("=== Function Call Counter ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    print(f"Analyzing program: {currentProgram.name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} functions")
    
    # Initialize counters
    call_counts = {}
    called_by_counts = {}
    
    # First pass: collect all functions and initialize counters
    for function in functions:
        if not function.isThunk():
            func_name = function.getName()
            func_addr = function.getEntryPoint()
            func_key = (func_name, func_addr)
            call_counts[func_key] = 0  # Outgoing calls
            called_by_counts[func_key] = 0  # Incoming calls
    
    # Second pass: analyze function calls
    for function in functions:
        if function.isThunk():
            continue
        
        func_name = function.getName()
        func_addr = function.getEntryPoint()
        func_key = (func_name, func_addr)
        
        # Get all calls made by this function
        instr = function.getEntryPoint()
        end_addr = function.getBody().getMaxAddress()
        
        while instr and instr <= end_addr:
            # Check if this is a call instruction
            flow_type = getFlowType(currentProgram, instr)
            if flow_type.isCall():
                # Get the called address
                called_addr = getReferenceTarget(instr, 0)  # Primary reference
                if called_addr:
                    # Try to get the function at the called address
                    called_function = function_manager.getFunctionAt(called_addr)
                    if called_function and not called_function.isThunk():
                        # Increment outgoing call count for current function
                        call_counts[func_key] += 1
                        
                        # Increment incoming call count for called function
                        called_func_name = called_function.getName()
                        called_func_addr = called_function.getEntryPoint()
                        called_func_key = (called_func_name, called_func_addr)
                        if called_func_key in called_by_counts:
                            called_by_counts[called_func_key] += 1
            
            # Move to next instruction
            instr = instr.add(1)
    
    # Generate report
    print("\n=== Function Call Statistics ===")
    
    # Sort functions by total call count (outgoing + incoming)
    sorted_functions = sorted(call_counts.keys(), 
                            key=lambda x: call_counts[x] + called_by_counts[x], 
                            reverse=True)
    
    for func_key in sorted_functions:
        func_name, func_addr = func_key
        outgoing = call_counts[func_key]
        incoming = called_by_counts[func_key]
        total = outgoing + incoming
        
        print(f"\n{func_name} (0x{func_addr}):")
        print(f"  Outgoing calls: {outgoing}")
        print(f"  Incoming calls: {incoming}")
        print(f"  Total calls: {total}")
    
    # Find functions with most outgoing calls
    if call_counts:
        most_outgoing = max(call_counts, key=call_counts.get)
        print(f"\n=== Most Outgoing Calls ===")
        print(f"{most_outgoing[0]} (0x{most_outgoing[1]}): {call_counts[most_outgoing]} calls")
    
    # Find functions with most incoming calls
    if called_by_counts:
        most_incoming = max(called_by_counts, key=called_by_counts.get)
        print(f"\n=== Most Incoming Calls ===")
        print(f"{most_incoming[0]} (0x{most_incoming[1]}): {called_by_counts[most_incoming]} calls")
    
    print("\n=== Analysis Complete ===")


def getFlowType(program, addr):
    """Get the flow type for an instruction"""
    instr = program.getListing().getInstructionAt(addr)
    if instr:
        return instr.getFlowType()
    return None


def getReferenceTarget(addr, ref_index):
    """Get the target of a reference at the given address"""
    refs = getReferencesFrom(addr)
    if refs and ref_index < len(refs):
        return refs[ref_index].getToAddress()
    return None


# Run the analysis
if __name__ == "__main__":
    analyze_function_call_counts()
