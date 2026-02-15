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
# Function Call Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor


def analyze_function_calls():
    """Analyze function call relationships in the current program"""
    
    print("=== Function Call Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    print(f"Analyzing program: {currentProgram.name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} functions")
    print("\n=== Function Call Relationships ===")
    
    # Analyze each function
    for function in functions:
        # Skip thunk functions
        if function.isThunk():
            continue
        
        function_name = function.getName()
        function_addr = function.getEntryPoint()
        
        # Get all calls made by this function
        calls = []
        
        # Iterate through all instructions in the function
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
                    if called_function:
                        calls.append((called_function.getName(), called_addr))
                    else:
                        calls.append((f"0x{called_addr}", called_addr))
            
            # Move to next instruction
            instr = instr.add(1)
        
        # Print the function and its calls
        if calls:
            print(f"\n{function_name} (0x{function_addr}):")
            for called_name, called_addr in calls:
                print(f"  -> {called_name} (0x{called_addr})")
        
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
    analyze_function_calls()
