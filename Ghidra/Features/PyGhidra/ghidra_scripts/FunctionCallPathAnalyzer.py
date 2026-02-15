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
# Function Call Path Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util import OptionChooser
from ghidra.app.util import OptionDialog


def analyze_function_call_paths():
    """Analyze function call paths between specified functions"""
    
    print("=== Function Call Path Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    print(f"Analyzing call paths in: {currentProgram.name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} functions")
    
    # Filter out thunk functions
    non_thunk_functions = [f for f in functions if not f.isThunk()]
    function_names = [f.getName() for f in non_thunk_functions]
    
    if not function_names:
        print("No non-thunk functions found!")
        return
    
    # Prompt user to select start and end functions
    start_function = select_function("Select Start Function", function_names)
    if not start_function:
        print("No start function selected. Exiting.")
        return
    
    end_function = select_function("Select End Function", function_names)
    if not end_function:
        print("No end function selected. Exiting.")
        return
    
    print(f"\nFinding paths from {start_function} to {end_function}...")
    
    # Build function call graph
    call_graph = build_call_graph(non_thunk_functions, function_manager)
    
    # Find all paths from start to end
    paths = find_all_paths(call_graph, start_function, end_function)
    
    # Display results
    if paths:
        print(f"\nFound {len(paths)} path(s) from {start_function} to {end_function}:")
        
        for i, path in enumerate(paths, 1):
            print(f"\nPath {i}:")
            for j, func_name in enumerate(path):
                if j < len(path) - 1:
                    print(f"  {func_name} ->")
                else:
                    print(f"  {func_name}")
    else:
        print(f"\nNo paths found from {start_function} to {end_function}!")
    
    print("\n=== Analysis Complete ===")


def select_function(title, function_names):
    """Prompt user to select a function from a list"""
    # Create option chooser
    chooser = OptionChooser(title, function_names)
    chooser.setMultipleSelectionEnabled(False)
    
    # Show dialog
    if chooser.showDialog():
        selected = chooser.getSelectedValues()
        if selected and len(selected) > 0:
            return selected[0]
    
    return None


def build_call_graph(functions, function_manager):
    """Build a function call graph"""
    call_graph = {}
    
    # Initialize graph with all functions
    for function in functions:
        func_name = function.getName()
        call_graph[func_name] = []
    
    # Populate call graph
    for function in functions:
        func_name = function.getName()
        
        # Get all instructions in the function
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
                        called_func_name = called_function.getName()
                        # Add to call graph if not already present
                        if called_func_name not in call_graph[func_name]:
                            call_graph[func_name].append(called_func_name)
            
            # Move to next instruction
            instr = instr.add(1)
    
    return call_graph


def find_all_paths(graph, start, end, path=None):
    """Find all paths from start to end in graph"""
    if path is None:
        path = []
    
    path = path + [start]
    
    if start == end:
        return [path]
    
    if start not in graph:
        return []
    
    paths = []
    for node in graph[start]:
        if node not in path:  # Avoid cycles
            new_paths = find_all_paths(graph, node, end, path)
            for new_path in new_paths:
                paths.append(new_path)
    
    return paths


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
    analyze_function_call_paths()
