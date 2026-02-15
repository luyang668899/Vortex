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
# Decompiler Integration Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import time
from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompileResults
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import PcodeOp
from ghidra.app.util import OptionChooser
from ghidra.app.util import OptionDialog


def analyze_functions_with_decompiler():
    """Analyze functions using Ghidra's decompiler for advanced insights"""
    
    print("=== Decompiler Integration Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    start_time = time.time()
    program_name = currentProgram.name
    print(f"Analyzing program: {program_name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    # Filter out thunk functions
    non_thunk_functions = [f for f in functions if not f.isThunk()]
    function_names = [f.getName() for f in non_thunk_functions]
    
    print(f"Found {len(non_thunk_functions)} non-thunk functions")
    
    # Prompt user to select functions to analyze
    selected_functions = select_functions("Select Functions to Analyze", function_names)
    if not selected_functions:
        print("No functions selected. Exiting.")
        return
    
    print(f"\nAnalyzing {len(selected_functions)} selected functions with decompiler...")
    
    # Initialize decompiler
    decompiler = initialize_decompiler()
    if not decompiler:
        print("Failed to initialize decompiler. Exiting.")
        return
    
    # Create a task monitor for progress reporting
    monitor = ConsoleTaskMonitor()
    monitor.setMaximum(len(selected_functions))
    
    # Analyze each selected function
    analysis_results = []
    processed_functions = 0
    
    for func_name in selected_functions:
        # Check if user cancelled
        if monitor.isCancelled():
            print("Analysis cancelled by user")
            return
        
        # Find the function by name
        function = find_function_by_name(function_manager, func_name)
        if not function:
            print(f"Function {func_name} not found. Skipping.")
            monitor.incrementProgress(1)
            continue
        
        # Decompile the function
        decompile_results = decompile_function(decompiler, function, monitor)
        if not decompile_results:
            print(f"Failed to decompile {func_name}. Skipping.")
            monitor.incrementProgress(1)
            continue
        
        # Analyze decompilation results
        func_analysis = analyze_decompiled_function(function, decompile_results)
        analysis_results.append(func_analysis)
        
        # Display analysis results
        display_function_analysis(func_analysis)
        
        processed_functions += 1
        monitor.setProgress(processed_functions)
        
        # Report progress
        if processed_functions % 5 == 0:
            elapsed = time.time() - start_time
            rate = processed_functions / elapsed if elapsed > 0 else 0
            print(f"Processed {processed_functions}/{len(selected_functions)} functions ({rate:.2f} funcs/sec)")
    
    # Clean up
    decompiler.dispose()
    
    # Display summary
    elapsed_time = time.time() - start_time
    print(f"\n=== Analysis Summary ===")
    print(f"Program: {program_name}")
    print(f"Selected functions: {len(selected_functions)}")
    print(f"Successfully analyzed: {len(analysis_results)}")
    print(f"Analysis time: {elapsed_time:.2f} seconds")
    print(f"Processing rate: {len(analysis_results) / elapsed_time:.2f} functions/second")
    
    print("\n=== Analysis Complete ===")


def initialize_decompiler():
    """Initialize the decompiler interface"""
    try:
        decompiler = DecompInterface()
        options = DecompileOptions()
        options.grabFromProgram(currentProgram)
        decompiler.setOptions(options)
        decompiler.openProgram(currentProgram)
        return decompiler
    except Exception as e:
        print(f"Error initializing decompiler: {e}")
        return None


def decompile_function(decompiler, function, monitor):
    """Decompile a function and return the results"""
    try:
        results = decompiler.decompileFunction(function, 60, monitor)  # 60 second timeout
        if results.decompileCompleted():
            return results
        else:
            print(f"Decompilation failed for {function.getName()}: {results.getErrorMessage()}")
            return None
    except Exception as e:
        print(f"Error decompiling {function.getName()}: {e}")
        return None


def analyze_decompiled_function(function, decompile_results):
    """Analyze a decompiled function for advanced insights"""
    
    func_name = function.getName()
    func_addr = function.getEntryPoint()
    
    # Get the high function from decompilation results
    high_function = decompile_results.getHighFunction()
    if not high_function:
        return {
            "name": func_name,
            "address": str(func_addr),
            "error": "No high function available"
        }
    
    # Extract C code
    c_code = decompile_results.getDecompiledFunction().getC()
    
    # Analyze variables
    variables = analyze_variables(high_function)
    
    # Analyze function calls in decompiled code
    decompiled_calls = analyze_decompiled_calls(high_function, function.getProgram().getFunctionManager())
    
    # Analyze control flow
    control_flow = analyze_control_flow(high_function)
    
    return {
        "name": func_name,
        "address": str(func_addr),
        "cCode": c_code,
        "variables": variables,
        "decompiledCalls": decompiled_calls,
        "controlFlow": control_flow,
        "size": function.getBody().getNumAddresses(),
        "isExternal": function.isExternal()
    }


def analyze_variables(high_function):
    """Analyze variables in the decompiled function"""
    variables = []
    
    try:
        # Get all variables
        local_variables = high_function.getLocalSymbolMap().getSymbols()
        for var in local_variables:
            var_name = var.getName()
            var_type = var.getType().getName()
            variables.append({
                "name": var_name,
                "type": var_type
            })
    except Exception as e:
        print(f"Error analyzing variables: {e}")
    
    return variables


def analyze_decompiled_calls(high_function, function_manager):
    """Analyze function calls in the decompiled code"""
    calls = []
    
    try:
        # Get all pcode operations
        pcode_ops = high_function.getPcodeOps()
        for op in pcode_ops:
            if op.getOpcode() == PcodeOp.CALL:
                # Get the called address
                input_varnodes = op.getInputs()
                if len(input_varnodes) > 0:
                    called_varnode = input_varnodes[0]
                    if called_varnode.isAddress():  # Direct call
                        called_addr = called_varnode.getAddress()
                        called_function = function_manager.getFunctionAt(called_addr)
                        if called_function:
                            calls.append({
                                "name": called_function.getName(),
                                "address": str(called_addr),
                                "type": "direct"
                            })
                        else:
                            calls.append({
                                "name": f"0x{called_addr}",
                                "address": str(called_addr),
                                "type": "direct"
                            })
                    else:  # Indirect call
                        calls.append({
                            "name": "[indirect]",
                            "address": "unknown",
                            "type": "indirect"
                        })
    except Exception as e:
        print(f"Error analyzing decompiled calls: {e}")
    
    return calls


def analyze_control_flow(high_function):
    """Analyze control flow in the decompiled function"""
    control_flow = {
        "basicBlocks": 0,
        "conditionalBranches": 0,
        "loops": 0
    }
    
    try:
        # Get basic blocks
        basic_blocks = high_function.getBasicBlocks()
        control_flow["basicBlocks"] = len(basic_blocks)
        
        # Count conditional branches and loops
        for block in basic_blocks:
            # Count conditional branches
            pcode_ops = block.getIterator()
            for op in pcode_ops:
                opcode = op.getOpcode()
                if opcode in (PcodeOp.BRANCH, PcodeOp.CBRANCH):
                    control_flow["conditionalBranches"] += 1
                elif opcode == PcodeOp.LOOP:  # This is a simplification
                    control_flow["loops"] += 1
    except Exception as e:
        print(f"Error analyzing control flow: {e}")
    
    return control_flow


def display_function_analysis(analysis):
    """Display analysis results for a function"""
    
    print(f"\n=== Function Analysis: {analysis['name']} ===")
    print(f"Address: 0x{analysis['address']}")
    
    if "error" in analysis:
        print(f"Error: {analysis['error']}")
        return
    
    print(f"Size: {analysis['size']} bytes")
    print(f"External: {analysis['isExternal']}")
    
    # Display variables
    if analysis['variables']:
        print(f"\nVariables ({len(analysis['variables'])}):")
        for var in analysis['variables'][:10]:  # Show first 10
            print(f"  - {var['name']}: {var['type']}")
        if len(analysis['variables']) > 10:
            print(f"  ... and {len(analysis['variables']) - 10} more")
    
    # Display decompiled calls
    if analysis['decompiledCalls']:
        print(f"\nFunction Calls ({len(analysis['decompiledCalls'])}):")
        for call in analysis['decompiledCalls']:
            print(f"  - {call['name']} ({call['type']} call)")
    
    # Display control flow
    print(f"\nControl Flow:")
    print(f"  Basic Blocks: {analysis['controlFlow']['basicBlocks']}")
    print(f"  Conditional Branches: {analysis['controlFlow']['conditionalBranches']}")
    print(f"  Loops: {analysis['controlFlow']['loops']}")
    
    # Offer to show C code
    if OptionDialog.showYesNoDialog("Show C Code", f"Show decompiled C code for {analysis['name']}?"):
        print(f"\n=== Decompiled C Code for {analysis['name']} ===")
        print(analysis['cCode'])
        print("=== End of C Code ===")


def select_functions(title, function_names):
    """Prompt user to select multiple functions from a list"""
    # Create option chooser
    chooser = OptionChooser(title, function_names)
    chooser.setMultipleSelectionEnabled(True)
    
    # Show dialog
    if chooser.showDialog():
        selected = chooser.getSelectedValues()
        return selected
    
    return None


def find_function_by_name(function_manager, name):
    """Find a function by name"""
    for function in function_manager.getFunctions(True):
        if function.getName() == name:
            return function
    return None


# Run the analysis
if __name__ == "__main__":
    analyze_functions_with_decompiler()
