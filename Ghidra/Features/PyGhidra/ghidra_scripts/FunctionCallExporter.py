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
# Function Call Exporter Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import json
import csv
import os
from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.util import FileChooser
from ghidra.app.util import FileChooserMode


def export_function_calls():
    """Export function call relationships to JSON and CSV formats"""
    
    print("=== Function Call Exporter ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    print(f"Exporting call relationships for: {currentProgram.name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} functions")
    
    # Collect function call data
    function_data = []
    call_relationships = []
    
    for function in functions:
        if function.isThunk():
            continue
        
        func_name = function.getName()
        func_addr = function.getEntryPoint()
        is_external = function.isExternal()
        
        # Add function to data list
        function_data.append({
            "name": func_name,
            "address": str(func_addr),
            "isExternal": is_external
        })
        
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
                    called_name = called_function.getName() if called_function else f"0x{called_addr}"
                    
                    # Add call relationship
                    call_relationships.append({
                        "caller": func_name,
                        "callerAddress": str(func_addr),
                        "callee": called_name,
                        "calleeAddress": str(called_addr),
                        "callInstruction": str(instr)
                    })
            
            # Move to next instruction
            instr = instr.add(1)
    
    # Create export data structure
    export_data = {
        "program": currentProgram.name,
        "functions": function_data,
        "calls": call_relationships
    }
    
    # Prompt user for export directory
    chooser = FileChooser.createFileChooser(currentProgram)
    chooser.setTitle("Select Export Directory")
    chooser.setMode(FileChooserMode.DIRECTORIES_ONLY)
    
    if chooser.showDialog():
        export_dir = chooser.getSelectedFile().getPath()
        
        # Export to JSON
        json_file = os.path.join(export_dir, f"{currentProgram.name}_function_calls.json")
        with open(json_file, 'w') as f:
            json.dump(export_data, f, indent=2)
        print(f"Exported to JSON: {json_file}")
        
        # Export to CSV
        csv_file = os.path.join(export_dir, f"{currentProgram.name}_function_calls.csv")
        with open(csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(["Caller", "Caller Address", "Callee", "Callee Address", "Call Instruction"])
            # Write data
            for call in call_relationships:
                writer.writerow([
                    call["caller"],
                    call["callerAddress"],
                    call["callee"],
                    call["calleeAddress"],
                    call["callInstruction"]
                ])
        print(f"Exported to CSV: {csv_file}")
        
        # Export functions to separate CSV
        functions_csv_file = os.path.join(export_dir, f"{currentProgram.name}_functions.csv")
        with open(functions_csv_file, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write header
            writer.writerow(["Function Name", "Address", "Is External"])
            # Write data
            for func in function_data:
                writer.writerow([
                    func["name"],
                    func["address"],
                    func["isExternal"]
                ])
        print(f"Exported functions to CSV: {functions_csv_file}")
    
    print("\n=== Export Complete ===")


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


# Run the export
if __name__ == "__main__":
    export_function_calls()
