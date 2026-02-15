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
# Indirect Call Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType


def analyze_indirect_calls():
    """Analyze indirect function calls in the current program"""
    
    print("=== Indirect Call Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    print(f"Analyzing indirect calls in: {currentProgram.name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} functions")
    
    # Collect indirect calls
    indirect_calls = []
    
    for function in functions:
        if function.isThunk():
            continue
        
        func_name = function.getName()
        func_addr = function.getEntryPoint()
        
        # Get all instructions in the function
        instr = function.getEntryPoint()
        end_addr = function.getBody().getMaxAddress()
        
        while instr and instr <= end_addr:
            # Check if this is a call instruction
            flow_type = getFlowType(currentProgram, instr)
            if flow_type.isCall():
                # Check if this is an indirect call
                if is_indirect_call(currentProgram, instr):
                    # Get the register or memory location used for the call
                    call_target_info = get_indirect_call_target_info(currentProgram, instr)
                    
                    # Add to indirect calls list
                    indirect_calls.append({
                        "function": func_name,
                        "functionAddress": str(func_addr),
                        "callAddress": str(instr),
                        "targetInfo": call_target_info,
                        "instruction": str(instr)
                    })
            
            # Move to next instruction
            instr = instr.add(1)
    
    # Display results
    if indirect_calls:
        print(f"\nFound {len(indirect_calls)} indirect calls:")
        
        for call in indirect_calls:
            print(f"\nFunction: {call['function']} (0x{call['functionAddress']})")
            print(f"Call Address: 0x{call['callAddress']}")
            print(f"Instruction: {call['instruction']}")
            print(f"Target Info: {call['targetInfo']}")
    else:
        print("\nNo indirect calls found!")
    
    print("\n=== Analysis Complete ===")


def is_indirect_call(program, addr):
    """Check if an instruction is an indirect call"""
    instr = program.getListing().getInstructionAt(addr)
    if not instr:
        return False
    
    # Check if this is a call with indirect reference
    refs = getReferencesFrom(addr)
    for ref in refs:
        if ref.getReferenceType().isCall() and ref.getReferenceType().isIndirect(): 
            return True
    
    # Check instruction mnemonic for indirect call patterns
    mnemonic = instr.getMnemonicString().lower()
    # Common indirect call patterns
    indirect_patterns = ["call", "jmp"]
    
    if mnemonic in indirect_patterns:
        # Check if operand is a register or memory location
        for i in range(instr.getNumOperands()):
            op_str = instr.getOperandRepresentation(i).lower()
            # Check for register (e.g., eax, r12)
            if op_str.startswith("r") and not op_str.startswith("0x"):
                return True
            # Check for memory reference (e.g., [eax], [rsp+8])
            if "[" in op_str and "]" in op_str:
                return True
    
    return False


def get_indirect_call_target_info(program, addr):
    """Get information about the target of an indirect call"""
    instr = program.getListing().getInstructionAt(addr)
    if not instr:
        return "Unknown"
    
    # Get operand information
    for i in range(instr.getNumOperands()):
        op_str = instr.getOperandRepresentation(i)
        return f"Operand {i}: {op_str}"
    
    return "Unknown"


def getFlowType(program, addr):
    """Get the flow type for an instruction"""
    instr = program.getListing().getInstructionAt(addr)
    if instr:
        return instr.getFlowType()
    return None


# Run the analysis
if __name__ == "__main__":
    analyze_indirect_calls()
