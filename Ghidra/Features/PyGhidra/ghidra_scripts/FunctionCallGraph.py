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
# Function Call Graph Generator Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

from ghidra.program.model.symbol import FlowType
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.service.graph import GraphService
from ghidra.service.graph import GraphDisplay
from ghidra.service.graph import AttributedVertex
from ghidra.service.graph import AttributedEdge
from ghidra.service.graph import AttributedGraph
from ghidra.graph import CallGraphType


def generate_function_call_graph():
    """Generate and display a function call graph"""
    
    print("=== Function Call Graph Generator ===")
    
    if not currentProgram:
        print("No program currently open!")
        return
    
    print(f"Generating call graph for: {currentProgram.name}")
    
    # Get all functions in the program
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))  # True for sorted
    
    print(f"Found {len(functions)} functions")
    
    # Create a graph service
    graph_service = GraphService.getGraphService(currentProgram)
    if not graph_service:
        print("Graph service not available!")
        return
    
    # Create a new graph
    graph = AttributedGraph()
    
    # Create vertices for each function
    function_vertices = {}
    
    for function in functions:
        if not function.isThunk():
            func_name = function.getName()
            func_addr = function.getEntryPoint()
            func_key = (func_name, func_addr)
            
            # Create vertex
            vertex = AttributedVertex(f"{func_name}\n0x{func_addr}")
            vertex.setAttribute("functionName", func_name)
            vertex.setAttribute("address", str(func_addr))
            vertex.setVertexType(CallGraphType.EXTERNAL if function.isExternal() else CallGraphType.BODY)
            
            graph.addVertex(vertex)
            function_vertices[func_key] = vertex
    
    # Create edges for function calls
    edge_id = 0
    
    for function in functions:
        if function.isThunk():
            continue
        
        func_name = function.getName()
        func_addr = function.getEntryPoint()
        source_key = (func_name, func_addr)
        
        # Skip if source function not in vertices
        if source_key not in function_vertices:
            continue
        
        source_vertex = function_vertices[source_key]
        
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
                        called_func_name = called_function.getName()
                        called_func_addr = called_function.getEntryPoint()
                        target_key = (called_func_name, called_func_addr)
                        
                        # Skip if target function not in vertices
                        if target_key not in function_vertices:
                            continue
                        
                        target_vertex = function_vertices[target_key]
                        
                        # Create edge
                        edge = AttributedEdge(f"edge_{edge_id}")
                        edge.setEdgeType(CallGraphType.UNCONDITIONAL_CALL)
                        edge.setAttribute("callAddress", str(instr))
                        
                        graph.addEdge(source_vertex, target_vertex, edge)
                        edge_id += 1
            
            # Move to next instruction
            instr = instr.add(1)
    
    # Display the graph
    if graph.getVertexCount() > 0:
        print(f"\nCreated graph with {graph.getVertexCount()} vertices and {graph.getEdgeCount()} edges")
        
        # Create graph display
        display = graph_service.createGraphDisplay("Function Call Graph", CallGraphType())
        if display:
            display.setGraph(graph)
            display.setVisible(True)
            print("Call graph displayed successfully!")
        else:
            print("Failed to create graph display!")
    else:
        print("No functions found to create graph!")
    
    print("\n=== Graph Generation Complete ===")


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


# Run the graph generation
if __name__ == "__main__":
    generate_function_call_graph()
