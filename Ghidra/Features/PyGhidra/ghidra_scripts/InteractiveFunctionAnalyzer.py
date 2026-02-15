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
# Interactive Function Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import time
import json
import csv
import os
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JLabel
from javax.swing import JTabbedPane
from javax.swing import BoxLayout
from javax.swing import BorderFactory
from javax.swing import JOptionPane
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt import BorderLayout
from java.awt import GridLayout
from java.awt import FlowLayout
from java.awt import Dimension
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.util.task import TaskMonitor
from ghidra.app.util import OptionDialog
from ghidra.program.model.symbol import FlowType
from ghidra.service.graph import GraphService
from ghidra.service.graph import AttributedVertex
from ghidra.service.graph import AttributedEdge
from ghidra.service.graph import AttributedGraph
from ghidra.graph import CallGraphType


def show_interactive_analyzer():
    """Show interactive function analyzer UI"""
    
    print("=== Interactive Function Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        JOptionPane.showMessageDialog(None, "No program currently open!", "Error", JOptionPane.ERROR_MESSAGE)
        return
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main interactive analyzer frame"""
    
    # Create frame
    frame = JFrame("Interactive Function Analyzer")
    frame.setSize(1000, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different analysis tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Function Info", create_function_info_panel())
    tabbed_pane.addTab("Call Graph", create_call_graph_panel())
    tabbed_pane.addTab("Call Paths", create_call_paths_panel())
    tabbed_pane.addTab("Export", create_export_panel())
    tabbed_pane.addTab("Advanced", create_advanced_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_function_info_panel():
    """Create panel for function information"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with function selection
    top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    function_label = JLabel("Select Function:")
    function_combo = create_function_combo()
    refresh_button = JButton("Refresh")
    
    top_panel.add(function_label)
    top_panel.add(function_combo)
    top_panel.add(refresh_button)
    
    # Text area for function info
    info_area = JTextArea()
    info_area.setEditable(False)
    info_area.setLineWrap(True)
    info_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(info_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Bottom panel with action buttons
    bottom_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_button = JButton("Analyze Selected Function")
    decompile_button = JButton("Show Decompiled Code")
    
    bottom_panel.add(analyze_button)
    bottom_panel.add(decompile_button)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_button:
                selected_func = function_combo.getSelectedItem()
                if selected_func:
                    analyze_function(selected_func, info_area)
            elif event.getSource() == decompile_button:
                selected_func = function_combo.getSelectedItem()
                if selected_func:
                    show_decompiled_code(selected_func, info_area)
            elif event.getSource() == refresh_button:
                refresh_function_combo(function_combo)
    
    listener = ButtonActionListener()
    analyze_button.addActionListener(listener)
    decompile_button.addActionListener(listener)
    refresh_button.addActionListener(listener)
    
    return panel


def create_call_graph_panel():
    """Create panel for call graph visualization"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with options
    top_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    generate_button = JButton("Generate Call Graph")
    export_graph_button = JButton("Export Graph")
    
    top_panel.add(generate_button)
    top_panel.add(export_graph_button)
    
    # Text area for status
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(status_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == generate_button:
                generate_and_show_call_graph(status_area)
            elif event.getSource() == export_graph_button:
                export_call_graph(status_area)
    
    listener = ButtonActionListener()
    generate_button.addActionListener(listener)
    export_graph_button.addActionListener(listener)
    
    return panel


def create_call_paths_panel():
    """Create panel for call path analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with function selection
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Start function selection
    start_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    start_label = JLabel("Start Function:")
    start_combo = create_function_combo()
    start_panel.add(start_label)
    start_panel.add(start_combo)
    
    # End function selection
    end_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    end_label = JLabel("End Function:")
    end_combo = create_function_combo()
    end_panel.add(end_label)
    end_panel.add(end_combo)
    
    # Find paths button
    find_button = JButton("Find Paths")
    
    top_panel.add(start_panel)
    top_panel.add(end_panel)
    top_panel.add(find_button)
    
    # Text area for paths
    paths_area = JTextArea()
    paths_area.setEditable(False)
    paths_area.setLineWrap(True)
    paths_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(paths_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == find_button:
                start_func = start_combo.getSelectedItem()
                end_func = end_combo.getSelectedItem()
                if start_func and end_func:
                    find_and_display_paths(start_func, end_func, paths_area)
    
    listener = ButtonActionListener()
    find_button.addActionListener(listener)
    
    return panel


def create_export_panel():
    """Create panel for exporting analysis results"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with export options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Export format selection
    format_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    format_label = JLabel("Export Format:")
    format_combo = JComboBox(["JSON", "CSV", "Both"])
    format_panel.add(format_label)
    format_panel.add(format_combo)
    
    # Export scope selection
    scope_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    scope_label = JLabel("Export Scope:")
    scope_combo = JComboBox(["All Functions", "Selected Functions", "Call Graph"])
    scope_panel.add(scope_label)
    scope_panel.add(scope_combo)
    
    # Export button
    export_button = JButton("Export")
    
    top_panel.add(format_panel)
    top_panel.add(scope_panel)
    top_panel.add(export_button)
    
    # Text area for status
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(status_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == export_button:
                export_format = format_combo.getSelectedItem()
                export_scope = scope_combo.getSelectedItem()
                export_analysis_results(export_format, export_scope, status_area)
    
    listener = ButtonActionListener()
    export_button.addActionListener(listener)
    
    return panel


def create_advanced_panel():
    """Create panel for advanced analysis options"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with advanced options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Performance options
    perf_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    perf_label = JLabel("Performance Mode:")
    perf_combo = JComboBox(["Standard", "High Performance", "Incremental"])
    perf_panel.add(perf_label)
    perf_panel.add(perf_combo)
    
    # Decompiler options
    decompile_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    decompile_button = JButton("Analyze with Decompiler")
    decompile_panel.add(decompile_button)
    
    # Indirect call analysis
    indirect_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    indirect_button = JButton("Analyze Indirect Calls")
    indirect_panel.add(indirect_button)
    
    top_panel.add(perf_panel)
    top_panel.add(decompile_panel)
    top_panel.add(indirect_panel)
    
    # Text area for status
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(status_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == decompile_button:
                analyze_with_decompiler(status_area)
            elif event.getSource() == indirect_button:
                analyze_indirect_calls(status_area)
    
    listener = ButtonActionListener()
    decompile_button.addActionListener(listener)
    indirect_button.addActionListener(listener)
    
    return panel


def create_function_combo():
    """Create a combo box with function names"""
    
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))
    non_thunk_functions = [f for f in functions if not f.isThunk()]
    function_names = [f.getName() for f in non_thunk_functions]
    
    combo = JComboBox(function_names)
    combo.setPreferredSize(Dimension(200, 25))
    return combo


def refresh_function_combo(combo):
    """Refresh the function combo box with current functions"""
    
    function_manager = currentProgram.functionManager
    functions = list(function_manager.getFunctions(True))
    non_thunk_functions = [f for f in functions if not f.isThunk()]
    function_names = [f.getName() for f in non_thunk_functions]
    
    # Clear and repopulate combo
    combo.removeAllItems()
    for name in function_names:
        combo.addItem(name)
    
    if function_names:
        combo.setSelectedIndex(0)


def analyze_function(func_name, text_area):
    """Analyze a function and display results"""
    
    function_manager = currentProgram.functionManager
    function = find_function_by_name(function_manager, func_name)
    
    if not function:
        text_area.setText(f"Function {func_name} not found!")
        return
    
    # Gather function information
    func_info = []
    func_info.append(f"Function: {function.getName()}")
    func_info.append(f"Address: 0x{function.getEntryPoint()}")
    func_info.append(f"Size: {function.getBody().getNumAddresses()} bytes")
    func_info.append(f"External: {function.isExternal()}")
    func_info.append(f"Thunk: {function.isThunk()}")
    
    # Get function calls
    calls = []
    instr = function.getEntryPoint()
    end_addr = function.getBody().getMaxAddress()
    
    while instr and instr <= end_addr:
        flow_type = get_flow_type(currentProgram, instr)
        if flow_type and flow_type.isCall():
            called_addr = get_reference_target(instr, 0)
            if called_addr:
                called_function = function_manager.getFunctionAt(called_addr)
                if called_function:
                    calls.append(f"  -> {called_function.getName()} (0x{called_addr})")
                else:
                    calls.append(f"  -> 0x{called_addr}")
        instr = instr.add(1)
    
    if calls:
        func_info.append("\nFunction Calls:")
        func_info.extend(calls)
    else:
        func_info.append("\nNo function calls found.")
    
    # Display results
    text_area.setText("\n".join(func_info))


def show_decompiled_code(func_name, text_area):
    """Show decompiled code for a function"""
    
    try:
        from ghidra.app.decompiler import DecompInterface
        from ghidra.app.decompiler import DecompileOptions
        
        function_manager = currentProgram.functionManager
        function = find_function_by_name(function_manager, func_name)
        
        if not function:
            text_area.setText(f"Function {func_name} not found!")
            return
        
        # Initialize decompiler
        decompiler = DecompInterface()
        options = DecompileOptions()
        options.grabFromProgram(currentProgram)
        decompiler.setOptions(options)
        decompiler.openProgram(currentProgram)
        
        # Decompile function
        monitor = ConsoleTaskMonitor()
        results = decompiler.decompileFunction(function, 30, monitor)
        
        if results.decompileCompleted():
            c_code = results.getDecompiledFunction().getC()
            text_area.setText(f"=== Decompiled Code for {func_name} ===\n\n{c_code}")
        else:
            text_area.setText(f"Decompilation failed: {results.getErrorMessage()}")
        
        decompiler.dispose()
        
    except Exception as e:
        text_area.setText(f"Error decompiling function: {e}")


def generate_and_show_call_graph(text_area):
    """Generate and show call graph"""
    
    try:
        function_manager = currentProgram.functionManager
        functions = list(function_manager.getFunctions(True))
        non_thunk_functions = [f for f in functions if not f.isThunk()]
        
        # Create graph
        graph = AttributedGraph()
        function_vertices = {}
        
        # Add vertices
        for function in non_thunk_functions:
            func_name = function.getName()
            func_addr = function.getEntryPoint()
            vertex = AttributedVertex(f"{func_name}\n0x{func_addr}")
            vertex.setAttribute("functionName", func_name)
            vertex.setAttribute("address", str(func_addr))
            vertex.setVertexType(CallGraphType.EXTERNAL if function.isExternal() else CallGraphType.BODY)
            graph.addVertex(vertex)
            function_vertices[(func_name, func_addr)] = vertex
        
        # Add edges
        edge_id = 0
        for function in non_thunk_functions:
            func_name = function.getName()
            func_addr = function.getEntryPoint()
            source_key = (func_name, func_addr)
            
            if source_key not in function_vertices:
                continue
            
            source_vertex = function_vertices[source_key]
            
            # Find calls
            instr = function.getEntryPoint()
            end_addr = function.getBody().getMaxAddress()
            
            while instr and instr <= end_addr:
                flow_type = get_flow_type(currentProgram, instr)
                if flow_type and flow_type.isCall():
                    called_addr = get_reference_target(instr, 0)
                    if called_addr:
                        called_function = function_manager.getFunctionAt(called_addr)
                        if called_function and not called_function.isThunk():
                            target_key = (called_function.getName(), called_function.getEntryPoint())
                            if target_key in function_vertices:
                                target_vertex = function_vertices[target_key]
                                edge = AttributedEdge(f"edge_{edge_id}")
                                edge.setEdgeType(CallGraphType.UNCONDITIONAL_CALL)
                                edge.setAttribute("callAddress", str(instr))
                                graph.addEdge(source_vertex, target_vertex, edge)
                                edge_id += 1
                instr = instr.add(1)
        
        # Display graph
        graph_service = GraphService.getGraphService(currentProgram)
        if graph_service:
            display = graph_service.createGraphDisplay("Function Call Graph", CallGraphType())
            if display:
                display.setGraph(graph)
                display.setVisible(True)
                text_area.setText(f"Call graph generated with {graph.getVertexCount()} vertices and {graph.getEdgeCount()} edges.")
            else:
                text_area.setText("Failed to create graph display.")
        else:
            text_area.setText("Graph service not available.")
            
    except Exception as e:
        text_area.setText(f"Error generating call graph: {e}")


def find_and_display_paths(start_func, end_func, text_area):
    """Find and display paths between functions"""
    
    try:
        function_manager = currentProgram.functionManager
        
        # Build call graph
        call_graph = {}
        functions = list(function_manager.getFunctions(True))
        non_thunk_functions = [f for f in functions if not f.isThunk()]
        
        for function in non_thunk_functions:
            func_name = function.getName()
            call_graph[func_name] = []
            
            # Find calls
            instr = function.getEntryPoint()
            end_addr = function.getBody().getMaxAddress()
            
            while instr and instr <= end_addr:
                flow_type = get_flow_type(currentProgram, instr)
                if flow_type and flow_type.isCall():
                    called_addr = get_reference_target(instr, 0)
                    if called_addr:
                        called_function = function_manager.getFunctionAt(called_addr)
                        if called_function and not called_function.isThunk():
                            call_graph[func_name].append(called_function.getName())
                instr = instr.add(1)
        
        # Find paths
        def find_paths(graph, start, end, path=None):
            if path is None:
                path = []
            path = path + [start]
            if start == end:
                return [path]
            if start not in graph:
                return []
            paths = []
            for node in graph[start]:
                if node not in path:
                    new_paths = find_paths(graph, node, end, path)
                    for new_path in new_paths:
                        paths.append(new_path)
            return paths
        
        paths = find_paths(call_graph, start_func, end_func)
        
        if paths:
            path_text = [f"Found {len(paths)} path(s) from {start_func} to {end_func}:"]
            for i, path in enumerate(paths, 1):
                path_text.append(f"\nPath {i}:")
                path_text.append(" -> ".join(path))
            text_area.setText("\n".join(path_text))
        else:
            text_area.setText(f"No paths found from {start_func} to {end_func}!")
            
    except Exception as e:
        text_area.setText(f"Error finding paths: {e}")


def export_analysis_results(export_format, export_scope, text_area):
    """Export analysis results in specified format"""
    
    try:
        # Create file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Export Directory")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        
        if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
            return
        
        export_dir = chooser.getSelectedFile().getPath()
        program_name = currentProgram.name
        
        # Gather data
        function_manager = currentProgram.functionManager
        functions = list(function_manager.getFunctions(True))
        non_thunk_functions = [f for f in functions if not f.isThunk()]
        
        # Export based on format
        if export_format in ["JSON", "Both"]:
            # Export to JSON
            export_data = {
                "program": program_name,
                "functions": [],
                "calls": []
            }
            
            for function in non_thunk_functions:
                func_name = function.getName()
                func_addr = function.getEntryPoint()
                
                export_data["functions"].append({
                    "name": func_name,
                    "address": str(func_addr),
                    "isExternal": function.isExternal()
                })
                
                # Get calls
                instr = function.getEntryPoint()
                end_addr = function.getBody().getMaxAddress()
                
                while instr and instr <= end_addr:
                    flow_type = get_flow_type(currentProgram, instr)
                    if flow_type and flow_type.isCall():
                        called_addr = get_reference_target(instr, 0)
                        if called_addr:
                            called_function = function_manager.getFunctionAt(called_addr)
                            called_name = called_function.getName() if called_function else f"0x{called_addr}"
                            export_data["calls"].append({
                                "caller": func_name,
                                "callee": called_name,
                                "callAddress": str(instr)
                            })
                    instr = instr.add(1)
            
            json_file = os.path.join(export_dir, f"{program_name}_function_analysis.json")
            with open(json_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
        if export_format in ["CSV", "Both"]:
            # Export to CSV
            csv_file = os.path.join(export_dir, f"{program_name}_function_analysis.csv")
            with open(csv_file, 'w') as f:
                writer = csv.writer(f)
                writer.writerow(["Caller", "Callee", "Call Address"])
                
                for function in non_thunk_functions:
                    func_name = function.getName()
                    instr = function.getEntryPoint()
                    end_addr = function.getBody().getMaxAddress()
                    
                    while instr and instr <= end_addr:
                        flow_type = get_flow_type(currentProgram, instr)
                        if flow_type and flow_type.isCall():
                            called_addr = get_reference_target(instr, 0)
                            if called_addr:
                                called_function = function_manager.getFunctionAt(called_addr)
                                called_name = called_function.getName() if called_function else f"0x{called_addr}"
                                writer.writerow([func_name, called_name, str(instr)])
                        instr = instr.add(1)
        
        text_area.setText(f"Analysis results exported to {export_dir}")
        
    except Exception as e:
        text_area.setText(f"Error exporting results: {e}")


def export_call_graph(text_area):
    """Export call graph"""
    text_area.setText("Export call graph functionality not yet implemented.")


def analyze_with_decompiler(text_area):
    """Analyze functions with decompiler"""
    text_area.setText("Decompiler analysis functionality not yet implemented.")


def analyze_indirect_calls(text_area):
    """Analyze indirect calls"""
    text_area.setText("Indirect call analysis functionality not yet implemented.")


def find_function_by_name(function_manager, name):
    """Find a function by name"""
    for function in function_manager.getFunctions(True):
        if function.getName() == name:
            return function
    return None


def get_flow_type(program, addr):
    """Get flow type for an instruction"""
    instr = program.getListing().getInstructionAt(addr)
    if instr:
        return instr.getFlowType()
    return None


def get_reference_target(addr, ref_index):
    """Get reference target"""
    refs = getReferencesFrom(addr)
    if refs and ref_index < len(refs):
        return refs[ref_index].getToAddress()
    return None


# Run the interactive analyzer
if __name__ == "__main__":
    show_interactive_analyzer()
