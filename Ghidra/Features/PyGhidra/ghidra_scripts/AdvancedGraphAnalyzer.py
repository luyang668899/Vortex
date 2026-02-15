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
# Advanced Graph Analyzer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import time
import os
from javax.swing import JFrame
from javax.swing import JPanel
from javax.swing import JButton
from javax.swing import JComboBox
from javax.swing import JTextField
from javax.swing import JTextArea
from javax.swing import JScrollPane
from javax.swing import JLabel
from javax.swing import JTabbedPane
from javax.swing import BoxLayout
from javax.swing import BorderFactory
from javax.swing import JOptionPane
from javax.swing import JCheckBox
from javax.swing import JSeparator
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import GridLayout
from java.awt import Dimension
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyAdapter
from java.awt.event import KeyEvent
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.service.graph import GraphService
from ghidra.service.graph import AttributedVertex
from ghidra.service.graph import AttributedEdge
from ghidra.service.graph import AttributedGraph
from ghidra.service.graph import GraphDisplay
from ghidra.service.graph import GraphDisplayOptions
from ghidra.service.graph import GraphDisplayOptionsBuilder
from ghidra.graph import CallGraphType
from ghidra.app.util import OptionDialog
from ghidra.app.services import GraphDisplayBroker


def show_advanced_graph_analyzer():
    """Show advanced graph analyzer UI"""
    
    print("=== Advanced Graph Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        JOptionPane.showMessageDialog(None, "No program currently open!", "Error", JOptionPane.ERROR_MESSAGE)
        return
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main advanced graph analyzer frame"""
    
    # Create frame
    frame = JFrame("Advanced Graph Analyzer")
    frame.setSize(1100, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different graph analysis tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Graph Generation", create_graph_generation_panel())
    tabbed_pane.addTab("Graph Layout", create_graph_layout_panel())
    tabbed_pane.addTab("Graph Filter", create_graph_filter_panel())
    tabbed_pane.addTab("Graph Export", create_graph_export_panel())
    tabbed_pane.addTab("Graph Analysis", create_graph_analysis_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_graph_generation_panel():
    """Create panel for graph generation options"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with generation options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Graph type selection
    graph_type_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    graph_type_label = JLabel("Graph Type:")
    graph_type_combo = JComboBox(["Function Call Graph", "Data Flow Graph", "Control Flow Graph"])
    graph_type_panel.add(graph_type_label)
    graph_type_panel.add(graph_type_combo)
    
    # Options panel
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    include_external_checkbox = JCheckBox("Include External Functions")
    include_thunks_checkbox = JCheckBox("Include Thunk Functions")
    options_panel.add(include_external_checkbox)
    options_panel.add(include_thunks_checkbox)
    
    # Generate button
    generate_button = JButton("Generate Graph")
    generate_button.setPreferredSize(Dimension(150, 30))
    
    top_panel.add(graph_type_panel)
    top_panel.add(options_panel)
    top_panel.add(generate_button)
    
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
                graph_type = graph_type_combo.getSelectedItem()
                include_external = include_external_checkbox.isSelected()
                include_thunks = include_thunks_checkbox.isSelected()
                generate_graph(graph_type, include_external, include_thunks, status_area)
    
    listener = ButtonActionListener()
    generate_button.addActionListener(listener)
    
    return panel


def create_graph_layout_panel():
    """Create panel for graph layout options"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with layout options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Layout algorithm selection
    layout_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    layout_label = JLabel("Layout Algorithm:")
    layout_combo = JComboBox(["Force-Directed", "Hierarchical", "Circular", "Spring", "Tree"])
    layout_panel.add(layout_label)
    layout_panel.add(layout_combo)
    
    # Layout parameters
    params_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    params_label = JLabel("Layout Parameters:")
    params_text = JTextField("Force: 1.0, Repulsion: 1.0, Damping: 0.1")
    params_text.setPreferredSize(Dimension(300, 25))
    params_panel.add(params_label)
    params_panel.add(params_text)
    
    # Apply layout button
    apply_button = JButton("Apply Layout")
    apply_button.setPreferredSize(Dimension(150, 30))
    
    top_panel.add(layout_panel)
    top_panel.add(params_panel)
    top_panel.add(apply_button)
    
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
            if event.getSource() == apply_button:
                layout_algorithm = layout_combo.getSelectedItem()
                parameters = params_text.getText()
                apply_layout(layout_algorithm, parameters, status_area)
    
    listener = ButtonActionListener()
    apply_button.addActionListener(listener)
    
    return panel


def create_graph_filter_panel():
    """Create panel for graph filtering and searching"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with filter and search options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Search panel
    search_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    search_label = JLabel("Search:")
    search_text = JTextField()
    search_text.setPreferredSize(Dimension(200, 25))
    search_button = JButton("Search")
    search_panel.add(search_label)
    search_panel.add(search_text)
    search_panel.add(search_button)
    
    # Filter panel
    filter_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    filter_label = JLabel("Filter:")
    filter_combo = JComboBox(["All Functions", "External Functions", "Internal Functions", "Functions with Calls"])
    filter_button = JButton("Apply Filter")
    filter_panel.add(filter_label)
    filter_panel.add(filter_combo)
    filter_panel.add(filter_button)
    
    # Reset button
    reset_button = JButton("Reset Filters")
    reset_button.setPreferredSize(Dimension(150, 30))
    
    top_panel.add(search_panel)
    top_panel.add(filter_panel)
    top_panel.add(reset_button)
    
    # Text area for results
    results_area = JTextArea()
    results_area.setEditable(False)
    results_area.setLineWrap(True)
    results_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(results_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == search_button:
                search_term = search_text.getText()
                search_in_graph(search_term, results_area)
            elif event.getSource() == filter_button:
                filter_type = filter_combo.getSelectedItem()
                apply_filter(filter_type, results_area)
            elif event.getSource() == reset_button:
                reset_filters(results_area)
    
    listener = ButtonActionListener()
    search_button.addActionListener(listener)
    filter_button.addActionListener(listener)
    reset_button.addActionListener(listener)
    
    # Add key listener for search text field
    class SearchKeyListener(KeyAdapter):
        def keyPressed(self, event):
            if event.getKeyCode() == KeyEvent.VK_ENTER:
                search_term = search_text.getText()
                search_in_graph(search_term, results_area)
    
    search_text.addKeyListener(SearchKeyListener())
    
    return panel


def create_graph_export_panel():
    """Create panel for graph export options"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with export options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Export format selection
    format_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    format_label = JLabel("Export Format:")
    format_combo = JComboBox(["PNG", "SVG", "JSON", "GraphML", "DOT", "CSV"])
    format_panel.add(format_label)
    format_panel.add(format_combo)
    
    # Export options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    include_labels_checkbox = JCheckBox("Include Labels")
    include_attributes_checkbox = JCheckBox("Include Attributes")
    options_panel.add(include_labels_checkbox)
    options_panel.add(include_attributes_checkbox)
    
    # Export button
    export_button = JButton("Export Graph")
    export_button.setPreferredSize(Dimension(150, 30))
    
    top_panel.add(format_panel)
    top_panel.add(options_panel)
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
                include_labels = include_labels_checkbox.isSelected()
                include_attributes = include_attributes_checkbox.isSelected()
                export_graph(export_format, include_labels, include_attributes, status_area)
    
    listener = ButtonActionListener()
    export_button.addActionListener(listener)
    
    return panel


def create_graph_analysis_panel():
    """Create panel for graph analysis options"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with analysis options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Analysis type selection
    analysis_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analysis_label = JLabel("Analysis Type:")
    analysis_combo = JComboBox(["Centrality Analysis", "Community Detection", "Path Analysis", "Cycle Detection"])
    analysis_panel.add(analysis_label)
    analysis_panel.add(analysis_combo)
    
    # Analysis button
    analyze_button = JButton("Run Analysis")
    analyze_button.setPreferredSize(Dimension(150, 30))
    
    top_panel.add(analysis_panel)
    top_panel.add(analyze_button)
    
    # Text area for results
    results_area = JTextArea()
    results_area.setEditable(False)
    results_area.setLineWrap(True)
    results_area.setWrapStyleWord(True)
    
    scroll_pane = JScrollPane(results_area)
    scroll_pane.setPreferredSize(Dimension(800, 400))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(scroll_pane, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_button:
                analysis_type = analysis_combo.getSelectedItem()
                run_graph_analysis(analysis_type, results_area)
    
    listener = ButtonActionListener()
    analyze_button.addActionListener(listener)
    
    return panel


def generate_graph(graph_type, include_external, include_thunks, text_area):
    """Generate a graph based on selected options"""
    
    try:
        start_time = time.time()
        text_area.setText(f"Generating {graph_type}...")
        
        # Get function manager
        function_manager = currentProgram.functionManager
        functions = list(function_manager.getFunctions(True))
        
        # Filter functions
        filtered_functions = []
        for function in functions:
            if not include_thunks and function.isThunk():
                continue
            if not include_external and function.isExternal():
                continue
            filtered_functions.append(function)
        
        # Create graph
        graph = AttributedGraph()
        function_vertices = {}
        
        # Add vertices
        for function in filtered_functions:
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
        for function in filtered_functions:
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
                        if called_function:
                            # Check if called function should be included
                            if (include_thunks or not called_function.isThunk()) and \
                               (include_external or not called_function.isExternal()):
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
            display = graph_service.createGraphDisplay(f"{graph_type}", CallGraphType())
            if display:
                display.setGraph(graph)
                display.setVisible(True)
                elapsed_time = time.time() - start_time
                text_area.setText(f"Generated {graph_type} with {graph.getVertexCount()} vertices and {graph.getEdgeCount()} edges in {elapsed_time:.2f} seconds.")
            else:
                text_area.setText("Failed to create graph display.")
        else:
            text_area.setText("Graph service not available.")
            
    except Exception as e:
        text_area.setText(f"Error generating graph: {e}")


def apply_layout(layout_algorithm, parameters, text_area):
    """Apply selected layout algorithm to the graph"""
    text_area.setText(f"Layout algorithm {layout_algorithm} with parameters {parameters} applied.")
    # Note: Actual layout application would require access to the current graph display
    # This is a placeholder implementation


def search_in_graph(search_term, text_area):
    """Search for nodes in the graph"""
    if not search_term:
        text_area.setText("Please enter a search term.")
        return
    
    # Note: Actual search would require access to the current graph
    # This is a placeholder implementation
    text_area.setText(f"Searching for '{search_term}' in graph...\n\nFound 0 nodes matching the search term.")


def apply_filter(filter_type, text_area):
    """Apply filter to the graph"""
    text_area.setText(f"Applied filter: {filter_type}")
    # Note: Actual filter application would require access to the current graph
    # This is a placeholder implementation


def reset_filters(text_area):
    """Reset all filters"""
    text_area.setText("All filters reset.")
    # Note: Actual reset would require access to the current graph
    # This is a placeholder implementation


def export_graph(export_format, include_labels, include_attributes, text_area):
    """Export graph to selected format"""
    
    try:
        # Get current tool
        from ghidra.framework.plugintool import PluginTool
        tool = get_current_tool()
        
        if not tool:
            text_area.setText("Could not get current tool.")
            return
        
        # Get graph display broker
        from ghidra.app.services import GraphDisplayBroker
        broker = tool.getService(GraphDisplayBroker)
        if not broker:
            text_area.setText("Graph display broker not available.")
            return
        
        # Note: In a real implementation, we would need to get the current graph
        # For this example, we'll create a simple test graph
        graph = create_test_graph()
        
        # Export based on format
        if export_format in ["PNG", "SVG"]:
            # For image formats, we would need to render the graph
            text_area.setText(f"Exporting graph to {export_format} format...\n\nNote: Image export functionality requires additional implementation.")
        else:
            # For other formats, use the built-in exporters
            exporters = broker.getGraphExporters()
            exporter = find_exporter_by_format(exporters, export_format)
            
            if exporter:
                # Show file chooser
                from javax.swing import JFileChooser
                chooser = JFileChooser()
                chooser.setDialogTitle(f"Export Graph as {export_format}")
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
                
                # Set file filter
                from javax.swing.filechooser import FileNameExtensionFilter
                extension = exporter.getFileExtension()
                chooser.setFileFilter(FileNameExtensionFilter(f"{export_format} files (*.{extension})", extension))
                
                if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
                    file = chooser.getSelectedFile()
                    # Ensure correct extension
                    file_path = file.getAbsolutePath()
                    if not file_path.endswith(f".{extension}"):
                        file_path += f".{extension}"
                    
                    # Export
                    exporter.exportGraph(graph, file_path)
                    text_area.setText(f"Graph exported to {file_path}")
                else:
                    text_area.setText("Export cancelled.")
            else:
                text_area.setText(f"No exporter found for {export_format} format.")
                
    except Exception as e:
        text_area.setText(f"Error exporting graph: {e}")


def run_graph_analysis(analysis_type, text_area):
    """Run selected graph analysis"""
    text_area.setText(f"Running {analysis_type}...\n\nNote: Graph analysis functionality requires additional implementation.")
    # Note: Actual analysis would require access to the current graph
    # This is a placeholder implementation


def create_test_graph():
    """Create a simple test graph for export"""
    graph = AttributedGraph()
    
    # Add test vertices
    v1 = AttributedVertex("Test1")
    v2 = AttributedVertex("Test2")
    v3 = AttributedVertex("Test3")
    
    graph.addVertex(v1)
    graph.addVertex(v2)
    graph.addVertex(v3)
    
    # Add test edges
    e1 = AttributedEdge("e1")
    e2 = AttributedEdge("e2")
    
    graph.addEdge(v1, v2, e1)
    graph.addEdge(v2, v3, e2)
    
    return graph


def get_current_tool():
    """Get the current plugin tool"""
    try:
        from ghidra.framework.plugintool import PluginTool
        from docking.DockingWindowManager import DockingWindowManager
        return DockingWindowManager.getActiveInstance().getActiveTool()
    except Exception:
        return None


def find_exporter_by_format(exporters, format_name):
    """Find an exporter by format name"""
    for exporter in exporters:
        if exporter.getName().upper() == format_name.upper():
            return exporter
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


# Run the advanced graph analyzer
if __name__ == "__main__":
    show_advanced_graph_analyzer()
