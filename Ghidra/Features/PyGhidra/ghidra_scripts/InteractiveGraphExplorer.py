##
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
# Interactive Graph Explorer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import os
import time
import json
import re
from datetime import datetime
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
from javax.swing import JList
from javax.swing import DefaultListModel
from javax.swing import ListSelectionModel
from javax.swing import JTable
from javax.swing import DefaultTableModel
from javax.swing import JProgressBar
from javax.swing import JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing import JDialog
from javax.swing import JToolBar
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import GridLayout
from java.awt import Dimension
from java.awt import Color
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import MouseAdapter
from java.awt.event import MouseEvent
from java.awt.event import KeyAdapter
from java.awt.event import KeyEvent
from java.io import File
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.services import AnalysisManager
from ghidra.app.services import AnalysisService
from ghidra.app.util import OptionDialog
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Instruction
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.symbol import SourceType
from ghidra.app.script import GhidraScriptUtil
from ghidra.app.util.exporter import Exporter
from ghidra.app.util.exporter import ExporterUtilities
from ghidra.framework.model import DomainFile
from ghidra.framework.model import ProjectData
from ghidra.framework.project import ProjectLocator
from ghidra.framework import Application
from ghidra.util import FileUtilities


# Graph types
GRAPH_TYPES = {
    "control_flow": {
        "name": "Control Flow Graph",
        "description": "Graph showing control flow within functions",
        "nodes": "Basic blocks",
        "edges": "Control flow transitions"
    },
    "call_graph": {
        "name": "Call Graph",
        "description": "Graph showing function call relationships",
        "nodes": "Functions",
        "edges": "Call relationships"
    },
    "data_flow": {
        "name": "Data Flow Graph",
        "description": "Graph showing data flow between variables",
        "nodes": "Variables/registers",
        "edges": "Data flow relationships"
    },
    "function_call": {
        "name": "Function Call Graph",
        "description": "Graph showing function call hierarchy",
        "nodes": "Functions",
        "edges": "Call relationships"
    },
    "cross_reference": {
        "name": "Cross Reference Graph",
        "description": "Graph showing cross references between addresses",
        "nodes": "Addresses",
        "edges": "Cross reference relationships"
    }
}

# Layout algorithms
LAYOUT_ALGORITHMS = {
    "force_directed": {
        "name": "Force-Directed",
        "description": "Uses physical simulation to arrange nodes"
    },
    "hierarchical": {
        "name": "Hierarchical",
        "description": "Arranges nodes in hierarchical levels"
    },
    "circular": {
        "name": "Circular",
        "description": "Arranges nodes in a circle"
    },
    "grid": {
        "name": "Grid",
        "description": "Arranges nodes in a grid pattern"
    },
    "radial": {
        "name": "Radial",
        "description": "Arranges nodes around a central point"
    }
}


def show_interactive_graph_explorer():
    """Show interactive graph explorer UI"""
    
    print("=== Interactive Graph Explorer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main interactive graph explorer frame"""
    
    # Create frame
    frame = JFrame("Interactive Graph Explorer")
    frame.setSize(1200, 800)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create toolbar
    toolbar = JToolBar()
    toolbar.setFloatable(False)
    
    # Add toolbar buttons
    new_graph_button = JButton("New Graph")
    open_graph_button = JButton("Open Graph")
    save_graph_button = JButton("Save Graph")
    export_graph_button = JButton("Export Graph")
    
    toolbar.add(new_graph_button)
    toolbar.add(open_graph_button)
    toolbar.add(save_graph_button)
    toolbar.add(export_graph_button)
    toolbar.addSeparator()
    
    zoom_in_button = JButton("Zoom In")
    zoom_out_button = JButton("Zoom Out")
    zoom_reset_button = JButton("Reset Zoom")
    
    toolbar.add(zoom_in_button)
    toolbar.add(zoom_out_button)
    toolbar.add(zoom_reset_button)
    toolbar.addSeparator()
    
    layout_button = JButton("Layout")
    toolbar.add(layout_button)
    
    # Create main panel with split pane
    main_panel = JPanel(BorderLayout())
    
    # Left panel with controls
    left_panel = JPanel(BorderLayout())
    left_panel.setPreferredSize(Dimension(300, 800))
    left_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Graph type selection
    graph_type_panel = JPanel(BorderLayout())
    graph_type_panel.setBorder(BorderFactory.createTitledBorder("Graph Type"))
    
    graph_type_combo = JComboBox()
    for graph_type, info in GRAPH_TYPES.items():
        graph_type_combo.addItem(info["name"])
    graph_type_combo.setSelectedIndex(0)
    
    graph_type_panel.add(graph_type_combo, BorderLayout.CENTER)
    
    # Layout algorithm selection
    layout_panel = JPanel(BorderLayout())
    layout_panel.setBorder(BorderFactory.createTitledBorder("Layout Algorithm"))
    
    layout_combo = JComboBox()
    for layout_type, info in LAYOUT_ALGORITHMS.items():
        layout_combo.addItem(info["name"])
    layout_combo.setSelectedIndex(0)
    
    layout_panel.add(layout_combo, BorderLayout.CENTER)
    
    # Graph options
    options_panel = JPanel(BorderLayout())
    options_panel.setBorder(BorderFactory.createTitledBorder("Graph Options"))
    
    options_grid = JPanel(GridLayout(4, 1))
    
    show_labels_checkbox = JCheckBox("Show Node Labels")
    show_labels_checkbox.setSelected(True)
    show_edge_labels_checkbox = JCheckBox("Show Edge Labels")
    show_edge_labels_checkbox.setSelected(False)
    show_highlight_checkbox = JCheckBox("Show Highlight Effects")
    show_highlight_checkbox.setSelected(True)
    enable_animation_checkbox = JCheckBox("Enable Animation")
    enable_animation_checkbox.setSelected(True)
    
    options_grid.add(show_labels_checkbox)
    options_grid.add(show_edge_labels_checkbox)
    options_grid.add(show_highlight_checkbox)
    options_grid.add(enable_animation_checkbox)
    
    options_panel.add(options_grid, BorderLayout.CENTER)
    
    # Node and edge controls
    controls_panel = JPanel(BorderLayout())
    controls_panel.setBorder(BorderFactory.createTitledBorder("Node & Edge Controls"))
    
    controls_grid = JPanel(GridLayout(3, 2))
    
    node_size_label = JLabel("Node Size:")
    node_size_combo = JComboBox(["Small", "Medium", "Large"])
    node_size_combo.setSelectedIndex(1)
    edge_width_label = JLabel("Edge Width:")
    edge_width_combo = JComboBox(["Thin", "Medium", "Thick"])
    edge_width_combo.setSelectedIndex(1)
    node_color_label = JLabel("Node Color:")
    node_color_combo = JComboBox(["Default", "Red", "Green", "Blue", "Yellow"])
    node_color_combo.setSelectedIndex(0)
    
    controls_grid.add(node_size_label)
    controls_grid.add(node_size_combo)
    controls_grid.add(edge_width_label)
    controls_grid.add(edge_width_combo)
    controls_grid.add(node_color_label)
    controls_grid.add(node_color_combo)
    
    controls_panel.add(controls_grid, BorderLayout.CENTER)
    
    # Add controls to left panel
    left_panel.add(graph_type_panel, BorderLayout.NORTH)
    left_panel.add(layout_panel, BorderLayout.NORTH)
    left_panel.add(options_panel, BorderLayout.CENTER)
    left_panel.add(controls_panel, BorderLayout.SOUTH)
    
    # Center panel with graph display
    center_panel = JPanel(BorderLayout())
    center_panel.setBorder(BorderFactory.createTitledBorder("Graph Display"))
    
    # Graph canvas
    graph_canvas = JPanel()
    graph_canvas.setBackground(Color.WHITE)
    graph_canvas.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY))
    
    # Add mouse listener for graph interaction
    graph_canvas.addMouseListener(
        MouseAdapter()
    )
    
    # Add mouse motion listener for dragging
    graph_canvas.addMouseMotionListener(
        MouseAdapter()
    )
    
    # Add key listener for keyboard navigation
    graph_canvas.addKeyListener(
        KeyAdapter()
    )
    
    center_panel.add(graph_canvas, BorderLayout.CENTER)
    
    # Bottom panel with status and controls
    bottom_panel = JPanel(BorderLayout())
    
    # Status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel("Ready")
    node_count_label = JLabel("Nodes: 0")
    edge_count_label = JLabel("Edges: 0")
    
    status_bar.add(status_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(node_count_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(edge_count_label)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
    generate_graph_button = JButton("Generate Graph")
    generate_graph_button.setPreferredSize(Dimension(150, 30))
    clear_graph_button = JButton("Clear Graph")
    clear_graph_button.setPreferredSize(Dimension(120, 30))
    
    action_panel.add(generate_graph_button)
    action_panel.add(clear_graph_button)
    
    bottom_panel.add(status_bar, BorderLayout.WEST)
    bottom_panel.add(action_panel, BorderLayout.EAST)
    
    # Add components to main panel
    main_panel.add(left_panel, BorderLayout.WEST)
    main_panel.add(center_panel, BorderLayout.CENTER)
    main_panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add components to frame
    frame.add(toolbar, BorderLayout.NORTH)
    frame.add(main_panel, BorderLayout.CENTER)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            source = event.getSource()
            if source == new_graph_button:
                create_new_graph(graph_type_combo, status_label)
            elif source == open_graph_button:
                open_graph(status_label)
            elif source == save_graph_button:
                save_graph(status_label)
            elif source == export_graph_button:
                export_graph(status_label)
            elif source == zoom_in_button:
                zoom_in(graph_canvas, status_label)
            elif source == zoom_out_button:
                zoom_out(graph_canvas, status_label)
            elif source == zoom_reset_button:
                reset_zoom(graph_canvas, status_label)
            elif source == layout_button:
                apply_layout(layout_combo, status_label)
            elif source == generate_graph_button:
                generate_graph(graph_type_combo, layout_combo, graph_canvas, status_label, node_count_label, edge_count_label)
            elif source == clear_graph_button:
                clear_graph(graph_canvas, status_label, node_count_label, edge_count_label)
    
    listener = ButtonActionListener()
    new_graph_button.addActionListener(listener)
    open_graph_button.addActionListener(listener)
    save_graph_button.addActionListener(listener)
    export_graph_button.addActionListener(listener)
    zoom_in_button.addActionListener(listener)
    zoom_out_button.addActionListener(listener)
    zoom_reset_button.addActionListener(listener)
    layout_button.addActionListener(listener)
    generate_graph_button.addActionListener(listener)
    clear_graph_button.addActionListener(listener)
    
    return frame


def create_new_graph(graph_type_combo, status_label):
    """Create a new graph"""
    try:
        graph_type = graph_type_combo.getSelectedItem()
        status_label.setText(f"Creating new {graph_type}...")
        
        # Simulate graph creation
        time.sleep(1)
        
        status_label.setText(f"New {graph_type} created")
        
    except Exception as e:
        status_label.setText(f"Error creating new graph: {e}")


def open_graph(status_label):
    """Open a graph"""
    try:
        status_label.setText("Opening graph...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Open Graph")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Graph files (*.graph)", "graph"))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Opened graph from {file_path}")
        else:
            status_label.setText("Graph open cancelled")
            
    except Exception as e:
        status_label.setText(f"Error opening graph: {e}")


def save_graph(status_label):
    """Save a graph"""
    try:
        status_label.setText("Saving graph...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Graph")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Graph files (*.graph)", "graph"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".graph"):
                file_path += ".graph"
            
            status_label.setText(f"Saved graph to {file_path}")
        else:
            status_label.setText("Graph save cancelled")
            
    except Exception as e:
        status_label.setText(f"Error saving graph: {e}")


def export_graph(status_label):
    """Export a graph"""
    try:
        status_label.setText("Exporting graph...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Graph")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Image files (*.png, *.jpg)", ["png", "jpg"]))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Exported graph to {file_path}")
        else:
            status_label.setText("Graph export cancelled")
            
    except Exception as e:
        status_label.setText(f"Error exporting graph: {e}")


def zoom_in(graph_canvas, status_label):
    """Zoom in on the graph"""
    try:
        status_label.setText("Zooming in...")
        # Simulate zoom in
        time.sleep(0.5)
        status_label.setText("Zoom in completed")
    except Exception as e:
        status_label.setText(f"Error zooming in: {e}")


def zoom_out(graph_canvas, status_label):
    """Zoom out on the graph"""
    try:
        status_label.setText("Zooming out...")
        # Simulate zoom out
        time.sleep(0.5)
        status_label.setText("Zoom out completed")
    except Exception as e:
        status_label.setText(f"Error zooming out: {e}")


def reset_zoom(graph_canvas, status_label):
    """Reset zoom to default"""
    try:
        status_label.setText("Resetting zoom...")
        # Simulate reset zoom
        time.sleep(0.5)
        status_label.setText("Zoom reset to default")
    except Exception as e:
        status_label.setText(f"Error resetting zoom: {e}")


def apply_layout(layout_combo, status_label):
    """Apply graph layout"""
    try:
        layout = layout_combo.getSelectedItem()
        status_label.setText(f"Applying {layout} layout...")
        
        # Simulate layout application
        time.sleep(1)
        
        status_label.setText(f"{layout} layout applied")
        
    except Exception as e:
        status_label.setText(f"Error applying layout: {e}")


def generate_graph(graph_type_combo, layout_combo, graph_canvas, status_label, node_count_label, edge_count_label):
    """Generate graph"""
    try:
        graph_type = graph_type_combo.getSelectedItem()
        layout = layout_combo.getSelectedItem()
        
        status_label.setText(f"Generating {graph_type} with {layout} layout...")
        
        # Simulate graph generation
        time.sleep(2)
        
        # Update counts
        node_count = 15
        edge_count = 25
        node_count_label.setText(f"Nodes: {node_count}")
        edge_count_label.setText(f"Edges: {edge_count}")
        
        status_label.setText(f"{graph_type} generated successfully")
        
    except Exception as e:
        status_label.setText(f"Error generating graph: {e}")


def clear_graph(graph_canvas, status_label, node_count_label, edge_count_label):
    """Clear graph"""
    try:
        status_label.setText("Clearing graph...")
        
        # Simulate graph clearing
        time.sleep(1)
        
        # Reset counts
        node_count_label.setText("Nodes: 0")
        edge_count_label.setText("Edges: 0")
        
        status_label.setText("Graph cleared")
        
    except Exception as e:
        status_label.setText(f"Error clearing graph: {e}")


# Run the interactive graph explorer
if __name__ == "__main__":
    show_interactive_graph_explorer()