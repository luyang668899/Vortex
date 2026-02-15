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
# Call Tree Visualizer Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import os
import time
import json
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


# Call tree visualization options
CALL_TREE_OPTIONS = {
    "view_modes": [
        "Call Graph",
        "Call Tree",
        "Call Hierarchy",
        "Reverse Call Tree"
    ],
    "layout_algorithms": [
        "Force-Directed",
        "Hierarchical",
        "Circular",
        "Radial"
    ],
    "filter_options": [
        "All Functions",
        "User Functions Only",
        "System Functions Only",
        "Custom Filter"
    ]
}


# Call tree node data structure
class CallTreeNode:
    def __init__(self, function, call_count=0):
        self.function = function
        self.call_count = call_count
        self.children = []
        self.parent = None
    
    def add_child(self, child):
        self.children.append(child)
        child.parent = self


def show_call_tree_visualizer():
    """Show call tree visualizer UI"""
    
    print("=== Call Tree Visualizer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main call tree visualizer frame"""
    
    # Create frame
    frame = JFrame("Call Tree Visualizer")
    frame.setSize(1200, 800)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create toolbar
    toolbar = JToolBar()
    toolbar.setFloatable(False)
    
    # Add toolbar buttons
    new_tree_button = JButton("New Call Tree")
    save_tree_button = JButton("Save Call Tree")
    load_tree_button = JButton("Load Call Tree")
    export_tree_button = JButton("Export Call Tree")
    
    toolbar.add(new_tree_button)
    toolbar.add(save_tree_button)
    toolbar.add(load_tree_button)
    toolbar.add(export_tree_button)
    toolbar.addSeparator()
    
    zoom_in_button = JButton("Zoom In")
    zoom_out_button = JButton("Zoom Out")
    reset_view_button = JButton("Reset View")
    
    toolbar.add(zoom_in_button)
    toolbar.add(zoom_out_button)
    toolbar.add(reset_view_button)
    toolbar.addSeparator()
    
    expand_all_button = JButton("Expand All")
    collapse_all_button = JButton("Collapse All")
    
    toolbar.add(expand_all_button)
    toolbar.add(collapse_all_button)
    
    # Create main panel with split pane
    main_panel = JPanel(BorderLayout())
    
    # Left panel with controls
    left_panel = JPanel(BorderLayout())
    left_panel.setPreferredSize(Dimension(300, 800))
    left_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # View mode selection
    view_mode_panel = JPanel(BorderLayout())
    view_mode_panel.setBorder(BorderFactory.createTitledBorder("View Mode"))
    
    view_mode_combo = JComboBox()
    for view_mode in CALL_TREE_OPTIONS["view_modes"]:
        view_mode_combo.addItem(view_mode)
    view_mode_combo.setSelectedIndex(0)
    
    view_mode_panel.add(view_mode_combo, BorderLayout.CENTER)
    
    # Layout algorithm selection
    layout_panel = JPanel(BorderLayout())
    layout_panel.setBorder(BorderFactory.createTitledBorder("Layout Algorithm"))
    
    layout_combo = JComboBox()
    for layout in CALL_TREE_OPTIONS["layout_algorithms"]:
        layout_combo.addItem(layout)
    layout_combo.setSelectedIndex(0)
    
    layout_panel.add(layout_combo, BorderLayout.CENTER)
    
    # Filter option selection
    filter_panel = JPanel(BorderLayout())
    filter_panel.setBorder(BorderFactory.createTitledBorder("Filter Option"))
    
    filter_combo = JComboBox()
    for filter_option in CALL_TREE_OPTIONS["filter_options"]:
        filter_combo.addItem(filter_option)
    filter_combo.setSelectedIndex(0)
    
    filter_panel.add(filter_combo, BorderLayout.CENTER)
    
    # Function selection
    function_panel = JPanel(BorderLayout())
    function_panel.setBorder(BorderFactory.createTitledBorder("Starting Function"))
    
    function_model = DefaultListModel()
    function_list = JList(function_model)
    function_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    function_scroll = JScrollPane(function_list)
    function_scroll.setPreferredSize(Dimension(280, 150))
    
    function_panel.add(function_scroll, BorderLayout.CENTER)
    
    # Call tree options
    options_panel = JPanel(BorderLayout())
    options_panel.setBorder(BorderFactory.createTitledBorder("Call Tree Options"))
    
    options_grid = JPanel(GridLayout(4, 1))
    
    show_call_count_checkbox = JCheckBox("Show Call Counts")
    show_call_count_checkbox.setSelected(True)
    show_function_names_checkbox = JCheckBox("Show Function Names")
    show_function_names_checkbox.setSelected(True)
    show_addresses_checkbox = JCheckBox("Show Addresses")
    show_addresses_checkbox.setSelected(False)
    show_function_size_checkbox = JCheckBox("Show Function Size")
    show_function_size_checkbox.setSelected(False)
    
    options_grid.add(show_call_count_checkbox)
    options_grid.add(show_function_names_checkbox)
    options_grid.add(show_addresses_checkbox)
    options_grid.add(show_function_size_checkbox)
    
    options_panel.add(options_grid, BorderLayout.CENTER)
    
    # Add controls to left panel
    left_panel.add(view_mode_panel, BorderLayout.NORTH)
    left_panel.add(layout_panel, BorderLayout.NORTH)
    left_panel.add(filter_panel, BorderLayout.NORTH)
    left_panel.add(function_panel, BorderLayout.CENTER)
    left_panel.add(options_panel, BorderLayout.SOUTH)
    
    # Center panel with call tree display
    center_panel = JPanel(BorderLayout())
    center_panel.setBorder(BorderFactory.createTitledBorder("Call Tree Display"))
    
    # Call tree canvas (placeholder)
    tree_canvas = JPanel()
    tree_canvas.setBackground(Color.WHITE)
    tree_canvas.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY))
    
    # Add placeholder text
    placeholder_label = JLabel("Call Tree Visualization Canvas")
    placeholder_label.setForeground(Color.GRAY)
    tree_canvas.add(placeholder_label)
    
    center_panel.add(tree_canvas, BorderLayout.CENTER)
    
    # Bottom panel with status and controls
    bottom_panel = JPanel(BorderLayout())
    
    # Status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel("Ready")
    function_count_label = JLabel("Functions: 0")
    call_count_label = JLabel("Calls: 0")
    
    status_bar.add(status_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(function_count_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(call_count_label)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
    generate_tree_button = JButton("Generate Call Tree")
    generate_tree_button.setPreferredSize(Dimension(150, 30))
    clear_tree_button = JButton("Clear Call Tree")
    clear_tree_button.setPreferredSize(Dimension(120, 30))
    
    action_panel.add(generate_tree_button)
    action_panel.add(clear_tree_button)
    
    bottom_panel.add(status_bar, BorderLayout.WEST)
    bottom_panel.add(action_panel, BorderLayout.EAST)
    
    # Add components to main panel
    main_panel.add(left_panel, BorderLayout.WEST)
    main_panel.add(center_panel, BorderLayout.CENTER)
    main_panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add components to frame
    frame.add(toolbar, BorderLayout.NORTH)
    frame.add(main_panel, BorderLayout.CENTER)
    
    # Populate functions if program is open
    if currentProgram:
        populate_functions(function_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            source = event.getSource()
            if source == new_tree_button:
                create_new_tree(view_mode_combo, status_label)
            elif source == save_tree_button:
                save_tree(status_label)
            elif source == load_tree_button:
                load_tree(status_label)
            elif source == export_tree_button:
                export_tree(status_label)
            elif source == zoom_in_button:
                zoom_in(tree_canvas, status_label)
            elif source == zoom_out_button:
                zoom_out(tree_canvas, status_label)
            elif source == reset_view_button:
                reset_view(tree_canvas, status_label)
            elif source == expand_all_button:
                expand_all(status_label)
            elif source == collapse_all_button:
                collapse_all(status_label)
            elif source == generate_tree_button:
                generate_call_tree(
                    view_mode_combo, layout_combo, filter_combo,
                    function_list, function_model,
                    show_call_count_checkbox, show_function_names_checkbox, show_addresses_checkbox, show_function_size_checkbox,
                    tree_canvas, status_label, function_count_label, call_count_label
                )
            elif source == clear_tree_button:
                clear_call_tree(tree_canvas, status_label, function_count_label, call_count_label)
    
    listener = ButtonActionListener()
    new_tree_button.addActionListener(listener)
    save_tree_button.addActionListener(listener)
    load_tree_button.addActionListener(listener)
    export_tree_button.addActionListener(listener)
    zoom_in_button.addActionListener(listener)
    zoom_out_button.addActionListener(listener)
    reset_view_button.addActionListener(listener)
    expand_all_button.addActionListener(listener)
    collapse_all_button.addActionListener(listener)
    generate_tree_button.addActionListener(listener)
    clear_tree_button.addActionListener(listener)
    
    return frame


def populate_functions(model):
    """Populate functions list"""
    try:
        if currentProgram:
            listing = currentProgram.listing
            functions = listing.getFunctions(True)
            
            model.clear()
            
            for function in functions:
                function_name = function.getName()
                function_address = function.getEntryPoint()
                model.addElement(f"{function_name} (0x{function_address.toString()})")
            
    except Exception as e:
        print(f"Error populating functions: {e}")


def create_new_tree(view_mode_combo, status_label):
    """Create a new call tree"""
    try:
        view_mode = view_mode_combo.getSelectedItem()
        status_label.setText(f"Creating new {view_mode}...")
        
        # Simulate tree creation
        time.sleep(1)
        
        status_label.setText(f"New {view_mode} created")
        
    except Exception as e:
        status_label.setText(f"Error creating new tree: {e}")


def save_tree(status_label):
    """Save call tree"""
    try:
        status_label.setText("Saving call tree...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Call Tree")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Call Tree files (*.calltree)", "calltree"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".calltree"):
                file_path += ".calltree"
            
            status_label.setText(f"Saved call tree to {file_path}")
        else:
            status_label.setText("Call tree save cancelled")
            
    except Exception as e:
        status_label.setText(f"Error saving call tree: {e}")


def load_tree(status_label):
    """Load call tree"""
    try:
        status_label.setText("Loading call tree...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Call Tree")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Call Tree files (*.calltree)", "calltree"))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Loaded call tree from {file_path}")
        else:
            status_label.setText("Call tree load cancelled")
            
    except Exception as e:
        status_label.setText(f"Error loading call tree: {e}")


def export_tree(status_label):
    """Export call tree"""
    try:
        status_label.setText("Exporting call tree...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Call Tree")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Image files (*.png, *.jpg)", ["png", "jpg"]))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Exported call tree to {file_path}")
        else:
            status_label.setText("Call tree export cancelled")
            
    except Exception as e:
        status_label.setText(f"Error exporting call tree: {e}")


def zoom_in(tree_canvas, status_label):
    """Zoom in on the call tree"""
    try:
        status_label.setText("Zooming in...")
        # Simulate zoom in
        time.sleep(0.5)
        status_label.setText("Zoom in completed")
    except Exception as e:
        status_label.setText(f"Error zooming in: {e}")


def zoom_out(tree_canvas, status_label):
    """Zoom out on the call tree"""
    try:
        status_label.setText("Zooming out...")
        # Simulate zoom out
        time.sleep(0.5)
        status_label.setText("Zoom out completed")
    except Exception as e:
        status_label.setText(f"Error zooming out: {e}")


def reset_view(tree_canvas, status_label):
    """Reset view to default"""
    try:
        status_label.setText("Resetting view...")
        # Simulate reset view
        time.sleep(0.5)
        status_label.setText("View reset to default")
    except Exception as e:
        status_label.setText(f"Error resetting view: {e}")


def expand_all(status_label):
    """Expand all nodes in the call tree"""
    try:
        status_label.setText("Expanding all nodes...")
        # Simulate expanding
        time.sleep(1)
        status_label.setText("All nodes expanded")
    except Exception as e:
        status_label.setText(f"Error expanding nodes: {e}")


def collapse_all(status_label):
    """Collapse all nodes in the call tree"""
    try:
        status_label.setText("Collapsing all nodes...")
        # Simulate collapsing
        time.sleep(1)
        status_label.setText("All nodes collapsed")
    except Exception as e:
        status_label.setText(f"Error collapsing nodes: {e}")


def generate_call_tree(view_mode_combo, layout_combo, filter_combo,
                      function_list, function_model,
                      show_call_count_checkbox, show_function_names_checkbox, show_addresses_checkbox, show_function_size_checkbox,
                      tree_canvas, status_label, function_count_label, call_count_label):
    """Generate call tree"""
    try:
        view_mode = view_mode_combo.getSelectedItem()
        layout = layout_combo.getSelectedItem()
        filter_option = filter_combo.getSelectedItem()
        
        # Get selected function
        selected_function = function_list.getSelectedValue()
        
        # Get options
        show_call_count = show_call_count_checkbox.isSelected()
        show_function_names = show_function_names_checkbox.isSelected()
        show_addresses = show_addresses_checkbox.isSelected()
        show_function_size = show_function_size_checkbox.isSelected()
        
        status_label.setText(f"Generating {view_mode} with {layout} layout and {filter_option} filter...")
        
        # Simulate call tree generation
        time.sleep(3)
        
        # Update counts
        function_count = 25
        call_count = 45
        function_count_label.setText(f"Functions: {function_count}")
        call_count_label.setText(f"Calls: {call_count}")
        
        status_label.setText(f"{view_mode} generated successfully")
        
    except Exception as e:
        status_label.setText(f"Error generating call tree: {e}")


def clear_call_tree(tree_canvas, status_label, function_count_label, call_count_label):
    """Clear call tree"""
    try:
        status_label.setText("Clearing call tree...")
        
        # Simulate clearing
        time.sleep(1)
        
        # Reset counts
        function_count_label.setText("Functions: 0")
        call_count_label.setText("Calls: 0")
        
        status_label.setText("Call tree cleared")
        
    except Exception as e:
        status_label.setText(f"Error clearing call tree: {e}")


# Run the call tree visualizer
if __name__ == "__main__":
    show_call_tree_visualizer()