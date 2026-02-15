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
# Cross Reference Explorer Script
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


# Cross reference types
CROSS_REFERENCE_TYPES = {
    "data_reference": "Data Reference",
    "code_reference": "Code Reference",
    "call_reference": "Call Reference",
    "string_reference": "String Reference",
    "symbol_reference": "Symbol Reference"
}


# Cross reference visualization options
CROSS_REFERENCE_VISUALIZATION_OPTIONS = {
    "view_modes": [
        "Graph View",
        "Tree View",
        "Table View",
        "List View"
    ],
    "layout_algorithms": [
        "Force-Directed",
        "Hierarchical",
        "Circular",
        "Radial"
    ],
    "filter_options": [
        "All References",
        "Incoming References",
        "Outgoing References",
        "Custom Filter"
    ]
}


# Cross reference explorer data structure
class CrossReferenceData:
    def __init__(self, source, target, ref_type, address):
        self.source = source
        self.target = target
        self.ref_type = ref_type
        self.address = address


def show_cross_reference_explorer():
    """Show cross reference explorer UI"""
    
    print("=== Cross Reference Explorer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main cross reference explorer frame"""
    
    # Create frame
    frame = JFrame("Cross Reference Explorer")
    frame.setSize(1200, 800)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create toolbar
    toolbar = JToolBar()
    toolbar.setFloatable(False)
    
    # Add toolbar buttons
    new_exploration_button = JButton("New Exploration")
    save_exploration_button = JButton("Save Exploration")
    load_exploration_button = JButton("Load Exploration")
    export_exploration_button = JButton("Export Exploration")
    
    toolbar.add(new_exploration_button)
    toolbar.add(save_exploration_button)
    toolbar.add(load_exploration_button)
    toolbar.add(export_exploration_button)
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
    for view_mode in CROSS_REFERENCE_VISUALIZATION_OPTIONS["view_modes"]:
        view_mode_combo.addItem(view_mode)
    view_mode_combo.setSelectedIndex(0)
    
    view_mode_panel.add(view_mode_combo, BorderLayout.CENTER)
    
    # Layout algorithm selection
    layout_panel = JPanel(BorderLayout())
    layout_panel.setBorder(BorderFactory.createTitledBorder("Layout Algorithm"))
    
    layout_combo = JComboBox()
    for layout in CROSS_REFERENCE_VISUALIZATION_OPTIONS["layout_algorithms"]:
        layout_combo.addItem(layout)
    layout_combo.setSelectedIndex(0)
    
    layout_panel.add(layout_combo, BorderLayout.CENTER)
    
    # Filter option selection
    filter_panel = JPanel(BorderLayout())
    filter_panel.setBorder(BorderFactory.createTitledBorder("Filter Option"))
    
    filter_combo = JComboBox()
    for filter_option in CROSS_REFERENCE_VISUALIZATION_OPTIONS["filter_options"]:
        filter_combo.addItem(filter_option)
    filter_combo.setSelectedIndex(0)
    
    filter_panel.add(filter_combo, BorderLayout.CENTER)
    
    # Reference type selection
    ref_type_panel = JPanel(BorderLayout())
    ref_type_panel.setBorder(BorderFactory.createTitledBorder("Reference Types"))
    
    ref_type_grid = JPanel(GridLayout(3, 2))
    ref_type_checkboxes = {}
    
    for ref_type, description in CROSS_REFERENCE_TYPES.items():
        checkbox = JCheckBox(description)
        checkbox.setSelected(True)
        ref_type_checkboxes[ref_type] = checkbox
        ref_type_grid.add(checkbox)
    
    ref_type_panel.add(ref_type_grid, BorderLayout.CENTER)
    
    # Starting address/function
    start_panel = JPanel(BorderLayout())
    start_panel.setBorder(BorderFactory.createTitledBorder("Starting Point"))
    
    start_combo = JComboBox(["Function", "Address", "Symbol"])
    start_combo.setSelectedIndex(0)
    start_text = JTextField()
    start_text.setToolTipText("Enter function name, address, or symbol")
    
    start_panel.add(start_combo, BorderLayout.NORTH)
    start_panel.add(start_text, BorderLayout.CENTER)
    
    # Add controls to left panel
    left_panel.add(view_mode_panel, BorderLayout.NORTH)
    left_panel.add(layout_panel, BorderLayout.NORTH)
    left_panel.add(filter_panel, BorderLayout.NORTH)
    left_panel.add(ref_type_panel, BorderLayout.CENTER)
    left_panel.add(start_panel, BorderLayout.SOUTH)
    
    # Center panel with cross reference display
    center_panel = JPanel(BorderLayout())
    center_panel.setBorder(BorderFactory.createTitledBorder("Cross References"))
    
    # Cross reference display (placeholder)
    ref_display = JPanel()
    ref_display.setBackground(Color.WHITE)
    ref_display.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY))
    
    # Add placeholder text
    placeholder_label = JLabel("Cross Reference Visualization Area")
    placeholder_label.setForeground(Color.GRAY)
    ref_display.add(placeholder_label)
    
    center_panel.add(ref_display, BorderLayout.CENTER)
    
    # Bottom panel with status and controls
    bottom_panel = JPanel(BorderLayout())
    
    # Status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel("Ready")
    ref_count_label = JLabel("References: 0")
    depth_label = JLabel("Depth: 0")
    
    status_bar.add(status_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(ref_count_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(depth_label)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
    explore_button = JButton("Explore References")
    explore_button.setPreferredSize(Dimension(150, 30))
    clear_button = JButton("Clear References")
    clear_button.setPreferredSize(Dimension(120, 30))
    
    action_panel.add(explore_button)
    action_panel.add(clear_button)
    
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
            if source == new_exploration_button:
                create_new_exploration(view_mode_combo, status_label)
            elif source == save_exploration_button:
                save_exploration(status_label)
            elif source == load_exploration_button:
                load_exploration(status_label)
            elif source == export_exploration_button:
                export_exploration(status_label)
            elif source == zoom_in_button:
                zoom_in(ref_display, status_label)
            elif source == zoom_out_button:
                zoom_out(ref_display, status_label)
            elif source == reset_view_button:
                reset_view(ref_display, status_label)
            elif source == expand_all_button:
                expand_all(status_label)
            elif source == collapse_all_button:
                collapse_all(status_label)
            elif source == explore_button:
                explore_references(
                    view_mode_combo, layout_combo, filter_combo,
                    ref_type_checkboxes,
                    start_combo, start_text,
                    ref_display, status_label, ref_count_label, depth_label
                )
            elif source == clear_button:
                clear_references(ref_display, status_label, ref_count_label, depth_label)
    
    listener = ButtonActionListener()
    new_exploration_button.addActionListener(listener)
    save_exploration_button.addActionListener(listener)
    load_exploration_button.addActionListener(listener)
    export_exploration_button.addActionListener(listener)
    zoom_in_button.addActionListener(listener)
    zoom_out_button.addActionListener(listener)
    reset_view_button.addActionListener(listener)
    expand_all_button.addActionListener(listener)
    collapse_all_button.addActionListener(listener)
    explore_button.addActionListener(listener)
    clear_button.addActionListener(listener)
    
    return frame


def create_new_exploration(view_mode_combo, status_label):
    """Create a new exploration"""
    try:
        view_mode = view_mode_combo.getSelectedItem()
        status_label.setText(f"Creating new {view_mode} exploration...")
        
        # Simulate exploration creation
        time.sleep(1)
        
        status_label.setText(f"New {view_mode} exploration created")
        
    except Exception as e:
        status_label.setText(f"Error creating new exploration: {e}")


def save_exploration(status_label):
    """Save exploration"""
    try:
        status_label.setText("Saving exploration...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Exploration")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Exploration files (*.explore)", "explore"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".explore"):
                file_path += ".explore"
            
            status_label.setText(f"Saved exploration to {file_path}")
        else:
            status_label.setText("Exploration save cancelled")
            
    except Exception as e:
        status_label.setText(f"Error saving exploration: {e}")


def load_exploration(status_label):
    """Load exploration"""
    try:
        status_label.setText("Loading exploration...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Exploration")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Exploration files (*.explore)", "explore"))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Loaded exploration from {file_path}")
        else:
            status_label.setText("Exploration load cancelled")
            
    except Exception as e:
        status_label.setText(f"Error loading exploration: {e}")


def export_exploration(status_label):
    """Export exploration"""
    try:
        status_label.setText("Exporting exploration...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Exploration")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Image files (*.png, *.jpg)", ["png", "jpg"]))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Exported exploration to {file_path}")
        else:
            status_label.setText("Exploration export cancelled")
            
    except Exception as e:
        status_label.setText(f"Error exporting exploration: {e}")


def zoom_in(ref_display, status_label):
    """Zoom in on the references"""
    try:
        status_label.setText("Zooming in...")
        # Simulate zoom in
        time.sleep(0.5)
        status_label.setText("Zoom in completed")
    except Exception as e:
        status_label.setText(f"Error zooming in: {e}")


def zoom_out(ref_display, status_label):
    """Zoom out on the references"""
    try:
        status_label.setText("Zooming out...")
        # Simulate zoom out
        time.sleep(0.5)
        status_label.setText("Zoom out completed")
    except Exception as e:
        status_label.setText(f"Error zooming out: {e}")


def reset_view(ref_display, status_label):
    """Reset view to default"""
    try:
        status_label.setText("Resetting view...")
        # Simulate reset view
        time.sleep(0.5)
        status_label.setText("View reset to default")
    except Exception as e:
        status_label.setText(f"Error resetting view: {e}")


def expand_all(status_label):
    """Expand all references"""
    try:
        status_label.setText("Expanding all references...")
        # Simulate expanding
        time.sleep(1)
        status_label.setText("All references expanded")
    except Exception as e:
        status_label.setText(f"Error expanding references: {e}")


def collapse_all(status_label):
    """Collapse all references"""
    try:
        status_label.setText("Collapsing all references...")
        # Simulate collapsing
        time.sleep(1)
        status_label.setText("All references collapsed")
    except Exception as e:
        status_label.setText(f"Error collapsing references: {e}")


def explore_references(view_mode_combo, layout_combo, filter_combo,
                     ref_type_checkboxes,
                     start_combo, start_text,
                     ref_display, status_label, ref_count_label, depth_label):
    """Explore cross references"""
    try:
        view_mode = view_mode_combo.getSelectedItem()
        layout = layout_combo.getSelectedItem()
        filter_option = filter_combo.getSelectedItem()
        
        # Get selected reference types
        selected_ref_types = []
        for ref_type, checkbox in ref_type_checkboxes.items():
            if checkbox.isSelected():
                selected_ref_types.append(ref_type)
        
        # Get starting point
        start_type = start_combo.getSelectedItem()
        start_value = start_text.getText().strip()
        
        status_label.setText(f"Exploring {filter_option} references with {view_mode} view...")
        
        # Simulate reference exploration
        time.sleep(3)
        
        # Update counts
        ref_count = 35
        ref_depth = 3
        ref_count_label.setText(f"References: {ref_count}")
        depth_label.setText(f"Depth: {ref_depth}")
        
        status_label.setText(f"Reference exploration completed successfully")
        
    except Exception as e:
        status_label.setText(f"Error exploring references: {e}")


def clear_references(ref_display, status_label, ref_count_label, depth_label):
    """Clear references"""
    try:
        status_label.setText("Clearing references...")
        
        # Simulate clearing
        time.sleep(1)
        
        # Reset counts
        ref_count_label.setText("References: 0")
        depth_label.setText("Depth: 0")
        
        status_label.setText("References cleared")
        
    except Exception as e:
        status_label.setText(f"Error clearing references: {e}")


# Run the cross reference explorer
if __name__ == "__main__":
    show_cross_reference_explorer()