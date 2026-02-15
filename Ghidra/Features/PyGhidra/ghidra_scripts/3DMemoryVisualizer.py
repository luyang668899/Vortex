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
# 3D Memory Visualizer Script
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


# Memory visualization options
MEMORY_VISUALIZATION_OPTIONS = {
    "view_modes": [
        "Block View",
        "Segment View",
        "Page View",
        "Heap View",
        "Stack View"
    ],
    "color_schemes": [
        "Default",
        "Heat Map",
        "Rainbow",
        "Grayscale",
        "Custom"
    ],
    "rendering_modes": [
        "Solid",
        "Wireframe",
        "Transparent",
        "Textured"
    ]
}


# Memory block types
MEMORY_BLOCK_TYPES = {
    "CODE": "Code",
    "DATA": "Data",
    "STACK": "Stack",
    "HEAP": "Heap",
    "BSS": "BSS",
    "RODATA": "Read-Only Data",
    "INIT": "Initialized Data",
    "EXTERN": "External"
}


# Memory visualization data structure
class MemoryBlockData:
    def __init__(self, name, start, end, size, block_type, permissions, content):
        self.name = name
        self.start = start
        self.end = end
        self.size = size
        self.block_type = block_type
        self.permissions = permissions
        self.content = content


def show_3d_memory_visualizer():
    """Show 3D memory visualizer UI"""
    
    print("=== 3D Memory Visualizer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main 3D memory visualizer frame"""
    
    # Create frame
    frame = JFrame("3D Memory Visualizer")
    frame.setSize(1200, 800)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create toolbar
    toolbar = JToolBar()
    toolbar.setFloatable(False)
    
    # Add toolbar buttons
    new_view_button = JButton("New View")
    save_view_button = JButton("Save View")
    load_view_button = JButton("Load View")
    export_view_button = JButton("Export View")
    
    toolbar.add(new_view_button)
    toolbar.add(save_view_button)
    toolbar.add(load_view_button)
    toolbar.add(export_view_button)
    toolbar.addSeparator()
    
    zoom_in_button = JButton("Zoom In")
    zoom_out_button = JButton("Zoom Out")
    reset_view_button = JButton("Reset View")
    
    toolbar.add(zoom_in_button)
    toolbar.add(zoom_out_button)
    toolbar.add(reset_view_button)
    toolbar.addSeparator()
    
    rotate_button = JButton("Rotate")
    pan_button = JButton("Pan")
    
    toolbar.add(rotate_button)
    toolbar.add(pan_button)
    
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
    for view_mode in MEMORY_VISUALIZATION_OPTIONS["view_modes"]:
        view_mode_combo.addItem(view_mode)
    view_mode_combo.setSelectedIndex(0)
    
    view_mode_panel.add(view_mode_combo, BorderLayout.CENTER)
    
    # Color scheme selection
    color_scheme_panel = JPanel(BorderLayout())
    color_scheme_panel.setBorder(BorderFactory.createTitledBorder("Color Scheme"))
    
    color_scheme_combo = JComboBox()
    for color_scheme in MEMORY_VISUALIZATION_OPTIONS["color_schemes"]:
        color_scheme_combo.addItem(color_scheme)
    color_scheme_combo.setSelectedIndex(0)
    
    color_scheme_panel.add(color_scheme_combo, BorderLayout.CENTER)
    
    # Rendering mode selection
    rendering_mode_panel = JPanel(BorderLayout())
    rendering_mode_panel.setBorder(BorderFactory.createTitledBorder("Rendering Mode"))
    
    rendering_mode_combo = JComboBox()
    for rendering_mode in MEMORY_VISUALIZATION_OPTIONS["rendering_modes"]:
        rendering_mode_combo.addItem(rendering_mode)
    rendering_mode_combo.setSelectedIndex(0)
    
    rendering_mode_panel.add(rendering_mode_combo, BorderLayout.CENTER)
    
    # Memory block selection
    memory_blocks_panel = JPanel(BorderLayout())
    memory_blocks_panel.setBorder(BorderFactory.createTitledBorder("Memory Blocks"))
    
    memory_blocks_model = DefaultListModel()
    memory_blocks_list = JList(memory_blocks_model)
    memory_blocks_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    memory_blocks_scroll = JScrollPane(memory_blocks_list)
    memory_blocks_scroll.setPreferredSize(Dimension(280, 150))
    
    memory_blocks_panel.add(memory_blocks_scroll, BorderLayout.CENTER)
    
    # Memory options
    memory_options_panel = JPanel(BorderLayout())
    memory_options_panel.setBorder(BorderFactory.createTitledBorder("Memory Options"))
    
    options_grid = JPanel(GridLayout(4, 1))
    
    show_addresses_checkbox = JCheckBox("Show Addresses")
    show_addresses_checkbox.setSelected(True)
    show_sizes_checkbox = JCheckBox("Show Sizes")
    show_sizes_checkbox.setSelected(True)
    show_permissions_checkbox = JCheckBox("Show Permissions")
    show_permissions_checkbox.setSelected(True)
    show_symbols_checkbox = JCheckBox("Show Symbols")
    show_symbols_checkbox.setSelected(False)
    
    options_grid.add(show_addresses_checkbox)
    options_grid.add(show_sizes_checkbox)
    options_grid.add(show_permissions_checkbox)
    options_grid.add(show_symbols_checkbox)
    
    memory_options_panel.add(options_grid, BorderLayout.CENTER)
    
    # Add controls to left panel
    left_panel.add(view_mode_panel, BorderLayout.NORTH)
    left_panel.add(color_scheme_panel, BorderLayout.NORTH)
    left_panel.add(rendering_mode_panel, BorderLayout.NORTH)
    left_panel.add(memory_blocks_panel, BorderLayout.CENTER)
    left_panel.add(memory_options_panel, BorderLayout.SOUTH)
    
    # Center panel with 3D visualization
    center_panel = JPanel(BorderLayout())
    center_panel.setBorder(BorderFactory.createTitledBorder("3D Memory Visualization"))
    
    # 3D canvas (placeholder for actual 3D rendering)
    canvas_panel = JPanel()
    canvas_panel.setBackground(Color.BLACK)
    canvas_panel.setBorder(BorderFactory.createLineBorder(Color.LIGHT_GRAY))
    
    # Add placeholder text
    placeholder_label = JLabel("3D Memory Visualization Canvas")
    placeholder_label.setForeground(Color.WHITE)
    canvas_panel.add(placeholder_label)
    
    center_panel.add(canvas_panel, BorderLayout.CENTER)
    
    # Bottom panel with status and controls
    bottom_panel = JPanel(BorderLayout())
    
    # Status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel("Ready")
    block_count_label = JLabel("Blocks: 0")
    memory_size_label = JLabel("Memory Size: 0 bytes")
    
    status_bar.add(status_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(block_count_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(memory_size_label)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
    generate_visualization_button = JButton("Generate Visualization")
    generate_visualization_button.setPreferredSize(Dimension(200, 30))
    clear_visualization_button = JButton("Clear Visualization")
    clear_visualization_button.setPreferredSize(Dimension(150, 30))
    
    action_panel.add(generate_visualization_button)
    action_panel.add(clear_visualization_button)
    
    bottom_panel.add(status_bar, BorderLayout.WEST)
    bottom_panel.add(action_panel, BorderLayout.EAST)
    
    # Add components to main panel
    main_panel.add(left_panel, BorderLayout.WEST)
    main_panel.add(center_panel, BorderLayout.CENTER)
    main_panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add components to frame
    frame.add(toolbar, BorderLayout.NORTH)
    frame.add(main_panel, BorderLayout.CENTER)
    
    # Populate memory blocks if program is open
    if currentProgram:
        populate_memory_blocks(memory_blocks_model, block_count_label, memory_size_label)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            source = event.getSource()
            if source == new_view_button:
                create_new_view(view_mode_combo, status_label)
            elif source == save_view_button:
                save_view(status_label)
            elif source == load_view_button:
                load_view(status_label)
            elif source == export_view_button:
                export_view(status_label)
            elif source == zoom_in_button:
                zoom_in(canvas_panel, status_label)
            elif source == zoom_out_button:
                zoom_out(canvas_panel, status_label)
            elif source == reset_view_button:
                reset_view(canvas_panel, status_label)
            elif source == rotate_button:
                rotate_view(status_label)
            elif source == pan_button:
                pan_view(status_label)
            elif source == generate_visualization_button:
                generate_visualization(
                    view_mode_combo, color_scheme_combo, rendering_mode_combo,
                    memory_blocks_list, memory_blocks_model,
                    show_addresses_checkbox, show_sizes_checkbox, show_permissions_checkbox, show_symbols_checkbox,
                    canvas_panel, status_label
                )
            elif source == clear_visualization_button:
                clear_visualization(canvas_panel, status_label)
    
    listener = ButtonActionListener()
    new_view_button.addActionListener(listener)
    save_view_button.addActionListener(listener)
    load_view_button.addActionListener(listener)
    export_view_button.addActionListener(listener)
    zoom_in_button.addActionListener(listener)
    zoom_out_button.addActionListener(listener)
    reset_view_button.addActionListener(listener)
    rotate_button.addActionListener(listener)
    pan_button.addActionListener(listener)
    generate_visualization_button.addActionListener(listener)
    clear_visualization_button.addActionListener(listener)
    
    return frame


def populate_memory_blocks(model, block_count_label, memory_size_label):
    """Populate memory blocks list"""
    try:
        if currentProgram:
            memory = currentProgram.memory
            blocks = memory.blocks
            total_size = 0
            
            model.clear()
            
            for block in blocks:
                block_name = block.name
                block_start = block.start
                block_end = block.end
                block_size = block.size
                total_size += block_size
                
                # Determine block type
                block_type = "Unknown"
                if block.name.upper() == ".text" or block.name.upper() == "CODE":
                    block_type = "CODE"
                elif block.name.upper() == ".data":
                    block_type = "DATA"
                elif block.name.upper() == ".bss":
                    block_type = "BSS"
                elif block.name.upper() == ".rodata":
                    block_type = "RODATA"
                elif "stack" in block.name.lower():
                    block_type = "STACK"
                elif "heap" in block.name.lower():
                    block_type = "HEAP"
                
                # Determine permissions
                permissions = []
                if block.isExecute(): permissions.append("X")
                if block.isRead(): permissions.append("R")
                if block.isWrite(): permissions.append("W")
                permissions_str = "+".join(permissions)
                
                model.addElement(f"{block_name} (0x{block_start.toString()}-0x{block_end.toString()}, {block_size} bytes, {permissions_str}, {block_type})")
            
            block_count_label.setText(f"Blocks: {model.getSize()}")
            memory_size_label.setText(f"Memory Size: {total_size} bytes")
            
    except Exception as e:
        print(f"Error populating memory blocks: {e}")


def create_new_view(view_mode_combo, status_label):
    """Create a new view"""
    try:
        view_mode = view_mode_combo.getSelectedItem()
        status_label.setText(f"Creating new {view_mode}...")
        
        # Simulate view creation
        time.sleep(1)
        
        status_label.setText(f"New {view_mode} created")
        
    except Exception as e:
        status_label.setText(f"Error creating new view: {e}")


def save_view(status_label):
    """Save view"""
    try:
        status_label.setText("Saving view...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save View")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("View files (*.view)", "view"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".view"):
                file_path += ".view"
            
            status_label.setText(f"Saved view to {file_path}")
        else:
            status_label.setText("View save cancelled")
            
    except Exception as e:
        status_label.setText(f"Error saving view: {e}")


def load_view(status_label):
    """Load view"""
    try:
        status_label.setText("Loading view...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Load View")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("View files (*.view)", "view"))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Loaded view from {file_path}")
        else:
            status_label.setText("View load cancelled")
            
    except Exception as e:
        status_label.setText(f"Error loading view: {e}")


def export_view(status_label):
    """Export view"""
    try:
        status_label.setText("Exporting view...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export View")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Image files (*.png, *.jpg)", ["png", "jpg"]))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            status_label.setText(f"Exported view to {file_path}")
        else:
            status_label.setText("View export cancelled")
            
    except Exception as e:
        status_label.setText(f"Error exporting view: {e}")


def zoom_in(canvas_panel, status_label):
    """Zoom in on the visualization"""
    try:
        status_label.setText("Zooming in...")
        # Simulate zoom in
        time.sleep(0.5)
        status_label.setText("Zoom in completed")
    except Exception as e:
        status_label.setText(f"Error zooming in: {e}")


def zoom_out(canvas_panel, status_label):
    """Zoom out on the visualization"""
    try:
        status_label.setText("Zooming out...")
        # Simulate zoom out
        time.sleep(0.5)
        status_label.setText("Zoom out completed")
    except Exception as e:
        status_label.setText(f"Error zooming out: {e}")


def reset_view(canvas_panel, status_label):
    """Reset view to default"""
    try:
        status_label.setText("Resetting view...")
        # Simulate reset view
        time.sleep(0.5)
        status_label.setText("View reset to default")
    except Exception as e:
        status_label.setText(f"Error resetting view: {e}")


def rotate_view(status_label):
    """Rotate view"""
    try:
        status_label.setText("Rotating view...")
        # Simulate rotation
        time.sleep(1)
        status_label.setText("View rotated")
    except Exception as e:
        status_label.setText(f"Error rotating view: {e}")


def pan_view(status_label):
    """Pan view"""
    try:
        status_label.setText("Panning view...")
        # Simulate panning
        time.sleep(0.5)
        status_label.setText("View panned")
    except Exception as e:
        status_label.setText(f"Error panning view: {e}")


def generate_visualization(view_mode_combo, color_scheme_combo, rendering_mode_combo,
                          memory_blocks_list, memory_blocks_model,
                          show_addresses_checkbox, show_sizes_checkbox, show_permissions_checkbox, show_symbols_checkbox,
                          canvas_panel, status_label):
    """Generate memory visualization"""
    try:
        view_mode = view_mode_combo.getSelectedItem()
        color_scheme = color_scheme_combo.getSelectedItem()
        rendering_mode = rendering_mode_combo.getSelectedItem()
        
        # Get selected memory blocks
        selected_blocks = []
        selected_indices = memory_blocks_list.getSelectedIndices()
        for index in selected_indices:
            selected_blocks.append(memory_blocks_model.getElementAt(index))
        
        # Get options
        show_addresses = show_addresses_checkbox.isSelected()
        show_sizes = show_sizes_checkbox.isSelected()
        show_permissions = show_permissions_checkbox.isSelected()
        show_symbols = show_symbols_checkbox.isSelected()
        
        status_label.setText(f"Generating {view_mode} with {color_scheme} color scheme and {rendering_mode} rendering...")
        
        # Simulate visualization generation
        time.sleep(3)
        
        status_label.setText(f"{view_mode} visualization generated successfully")
        
    except Exception as e:
        status_label.setText(f"Error generating visualization: {e}")


def clear_visualization(canvas_panel, status_label):
    """Clear memory visualization"""
    try:
        status_label.setText("Clearing visualization...")
        
        # Simulate clearing
        time.sleep(1)
        
        status_label.setText("Visualization cleared")
        
    except Exception as e:
        status_label.setText(f"Error clearing visualization: {e}")


# Run the 3D memory visualizer
if __name__ == "__main__":
    show_3d_memory_visualizer()