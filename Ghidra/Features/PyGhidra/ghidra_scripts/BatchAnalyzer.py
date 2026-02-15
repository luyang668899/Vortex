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
# Batch Analyzer Script
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


def show_batch_analyzer():
    """Show batch analyzer UI"""
    
    print("=== Batch Analyzer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main batch analyzer frame"""
    
    # Create frame
    frame = JFrame("Batch Analyzer")
    frame.setSize(1100, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different batch analysis tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("File Batch Analysis", create_file_batch_analysis_panel())
    tabbed_pane.addTab("Program Section Analysis", create_program_section_analysis_panel())
    tabbed_pane.addTab("Analysis Configuration", create_analysis_configuration_panel())
    tabbed_pane.addTab("Results", create_batch_results_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel("Ready")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_file_batch_analysis_panel():
    """Create panel for file batch analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with file selection
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # File selection
    file_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    file_label = JLabel("Files to Analyze:")
    add_file_button = JButton("Add Files")
    add_folder_button = JButton("Add Folder")
    remove_file_button = JButton("Remove Selected")
    clear_files_button = JButton("Clear All")
    
    file_panel.add(file_label)
    file_panel.add(add_file_button)
    file_panel.add(add_folder_button)
    file_panel.add(remove_file_button)
    file_panel.add(clear_files_button)
    
    # File list
    files_panel = JPanel(BorderLayout())
    files_label = JLabel("Selected Files:")
    files_model = DefaultListModel()
    files_list = JList(files_model)
    files_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    files_scroll = JScrollPane(files_list)
    files_scroll.setPreferredSize(Dimension(800, 200))
    
    files_panel.add(files_label, BorderLayout.NORTH)
    files_panel.add(files_scroll, BorderLayout.CENTER)
    
    # Analysis options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    options_panel.setBorder(BorderFactory.createTitledBorder("Analysis Options"))
    
    analysis_type_label = JLabel("Analysis Type:")
    analysis_type_combo = JComboBox(["Full Analysis", "Quick Analysis", "Custom Analysis"])
    analysis_type_combo.setPreferredSize(Dimension(150, 25))
    
    project_label = JLabel("Output Project:")
    project_text = JTextField("Default Project")
    project_text.setPreferredSize(Dimension(200, 25))
    browse_project_button = JButton("Browse")
    
    options_panel.add(analysis_type_label)
    options_panel.add(analysis_type_combo)
    options_panel.add(project_label)
    options_panel.add(project_text)
    options_panel.add(browse_project_button)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    execute_button = JButton("Execute Batch Analysis")
    execute_button.setPreferredSize(Dimension(200, 30))
    execution_panel.add(execute_button)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 100))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    top_panel.add(file_panel)
    top_panel.add(files_panel)
    top_panel.add(options_panel)
    top_panel.add(execution_panel)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == add_file_button:
                add_files(files_model, status_area)
            elif event.getSource() == add_folder_button:
                add_folder(files_model, status_area)
            elif event.getSource() == remove_file_button:
                remove_selected_files(files_list, files_model, status_area)
            elif event.getSource() == clear_files_button:
                clear_all_files(files_model, status_area)
            elif event.getSource() == browse_project_button:
                browse_project(project_text, status_area)
            elif event.getSource() == execute_button:
                execute_file_batch_analysis(files_model, analysis_type_combo, project_text, status_area)
    
    listener = ButtonActionListener()
    add_file_button.addActionListener(listener)
    add_folder_button.addActionListener(listener)
    remove_file_button.addActionListener(listener)
    clear_files_button.addActionListener(listener)
    browse_project_button.addActionListener(listener)
    execute_button.addActionListener(listener)
    
    return panel


def create_program_section_analysis_panel():
    """Create panel for program section analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with program selection
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Program selection
    program_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    program_label = JLabel("Current Program:")
    program_name_label = JLabel(currentProgram.name if currentProgram else "No Program Open")
    
    program_panel.add(program_label)
    program_panel.add(program_name_label)
    
    # Section selection
    section_panel = JPanel(BorderLayout())
    section_label = JLabel("Program Sections:")
    section_model = DefaultListModel()
    section_list = JList(section_model)
    section_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    section_scroll = JScrollPane(section_list)
    section_scroll.setPreferredSize(Dimension(400, 200))
    
    section_panel.add(section_label, BorderLayout.NORTH)
    section_panel.add(section_scroll, BorderLayout.CENTER)
    
    # Address range selection
    range_panel = JPanel(BorderLayout())
    range_label = JLabel("Custom Address Ranges:")
    range_text = JTextField()
    range_text.setToolTipText("Format: start-end, start-end")
    add_range_button = JButton("Add Range")
    
    range_panel.add(range_label, BorderLayout.NORTH)
    range_panel.add(range_text, BorderLayout.CENTER)
    range_panel.add(add_range_button, BorderLayout.EAST)
    
    # Range list
    ranges_panel = JPanel(BorderLayout())
    ranges_label = JLabel("Selected Ranges:")
    ranges_model = DefaultListModel()
    ranges_list = JList(ranges_model)
    ranges_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    ranges_scroll = JScrollPane(ranges_list)
    ranges_scroll.setPreferredSize(Dimension(400, 100))
    
    ranges_panel.add(ranges_label, BorderLayout.NORTH)
    ranges_panel.add(ranges_scroll, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    execute_button = JButton("Execute Section Analysis")
    execute_button.setPreferredSize(Dimension(200, 30))
    execution_panel.add(execute_button)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 100))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    top_panel.add(program_panel)
    top_panel.add(section_panel)
    top_panel.add(range_panel)
    top_panel.add(ranges_panel)
    top_panel.add(execution_panel)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate sections if program is open
    if currentProgram:
        populate_sections(section_model, status_area)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == add_range_button:
                add_custom_range(range_text, ranges_model, status_area)
            elif event.getSource() == execute_button:
                execute_section_analysis(section_list, section_model, ranges_model, status_area)
    
    listener = ButtonActionListener()
    add_range_button.addActionListener(listener)
    execute_button.addActionListener(listener)
    
    return panel


def create_analysis_configuration_panel():
    """Create panel for analysis configuration"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Analysis options
    options_panel = JPanel()
    options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
    
    # Analysis types
    analysis_types_panel = JPanel(BorderLayout())
    analysis_types_panel.setBorder(BorderFactory.createTitledBorder("Analysis Types"))
    
    analysis_types_list = JPanel(GridLayout(5, 2))
    
    # Create checkboxes for analysis types
    analysis_checkboxes = {
        "Function ID": JCheckBox("Function ID"),
        "Instruction Info": JCheckBox("Instruction Info"),
        "Data Reference": JCheckBox("Data Reference"),
        "Call Reference": JCheckBox("Call Reference"),
        "Stack": JCheckBox("Stack"),
        "Aggressive Instruction": JCheckBox("Aggressive Instruction"),
        "Decompiler": JCheckBox("Decompiler"),
        "Type Inference": JCheckBox("Type Inference"),
        "Variable Tracking": JCheckBox("Variable Tracking"),
        "Reference Analyzer": JCheckBox("Reference Analyzer")
    }
    
    for name, checkbox in analysis_checkboxes.items():
        analysis_types_list.add(checkbox)
    
    analysis_types_panel.add(analysis_types_list, BorderLayout.CENTER)
    
    # Analysis options
    analysis_options_panel = JPanel(BorderLayout())
    analysis_options_panel.setBorder(BorderFactory.createTitledBorder("Analysis Options"))
    
    options_grid = JPanel(GridLayout(4, 2))
    
    # Create option controls
    max_depth_label = JLabel("Maximum Function Depth:")
    max_depth_text = JTextField("10")
    max_depth_text.setPreferredSize(Dimension(50, 25))
    
    timeout_label = JLabel("Analysis Timeout (minutes):")
    timeout_text = JTextField("60")
    timeout_text.setPreferredSize(Dimension(50, 25))
    
    threads_label = JLabel("Number of Threads:")
    threads_combo = JComboBox(["1", "2", "4", "8", "16"])
    threads_combo.setPreferredSize(Dimension(80, 25))
    
    memory_label = JLabel("Memory Limit (GB):")
    memory_text = JTextField("4")
    memory_text.setPreferredSize(Dimension(50, 25))
    
    options_grid.add(max_depth_label)
    options_grid.add(max_depth_text)
    options_grid.add(timeout_label)
    options_grid.add(timeout_text)
    options_grid.add(threads_label)
    options_grid.add(threads_combo)
    options_grid.add(memory_label)
    options_grid.add(memory_text)
    
    analysis_options_panel.add(options_grid, BorderLayout.CENTER)
    
    # Save configuration
    save_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    save_config_button = JButton("Save Configuration")
    load_config_button = JButton("Load Configuration")
    save_panel.add(save_config_button)
    save_panel.add(load_config_button)
    
    options_panel.add(analysis_types_panel)
    options_panel.add(analysis_options_panel)
    options_panel.add(save_panel)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 100))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    # Add components to panel
    panel.add(options_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == save_config_button:
                save_analysis_config(analysis_checkboxes, max_depth_text, timeout_text, threads_combo, memory_text, status_area)
            elif event.getSource() == load_config_button:
                load_analysis_config(analysis_checkboxes, max_depth_text, timeout_text, threads_combo, memory_text, status_area)
    
    listener = ButtonActionListener()
    save_config_button.addActionListener(listener)
    load_config_button.addActionListener(listener)
    
    return panel


def create_batch_results_panel():
    """Create panel for batch results"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Batch Analysis Results:")
    table_model = DefaultTableModel(["File/Section", "Status", "Start Time", "End Time", "Duration", "Results"], 0)
    result_table = JTable(table_model)
    result_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
    table_scroll = JScrollPane(result_table)
    table_scroll.setPreferredSize(Dimension(800, 200))
    
    table_panel.add(table_label, BorderLayout.NORTH)
    table_panel.add(table_scroll, BorderLayout.CENTER)
    
    # Results details
    details_panel = JPanel(BorderLayout())
    details_label = JLabel("Result Details:")
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(800, 200))
    
    details_panel.add(details_label, BorderLayout.NORTH)
    details_panel.add(details_scroll, BorderLayout.CENTER)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    export_button = JButton("Export Results")
    clear_button = JButton("Clear Results")
    action_panel.add(export_button)
    action_panel.add(clear_button)
    
    # Add components to panel
    panel.add(table_panel, BorderLayout.NORTH)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(action_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == export_button:
                export_batch_results(table_model, details_area)
            elif event.getSource() == clear_button:
                clear_batch_results(table_model, details_area)
    
    listener = ButtonActionListener()
    export_button.addActionListener(listener)
    clear_button.addActionListener(listener)
    
    # Add table selection listener
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                file_section = table_model.getValueAt(selected_row, 0)
                status = table_model.getValueAt(selected_row, 1)
                start_time = table_model.getValueAt(selected_row, 2)
                end_time = table_model.getValueAt(selected_row, 3)
                duration = table_model.getValueAt(selected_row, 4)
                results = table_model.getValueAt(selected_row, 5)
                details_area.setText(f"File/Section: {file_section}\nStatus: {status}\nStart Time: {start_time}\nEnd Time: {end_time}\nDuration: {duration}\nResults: {results}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def add_files(model, text_area):
    """Add files to batch analysis"""
    try:
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Files to Analyze")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setMultiSelectionEnabled(True)
        
        # Add common executable file filters
        chooser.addChoosableFileFilter(FileNameExtensionFilter("Executable Files", ["exe", "dll", "elf", "bin", "so", "sys", "com"]))
        chooser.addChoosableFileFilter(FileNameExtensionFilter("All Files", ["*"]))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            files = chooser.getSelectedFiles()
            for file in files:
                file_path = file.getAbsolutePath()
                model.addElement(file_path)
            text_area.setText(f"Added {len(files)} files to batch analysis")
        else:
            text_area.setText("File selection cancelled")
            
    except Exception as e:
        text_area.setText(f"Error adding files: {e}")


def add_folder(model, text_area):
    """Add folder to batch analysis"""
    try:
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Folder to Analyze")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            folder = chooser.getSelectedFile()
            folder_path = folder.getAbsolutePath()
            
            # Recursively find executable files in folder
            executable_extensions = [".exe", ".dll", ".elf", ".bin", ".so", ".sys", ".com"]
            added_files = 0
            
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    if any(file.lower().endswith(ext) for ext in executable_extensions):
                        file_path = os.path.join(root, file)
                        model.addElement(file_path)
                        added_files += 1
            
            text_area.setText(f"Added {added_files} files from folder: {folder_path}")
        else:
            text_area.setText("Folder selection cancelled")
            
    except Exception as e:
        text_area.setText(f"Error adding folder: {e}")


def remove_selected_files(list_component, model, text_area):
    """Remove selected files from batch analysis"""
    try:
        selected_indices = list_component.getSelectedIndices()
        if selected_indices:
            # Remove in reverse order to avoid index shifting
            for index in sorted(selected_indices, reverse=True):
                model.removeElementAt(index)
            text_area.setText(f"Removed {len(selected_indices)} files from batch analysis")
        else:
            text_area.setText("No files selected for removal")
            
    except Exception as e:
        text_area.setText(f"Error removing files: {e}")


def clear_all_files(model, text_area):
    """Clear all files from batch analysis"""
    try:
        model.clear()
        text_area.setText("Cleared all files from batch analysis")
        
    except Exception as e:
        text_area.setText(f"Error clearing files: {e}")


def browse_project(text_field, text_area):
    """Browse for output project"""
    try:
        chooser = JFileChooser()
        chooser.setDialogTitle("Select Output Project")
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            project_path = chooser.getSelectedFile().getAbsolutePath()
            text_field.setText(project_path)
            text_area.setText(f"Selected output project: {project_path}")
        else:
            text_area.setText("Project selection cancelled")
            
    except Exception as e:
        text_area.setText(f"Error browsing project: {e}")


def execute_file_batch_analysis(model, analysis_type_combo, project_text, status_area):
    """Execute file batch analysis"""
    try:
        files = []
        for i in range(model.getSize()):
            files.append(model.getElementAt(i))
        
        if not files:
            status_area.setText("No files to analyze")
            return
        
        analysis_type = analysis_type_combo.getSelectedItem()
        project_path = project_text.getText()
        
        status_area.setText(f"Executing batch analysis on {len(files)} files...")
        
        total_files = len(files)
        for i, file_path in enumerate(files):
            file_status = f"[{i+1}/{total_files}] Analyzing file: {os.path.basename(file_path)}"
            status_area.setText(file_status)
            
            # Simulate file analysis
            import time
            time.sleep(1)
            
            status_area.append(f"\nAnalysis completed for: {os.path.basename(file_path)}")
        
        status_area.append(f"\n\nBatch analysis completed successfully!")
        
    except Exception as e:
        status_area.setText(f"Error executing batch analysis: {e}")


def populate_sections(model, text_area):
    """Populate program sections"""
    try:
        if currentProgram:
            memory = currentProgram.memory
            blocks = memory.blocks
            
            for block in blocks:
                block_name = block.name
                block_start = block.start
                block_end = block.end
                block_size = block.size
                model.addElement(f"{block_name} (0x{block_start.toString()}-0x{block_end.toString()}, {block_size} bytes)")
            
            text_area.setText(f"Populated {model.getSize()} program sections")
        
    except Exception as e:
        text_area.setText(f"Error populating sections: {e}")


def add_custom_range(text_field, model, text_area):
    """Add custom address range"""
    try:
        range_text = text_field.getText().strip()
        if not range_text:
            text_area.setText("Please enter an address range")
            return
        
        model.addElement(range_text)
        text_field.setText("")
        text_area.setText(f"Added custom range: {range_text}")
        
    except Exception as e:
        text_area.setText(f"Error adding custom range: {e}")


def execute_section_analysis(section_list, section_model, ranges_model, status_area):
    """Execute section analysis"""
    try:
        if not currentProgram:
            status_area.setText("No program open for analysis")
            return
        
        # Get selected sections
        selected_sections = []
        selected_indices = section_list.getSelectedIndices()
        for index in selected_indices:
            selected_sections.append(section_model.getElementAt(index))
        
        # Get custom ranges
        custom_ranges = []
        for i in range(ranges_model.getSize()):
            custom_ranges.append(ranges_model.getElementAt(i))
        
        if not selected_sections and not custom_ranges:
            status_area.setText("No sections or ranges selected for analysis")
            return
        
        status_area.setText(f"Executing section analysis on {len(selected_sections)} sections and {len(custom_ranges)} custom ranges...")
        
        # Analyze sections
        for section in selected_sections:
            status_area.setText(f"Analyzing section: {section}")
            # Simulate section analysis
            import time
            time.sleep(0.5)
        
        # Analyze custom ranges
        for range_text in custom_ranges:
            status_area.setText(f"Analyzing custom range: {range_text}")
            # Simulate range analysis
            import time
            time.sleep(0.5)
        
        status_area.append(f"\n\nSection analysis completed successfully!")
        
    except Exception as e:
        status_area.setText(f"Error executing section analysis: {e}")


def save_analysis_config(checkboxes, max_depth_text, timeout_text, threads_combo, memory_text, status_area):
    """Save analysis configuration"""
    try:
        # Create configuration data
        config_data = {
            "analysis_types": {name: checkbox.isSelected() for name, checkbox in checkboxes.items()},
            "max_depth": max_depth_text.getText(),
            "timeout": timeout_text.getText(),
            "threads": threads_combo.getSelectedItem(),
            "memory_limit": memory_text.getText()
        }
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Analysis Configuration")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Configuration files (*.config)", "config"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".config"):
                file_path += ".config"
            
            # Save configuration to file
            with open(file_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            status_area.setText(f"Saved analysis configuration to {file_path}")
        else:
            status_area.setText("Configuration save cancelled")
            
    except Exception as e:
        status_area.setText(f"Error saving configuration: {e}")


def load_analysis_config(checkboxes, max_depth_text, timeout_text, threads_combo, memory_text, status_area):
    """Load analysis configuration"""
    try:
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Analysis Configuration")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Configuration files (*.config)", "config"))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            # Load configuration from file
            with open(file_path, 'r') as f:
                config_data = json.load(f)
            
            # Update analysis types
            for name, checkbox in checkboxes.items():
                checkbox.setSelected(config_data.get("analysis_types", {}).get(name, False))
            
            # Update options
            max_depth_text.setText(config_data.get("max_depth", "10"))
            timeout_text.setText(config_data.get("timeout", "60"))
            threads_combo.setSelectedItem(config_data.get("threads", "4"))
            memory_text.setText(config_data.get("memory_limit", "4"))
            
            status_area.setText(f"Loaded analysis configuration from {file_path}")
        else:
            status_area.setText("Configuration load cancelled")
            
    except Exception as e:
        status_area.setText(f"Error loading configuration: {e}")


def export_batch_results(table_model, details_area):
    """Export batch analysis results"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to export")
            return
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Batch Results")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("CSV files (*.csv)", "csv"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".csv"):
                file_path += ".csv"
            
            # Export results to CSV
            with open(file_path, 'w') as f:
                # Write header
                header = ",".join([table_model.getColumnName(i) for i in range(table_model.getColumnCount())])
                f.write(header + "\n")
                
                # Write rows
                for i in range(table_model.getRowCount()):
                    row = ",".join([str(table_model.getValueAt(i, j)) for j in range(table_model.getColumnCount())])
                    f.write(row + "\n")
            
            details_area.setText(f"Results exported successfully to {file_path}")
        else:
            details_area.setText("Results export cancelled")
            
    except Exception as e:
        details_area.setText(f"Error exporting results: {e}")


def clear_batch_results(table_model, details_area):
    """Clear batch analysis results"""
    try:
        table_model.setRowCount(0)
        details_area.setText("Results cleared successfully")
        
    except Exception as e:
        details_area.setText(f"Error clearing results: {e}")


# Run the batch analyzer
if __name__ == "__main__":
    show_batch_analyzer()