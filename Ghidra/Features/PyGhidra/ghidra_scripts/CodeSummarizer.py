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
# Code Summarizer Script
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


# Code summarization options
CODE_SUMMARIZATION_OPTIONS = {
    "summary_types": [
        "Function Summary",
        "Code Block Summary",
        "File Summary",
        "Module Summary"
    ],
    "detail_levels": [
        "Basic",
        "Detailed",
        "Comprehensive"
    ],
    "output_formats": [
        "Plain Text",
        "Markdown",
        "HTML",
        "JSON"
    ]
}


# Code feature categories
CODE_FEATURE_CATEGORIES = {
    "control_flow": "Control Flow",
    "data_flow": "Data Flow",
    "api_calls": "API Calls",
    "memory_operations": "Memory Operations",
    "string_operations": "String Operations",
    "mathematical_operations": "Mathematical Operations",
    "error_handling": "Error Handling",
    "security_features": "Security Features"
}


def show_code_summarizer():
    """Show code summarizer UI"""
    
    print("=== Code Summarizer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main code summarizer frame"""
    
    # Create frame
    frame = JFrame("Code Summarizer")
    frame.setSize(1200, 800)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create toolbar
    toolbar = JToolBar()
    toolbar.setFloatable(False)
    
    # Add toolbar buttons
    new_summary_button = JButton("New Summary")
    save_summary_button = JButton("Save Summary")
    load_summary_button = JButton("Load Summary")
    export_summary_button = JButton("Export Summary")
    
    toolbar.add(new_summary_button)
    toolbar.add(save_summary_button)
    toolbar.add(load_summary_button)
    toolbar.add(export_summary_button)
    toolbar.addSeparator()
    
    generate_all_button = JButton("Generate All")
    clear_all_button = JButton("Clear All")
    
    toolbar.add(generate_all_button)
    toolbar.add(clear_all_button)
    
    # Create main panel with split pane
    main_panel = JPanel(BorderLayout())
    
    # Left panel with controls
    left_panel = JPanel(BorderLayout())
    left_panel.setPreferredSize(Dimension(300, 800))
    left_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Summary type selection
    summary_type_panel = JPanel(BorderLayout())
    summary_type_panel.setBorder(BorderFactory.createTitledBorder("Summary Type"))
    
    summary_type_combo = JComboBox()
    for summary_type in CODE_SUMMARIZATION_OPTIONS["summary_types"]:
        summary_type_combo.addItem(summary_type)
    summary_type_combo.setSelectedIndex(0)
    
    summary_type_panel.add(summary_type_combo, BorderLayout.CENTER)
    
    # Detail level selection
    detail_level_panel = JPanel(BorderLayout())
    detail_level_panel.setBorder(BorderFactory.createTitledBorder("Detail Level"))
    
    detail_level_combo = JComboBox()
    for detail_level in CODE_SUMMARIZATION_OPTIONS["detail_levels"]:
        detail_level_combo.addItem(detail_level)
    detail_level_combo.setSelectedIndex(0)
    
    detail_level_panel.add(detail_level_combo, BorderLayout.CENTER)
    
    # Output format selection
    output_format_panel = JPanel(BorderLayout())
    output_format_panel.setBorder(BorderFactory.createTitledBorder("Output Format"))
    
    output_format_combo = JComboBox()
    for output_format in CODE_SUMMARIZATION_OPTIONS["output_formats"]:
        output_format_combo.addItem(output_format)
    output_format_combo.setSelectedIndex(0)
    
    output_format_panel.add(output_format_combo, BorderLayout.CENTER)
    
    # Function selection
    function_panel = JPanel(BorderLayout())
    function_panel.setBorder(BorderFactory.createTitledBorder("Function"))
    
    function_model = DefaultListModel()
    function_list = JList(function_model)
    function_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    function_scroll = JScrollPane(function_list)
    function_scroll.setPreferredSize(Dimension(280, 150))
    
    function_panel.add(function_scroll, BorderLayout.CENTER)
    
    # Code features to include
    features_panel = JPanel(BorderLayout())
    features_panel.setBorder(BorderFactory.createTitledBorder("Code Features to Include"))
    
    features_grid = JPanel(GridLayout(4, 2))
    feature_checkboxes = {}
    
    for feature, description in CODE_FEATURE_CATEGORIES.items():
        checkbox = JCheckBox(description)
        checkbox.setSelected(True)
        feature_checkboxes[feature] = checkbox
        features_grid.add(checkbox)
    
    features_panel.add(features_grid, BorderLayout.CENTER)
    
    # Add controls to left panel
    left_panel.add(summary_type_panel, BorderLayout.NORTH)
    left_panel.add(detail_level_panel, BorderLayout.NORTH)
    left_panel.add(output_format_panel, BorderLayout.NORTH)
    left_panel.add(function_panel, BorderLayout.CENTER)
    left_panel.add(features_panel, BorderLayout.SOUTH)
    
    # Center panel with summary display
    center_panel = JPanel(BorderLayout())
    center_panel.setBorder(BorderFactory.createTitledBorder("Code Summary"))
    
    # Summary text area
    summary_area = JTextArea()
    summary_area.setEditable(False)
    summary_area.setLineWrap(True)
    summary_area.setWrapStyleWord(True)
    summary_scroll = JScrollPane(summary_area)
    summary_scroll.setPreferredSize(Dimension(850, 600))
    
    center_panel.add(summary_scroll, BorderLayout.CENTER)
    
    # Bottom panel with status and controls
    bottom_panel = JPanel(BorderLayout())
    
    # Status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel("Ready")
    function_count_label = JLabel("Functions: 0")
    summary_count_label = JLabel("Summaries: 0")
    
    status_bar.add(status_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(function_count_label)
    status_bar.add(JLabel(" | "))
    status_bar.add(summary_count_label)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.RIGHT))
    generate_summary_button = JButton("Generate Summary")
    generate_summary_button.setPreferredSize(Dimension(150, 30))
    clear_summary_button = JButton("Clear Summary")
    clear_summary_button.setPreferredSize(Dimension(120, 30))
    
    action_panel.add(generate_summary_button)
    action_panel.add(clear_summary_button)
    
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
        populate_functions(function_model, function_count_label)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            source = event.getSource()
            if source == new_summary_button:
                create_new_summary(summary_type_combo, status_label)
            elif source == save_summary_button:
                save_summary(summary_area, status_label)
            elif source == load_summary_button:
                load_summary(summary_area, status_label)
            elif source == export_summary_button:
                export_summary(summary_area, output_format_combo, status_label)
            elif source == generate_all_button:
                generate_all_summaries(summary_type_combo, detail_level_combo, output_format_combo, status_label)
            elif source == clear_all_button:
                clear_all_summaries(summary_area, status_label, summary_count_label)
            elif source == generate_summary_button:
                generate_code_summary(
                    summary_type_combo, detail_level_combo, output_format_combo,
                    function_list, function_model,
                    feature_checkboxes,
                    summary_area, status_label, summary_count_label
                )
            elif source == clear_summary_button:
                clear_summary(summary_area, status_label)
    
    listener = ButtonActionListener()
    new_summary_button.addActionListener(listener)
    save_summary_button.addActionListener(listener)
    load_summary_button.addActionListener(listener)
    export_summary_button.addActionListener(listener)
    generate_all_button.addActionListener(listener)
    clear_all_button.addActionListener(listener)
    generate_summary_button.addActionListener(listener)
    clear_summary_button.addActionListener(listener)
    
    return frame


def populate_functions(model, function_count_label):
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
            
            function_count_label.setText(f"Functions: {model.getSize()}")
            
    except Exception as e:
        print(f"Error populating functions: {e}")


def create_new_summary(summary_type_combo, status_label):
    """Create a new summary"""
    try:
        summary_type = summary_type_combo.getSelectedItem()
        status_label.setText(f"Creating new {summary_type}...")
        
        # Simulate summary creation
        time.sleep(1)
        
        status_label.setText(f"New {summary_type} created")
        
    except Exception as e:
        status_label.setText(f"Error creating new summary: {e}")


def save_summary(summary_area, status_label):
    """Save summary"""
    try:
        summary_text = summary_area.getText()
        if not summary_text:
            status_label.setText("No summary to save")
            return
        
        status_label.setText("Saving summary...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Save Summary")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Summary files (*.summary)", "summary"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".summary"):
                file_path += ".summary"
            
            # Save summary
            with open(file_path, 'w') as f:
                f.write(summary_text)
            
            status_label.setText(f"Saved summary to {file_path}")
        else:
            status_label.setText("Summary save cancelled")
            
    except Exception as e:
        status_label.setText(f"Error saving summary: {e}")


def load_summary(summary_area, status_label):
    """Load summary"""
    try:
        status_label.setText("Loading summary...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Load Summary")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("Summary files (*.summary)", "summary"))
        
        if chooser.showOpenDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            # Load summary
            with open(file_path, 'r') as f:
                summary_text = f.read()
            
            summary_area.setText(summary_text)
            status_label.setText(f"Loaded summary from {file_path}")
        else:
            status_label.setText("Summary load cancelled")
            
    except Exception as e:
        status_label.setText(f"Error loading summary: {e}")


def export_summary(summary_area, output_format_combo, status_label):
    """Export summary"""
    try:
        summary_text = summary_area.getText()
        if not summary_text:
            status_label.setText("No summary to export")
            return
        
        output_format = output_format_combo.getSelectedItem()
        status_label.setText(f"Exporting summary as {output_format}...")
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Summary")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        
        # Set file filter based on output format
        if output_format == "Plain Text":
            chooser.setFileFilter(FileNameExtensionFilter("Text files (*.txt)", "txt"))
        elif output_format == "Markdown":
            chooser.setFileFilter(FileNameExtensionFilter("Markdown files (*.md)", "md"))
        elif output_format == "HTML":
            chooser.setFileFilter(FileNameExtensionFilter("HTML files (*.html)", "html"))
        elif output_format == "JSON":
            chooser.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", "json"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file_path = chooser.getSelectedFile().getAbsolutePath()
            
            # Save summary in selected format
            with open(file_path, 'w') as f:
                f.write(summary_text)
            
            status_label.setText(f"Exported summary to {file_path}")
        else:
            status_label.setText("Summary export cancelled")
            
    except Exception as e:
        status_label.setText(f"Error exporting summary: {e}")


def generate_all_summaries(summary_type_combo, detail_level_combo, output_format_combo, status_label):
    """Generate all summaries"""
    try:
        summary_type = summary_type_combo.getSelectedItem()
        detail_level = detail_level_combo.getSelectedItem()
        output_format = output_format_combo.getSelectedItem()
        
        status_label.setText(f"Generating all {summary_type} with {detail_level} detail level...")
        
        # Simulate generating all summaries
        time.sleep(5)
        
        status_label.setText(f"All {summary_type} generated successfully")
        
    except Exception as e:
        status_label.setText(f"Error generating all summaries: {e}")


def clear_all_summaries(summary_area, status_label, summary_count_label):
    """Clear all summaries"""
    try:
        status_label.setText("Clearing all summaries...")
        
        # Simulate clearing all summaries
        time.sleep(1)
        
        summary_area.setText("")
        summary_count_label.setText("Summaries: 0")
        
        status_label.setText("All summaries cleared")
        
    except Exception as e:
        status_label.setText(f"Error clearing all summaries: {e}")


def generate_code_summary(summary_type_combo, detail_level_combo, output_format_combo,
                        function_list, function_model,
                        feature_checkboxes,
                        summary_area, status_label, summary_count_label):
    """Generate code summary"""
    try:
        summary_type = summary_type_combo.getSelectedItem()
        detail_level = detail_level_combo.getSelectedItem()
        output_format = output_format_combo.getSelectedItem()
        
        # Get selected function
        selected_function = function_list.getSelectedValue()
        
        # Get selected features
        selected_features = []
        for feature, checkbox in feature_checkboxes.items():
            if checkbox.isSelected():
                selected_features.append(feature)
        
        status_label.setText(f"Generating {summary_type} with {detail_level} detail level...")
        
        # Simulate code summary generation
        time.sleep(3)
        
        # Generate sample summary
        summary = generate_sample_summary(summary_type, detail_level, selected_function, selected_features, output_format)
        summary_area.setText(summary)
        
        # Update summary count
        summary_count = 1
        summary_count_label.setText(f"Summaries: {summary_count}")
        
        status_label.setText(f"{summary_type} generated successfully")
        
    except Exception as e:
        status_label.setText(f"Error generating code summary: {e}")


def generate_sample_summary(summary_type, detail_level, selected_function, selected_features, output_format):
    """Generate sample code summary"""
    if output_format == "Markdown":
        summary = f"# {summary_type}\n\n"
        summary += f"## Detail Level: {detail_level}\n\n"
        if selected_function:
            summary += f"## Function: {selected_function}\n\n"
        summary += "## Summary\n\n"
        summary += "This is a sample summary for demonstration purposes.\n\n"
        summary += "### Key Features:\n\n"
        for feature in selected_features:
            summary += f"- {CODE_FEATURE_CATEGORIES[feature]}\n"
        summary += "\n### Conclusion\n\n"
        summary += "The function appears to be well-structured and follows good coding practices."
    elif output_format == "HTML":
        summary = f"<h1>{summary_type}</h1>\n"
        summary += f"<h2>Detail Level: {detail_level}</h2>\n"
        if selected_function:
            summary += f"<h2>Function: {selected_function}</h2>\n"
        summary += "<h2>Summary</h2>\n"
        summary += "<p>This is a sample summary for demonstration purposes.</p>\n"
        summary += "<h3>Key Features:</h3>\n"
        summary += "<ul>\n"
        for feature in selected_features:
            summary += f"<li>{CODE_FEATURE_CATEGORIES[feature]}</li>\n"
        summary += "</ul>\n"
        summary += "<h3>Conclusion</h3>\n"
        summary += "<p>The function appears to be well-structured and follows good coding practices.</p>"
    elif output_format == "JSON":
        summary_data = {
            "summary_type": summary_type,
            "detail_level": detail_level,
            "function": selected_function,
            "features": selected_features,
            "summary": "This is a sample summary for demonstration purposes.",
            "conclusion": "The function appears to be well-structured and follows good coding practices."
        }
        summary = json.dumps(summary_data, indent=2)
    else:  # Plain Text
        summary = f"{summary_type}\n"
        summary += f"Detail Level: {detail_level}\n"
        if selected_function:
            summary += f"Function: {selected_function}\n"
        summary += "Summary:\n"
        summary += "This is a sample summary for demonstration purposes.\n"
        summary += "Key Features:\n"
        for feature in selected_features:
            summary += f"- {CODE_FEATURE_CATEGORIES[feature]}\n"
        summary += "Conclusion:\n"
        summary += "The function appears to be well-structured and follows good coding practices."
    return summary


def clear_summary(summary_area, status_label):
    """Clear summary"""
    try:
        status_label.setText("Clearing summary...")
        
        # Simulate clearing
        time.sleep(0.5)
        
        summary_area.setText("")
        
        status_label.setText("Summary cleared")
        
    except Exception as e:
        status_label.setText(f"Error clearing summary: {e}")


# Run the code summarizer
if __name__ == "__main__":
    show_code_summarizer()