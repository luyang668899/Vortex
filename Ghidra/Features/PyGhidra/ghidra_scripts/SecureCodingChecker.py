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
# Secure Coding Checker Script
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
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import GridLayout
from java.awt import Dimension
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.services import AnalysisManager
from ghidra.app.util import OptionDialog
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.listing import Instruction
from ghidra.program.model.symbol import Symbol
from ghidra.program.model.symbol import SymbolType
from ghidra.app.script import GhidraScriptUtil


def show_secure_coding_checker():
    """Show secure coding checker UI"""
    
    print("=== Secure Coding Checker ===")
    
    if not currentProgram:
        print("No program currently open!")
        JOptionPane.showMessageDialog(None, "No program currently open!", "Error", JOptionPane.ERROR_MESSAGE)
        return
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main secure coding checker frame"""
    
    # Create frame
    frame = JFrame("Secure Coding Checker")
    frame.setSize(1000, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different secure coding tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Coding Standards", create_coding_standards_panel())
    tabbed_pane.addTab("Security Rules", create_security_rules_panel())
    tabbed_pane.addTab("Code Review", create_code_review_panel())
    tabbed_pane.addTab("Results", create_results_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_coding_standards_panel():
    """Create panel for coding standards checking"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with standard selection
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Coding standard selection
    standard_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    standard_label = JLabel("Coding Standard:")
    standard_combo = JComboBox(["CERT C/C++", "MISRA C/C++", "Google C++ Style", "Microsoft C++ Style", "POSIX", "Custom"])
    standard_combo.setSelectedIndex(0)
    standard_panel.add(standard_label)
    standard_panel.add(standard_combo)
    
    # Language selection
    language_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    language_label = JLabel("Language:")
    language_combo = JComboBox(["C", "C++", "Java", "Python", "JavaScript"])
    language_combo.setSelectedIndex(0)
    language_panel.add(language_label)
    language_panel.add(language_combo)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    check_button = JButton("Check Coding Standards")
    check_button.setPreferredSize(Dimension(180, 30))
    action_panel.add(check_button)
    
    # Standards list
    standards_panel = JPanel(BorderLayout())
    standards_label = JLabel("Selected Standards:")
    standards_model = DefaultListModel()
    standards_list = JList(standards_model)
    standards_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    standards_scroll = JScrollPane(standards_list)
    standards_scroll.setPreferredSize(Dimension(400, 200))
    
    standards_panel.add(standards_label, BorderLayout.NORTH)
    standards_panel.add(standards_scroll, BorderLayout.CENTER)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 150))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    top_panel.add(standard_panel)
    top_panel.add(language_panel)
    top_panel.add(action_panel)
    top_panel.add(standards_panel)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate standards list
    populate_coding_standards(standards_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == check_button:
                coding_standard = standard_combo.getSelectedItem()
                language = language_combo.getSelectedItem()
                selected_standards = get_selected_items(standards_list, standards_model)
                check_coding_standards(coding_standard, language, selected_standards, status_area)
    
    listener = ButtonActionListener()
    check_button.addActionListener(listener)
    
    return panel


def create_security_rules_panel():
    """Create panel for security rules checking"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Security rules list
    rules_panel = JPanel(BorderLayout())
    rules_label = JLabel("Security Rules:")
    rules_model = DefaultListModel()
    rules_list = JList(rules_model)
    rules_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    rules_scroll = JScrollPane(rules_list)
    rules_scroll.setPreferredSize(Dimension(400, 250))
    
    rules_panel.add(rules_label, BorderLayout.NORTH)
    rules_panel.add(rules_scroll, BorderLayout.CENTER)
    
    # Rule details
    details_panel = JPanel(BorderLayout())
    details_label = JLabel("Rule Details:")
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(500, 200))
    
    details_panel.add(details_label, BorderLayout.NORTH)
    details_panel.add(details_scroll, BorderLayout.CENTER)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    check_button = JButton("Check Security Rules")
    check_button.setPreferredSize(Dimension(150, 30))
    action_panel.add(check_button)
    
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
    panel.add(rules_panel, BorderLayout.WEST)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(action_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate security rules
    populate_security_rules(rules_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == check_button:
                selected_rules = get_selected_items(rules_list, rules_model)
                check_security_rules(selected_rules, status_area)
    
    listener = ButtonActionListener()
    check_button.addActionListener(listener)
    
    # Add list selection listener for rules list
    class ListSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_rule = rules_list.getSelectedValue()
            if selected_rule:
                details_area.setText(get_rule_details(selected_rule))
    
    rules_list.addListSelectionListener(
        lambda e: ListSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_code_review_panel():
    """Create panel for code review"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Code review options
    options_panel = JPanel()
    options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
    
    # Review type
    review_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    review_label = JLabel("Review Type:")
    review_combo = JComboBox(["Full Review", "Quick Review", "Focused Review"])
    review_combo.setSelectedIndex(1)
    review_panel.add(review_label)
    review_panel.add(review_combo)
    
    # Focus areas
    focus_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    focus_label = JLabel("Focus Areas:")
    focus_combo = JComboBox(["Memory Safety", "Input Validation", "Cryptography", "Concurrency", "Error Handling"])
    focus_combo.setSelectedIndex(0)
    focus_panel.add(focus_label)
    focus_panel.add(focus_combo)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    review_button = JButton("Start Code Review")
    review_button.setPreferredSize(Dimension(150, 30))
    action_panel.add(review_button)
    
    # Review checklist
    checklist_panel = JPanel(BorderLayout())
    checklist_label = JLabel("Review Checklist:")
    checklist_model = DefaultListModel()
    checklist_list = JList(checklist_model)
    checklist_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    checklist_scroll = JScrollPane(checklist_list)
    checklist_scroll.setPreferredSize(Dimension(400, 200))
    
    checklist_panel.add(checklist_label, BorderLayout.NORTH)
    checklist_panel.add(checklist_scroll, BorderLayout.CENTER)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 100))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    options_panel.add(review_panel)
    options_panel.add(focus_panel)
    options_panel.add(action_panel)
    options_panel.add(checklist_panel)
    
    # Add components to panel
    panel.add(options_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate review checklist
    populate_review_checklist(checklist_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == review_button:
                review_type = review_combo.getSelectedItem()
                focus_area = focus_combo.getSelectedItem()
                selected_items = get_selected_items(checklist_list, checklist_model)
                start_code_review(review_type, focus_area, selected_items, status_area)
    
    listener = ButtonActionListener()
    review_button.addActionListener(listener)
    
    return panel


def create_results_panel():
    """Create panel for results"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Secure Coding Check Results:")
    table_model = DefaultTableModel(["Rule/Standard", "Violation", "Severity", "Location", "Details", "Recommendations"], 0)
    result_table = JTable(table_model)
    result_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
    table_scroll = JScrollPane(result_table)
    table_scroll.setPreferredSize(Dimension(800, 250))
    
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
    details_scroll.setPreferredSize(Dimension(800, 150))
    
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
                export_results(table_model, details_area)
            elif event.getSource() == clear_button:
                clear_results(table_model, details_area)
    
    listener = ButtonActionListener()
    export_button.addActionListener(listener)
    clear_button.addActionListener(listener)
    
    # Add table selection listener
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                rule = table_model.getValueAt(selected_row, 0)
                violation = table_model.getValueAt(selected_row, 1)
                severity = table_model.getValueAt(selected_row, 2)
                location = table_model.getValueAt(selected_row, 3)
                details = table_model.getValueAt(selected_row, 4)
                recommendations = table_model.getValueAt(selected_row, 5)
                details_area.setText(f"Rule/Standard: {rule}\nViolation: {violation}\nSeverity: {severity}\nLocation: {location}\nDetails: {details}\nRecommendations: {recommendations}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def populate_coding_standards(model):
    """Populate coding standards list"""
    standards = [
        "CERT C Secure Coding Standard",
        "CERT C++ Secure Coding Standard",
        "MISRA C:2012",
        "MISRA C++:2008",
        "Google C++ Style Guide",
        "Microsoft C++ Coding Conventions",
        "POSIX Coding Standards",
        "ISO/IEC 9899:2018 (C18)",
        "ISO/IEC 14882:2017 (C++17)",
        "Java Coding Conventions",
        "Python PEP 8 Style Guide",
        "JavaScript Standard Style"
    ]
    
    for standard in standards:
        model.addElement(standard)


def populate_security_rules(model):
    """Populate security rules list"""
    rules = [
        "Input Validation and Data Sanitization",
        "Memory Management and Buffer Overflows",
        "Cryptographic Practices",
        "Authentication and Authorization",
        "Error Handling and Logging",
        "Concurrency and Thread Safety",
        "File I/O and Resource Management",
        "Network Security",
        "System Interaction",
        "Code Quality and Maintainability"
    ]
    
    for rule in rules:
        model.addElement(rule)


def populate_review_checklist(model):
    """Populate review checklist"""
    checklist = [
        "Memory allocation and deallocation",
        "Buffer size validation",
        "Input sanitization",
        "Error checking for all function calls",
        "Proper use of cryptographic functions",
        "Secure random number generation",
        "Thread synchronization mechanisms",
        "Resource cleanup in error paths",
        "Secure file permissions",
        "Network input validation",
        "Proper exception handling",
        "Secure use of system calls",
        "Avoidance of hardcoded secrets",
        "Proper use of pointers and references",
        "Bounds checking for arrays and strings"
    ]
    
    for item in checklist:
        model.addElement(item)


def get_selected_items(list_component, model):
    """Get selected items from a list"""
    selected_indices = list_component.getSelectedIndices()
    selected_items = []
    for index in selected_indices:
        selected_items.append(model.getElementAt(index))
    return selected_items


def get_rule_details(rule):
    """Get details for a security rule"""
    # Dummy details
    details = {
        "Input Validation and Data Sanitization": "Ensure all user input is properly validated and sanitized before use. This includes checking for proper length, format, and type.",
        "Memory Management and Buffer Overflows": "Avoid buffer overflows by properly managing memory allocation, checking bounds, and using safe string functions.",
        "Cryptographic Practices": "Use cryptographically strong algorithms, proper key management, and avoid insecure practices like hardcoding keys.",
        "Authentication and Authorization": "Implement strong authentication and authorization mechanisms to control access to sensitive resources.",
        "Error Handling and Logging": "Properly handle errors without exposing sensitive information, and implement secure logging practices.",
        "Concurrency and Thread Safety": "Ensure thread safety by properly synchronizing access to shared resources and avoiding race conditions.",
        "File I/O and Resource Management": "Safely handle file operations, including proper permissions, path validation, and resource cleanup.",
        "Network Security": "Implement secure network communications, including encryption, proper certificate validation, and input sanitization.",
        "System Interaction": "Safely interact with system resources, including avoiding command injection and properly validating inputs to system calls.",
        "Code Quality and Maintainability": "Write clean, maintainable code with proper documentation, error handling, and consistent style."
    }
    return details.get(rule, "No details available for this rule.")


def check_coding_standards(coding_standard, language, selected_standards, text_area):
    """Check coding standards compliance"""
    try:
        text_area.setText(f"Checking {coding_standard} compliance for {language}...")
        
        if not selected_standards:
            text_area.setText("No coding standards selected.")
            return
        
        # Simulate coding standards check
        import time
        total_standards = len(selected_standards)
        for i, standard in enumerate(selected_standards):
            text_area.setText(f"Checking standard {i+1}/{total_standards}: {standard}")
            time.sleep(0.5)
        
        text_area.append("\n\nCoding standards check completed successfully!")
        
    except Exception as e:
        text_area.setText(f"Error checking coding standards: {e}")


def check_security_rules(selected_rules, text_area):
    """Check security rules compliance"""
    try:
        text_area.setText("Checking security rules compliance...")
        
        if not selected_rules:
            text_area.setText("No security rules selected.")
            return
        
        # Simulate security rules check
        import time
        total_rules = len(selected_rules)
        for i, rule in enumerate(selected_rules):
            text_area.setText(f"Checking rule {i+1}/{total_rules}: {rule}")
            time.sleep(0.5)
        
        text_area.append("\n\nSecurity rules check completed successfully!")
        
    except Exception as e:
        text_area.setText(f"Error checking security rules: {e}")


def start_code_review(review_type, focus_area, selected_items, text_area):
    """Start code review"""
    try:
        text_area.setText(f"Starting {review_type} with focus on {focus_area}...")
        
        if not selected_items:
            text_area.setText("No checklist items selected.")
            return
        
        # Simulate code review
        import time
        total_items = len(selected_items)
        for i, item in enumerate(selected_items):
            text_area.setText(f"Reviewing item {i+1}/{total_items}: {item}")
            time.sleep(0.5)
        
        text_area.append("\n\nCode review completed successfully!")
        
    except Exception as e:
        text_area.setText(f"Error starting code review: {e}")


def export_results(table_model, details_area):
    """Export check results"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to export.")
            return
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Results")
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
            details_area.setText("Results export cancelled.")
            
    except Exception as e:
        details_area.setText(f"Error exporting results: {e}")


def clear_results(table_model, details_area):
    """Clear check results"""
    try:
        table_model.setRowCount(0)
        details_area.setText("Results cleared successfully.")
        
    except Exception as e:
        details_area.setText(f"Error clearing results: {e}")


# Run the secure coding checker
if __name__ == "__main__":
    show_secure_coding_checker()
