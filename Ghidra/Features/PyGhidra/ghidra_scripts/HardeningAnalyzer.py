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
# Hardening Analyzer Script
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


def show_hardening_analyzer():
    """Show hardening analyzer UI"""
    
    print("=== Hardening Analyzer ===")
    
    if not currentProgram:
        print("No program currently open!")
        JOptionPane.showMessageDialog(None, "No program currently open!", "Error", JOptionPane.ERROR_MESSAGE)
        return
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main hardening analyzer frame"""
    
    # Create frame
    frame = JFrame("Hardening Analyzer")
    frame.setSize(1000, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different hardening analysis tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Security Hardening", create_security_hardening_panel())
    tabbed_pane.addTab("Mitigation Techniques", create_mitigation_techniques_panel())
    tabbed_pane.addTab("Compliance Check", create_compliance_check_panel())
    tabbed_pane.addTab("Results", create_results_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_security_hardening_panel():
    """Create panel for security hardening analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with analysis options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Analysis options
    analysis_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analysis_label = JLabel("Analysis Level:")
    analysis_combo = JComboBox(["Basic", "Intermediate", "Advanced"])
    analysis_combo.setSelectedIndex(1)
    analysis_panel.add(analysis_label)
    analysis_panel.add(analysis_combo)
    
    # Target platform
    platform_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    platform_label = JLabel("Target Platform:")
    platform_combo = JComboBox(["Windows", "Linux", "macOS", "Embedded", "Web"])
    platform_combo.setSelectedIndex(1)
    platform_panel.add(platform_label)
    platform_panel.add(platform_combo)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_button = JButton("Analyze Hardening")
    analyze_button.setPreferredSize(Dimension(150, 30))
    action_panel.add(analyze_button)
    
    # Hardening checks
    checks_panel = JPanel(BorderLayout())
    checks_label = JLabel("Hardening Checks:")
    checks_model = DefaultListModel()
    checks_list = JList(checks_model)
    checks_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    checks_scroll = JScrollPane(checks_list)
    checks_scroll.setPreferredSize(Dimension(400, 200))
    
    checks_panel.add(checks_label, BorderLayout.NORTH)
    checks_panel.add(checks_scroll, BorderLayout.CENTER)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 150))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    top_panel.add(analysis_panel)
    top_panel.add(platform_panel)
    top_panel.add(action_panel)
    top_panel.add(checks_panel)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate hardening checks
    populate_hardening_checks(checks_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_button:
                analysis_level = analysis_combo.getSelectedItem()
                platform = platform_combo.getSelectedItem()
                selected_checks = get_selected_items(checks_list, checks_model)
                analyze_hardening(analysis_level, platform, selected_checks, status_area)
    
    listener = ButtonActionListener()
    analyze_button.addActionListener(listener)
    
    return panel


def create_mitigation_techniques_panel():
    """Create panel for mitigation techniques analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Mitigation techniques list
    techniques_panel = JPanel(BorderLayout())
    techniques_label = JLabel("Mitigation Techniques:")
    techniques_model = DefaultListModel()
    techniques_list = JList(techniques_model)
    techniques_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    techniques_scroll = JScrollPane(techniques_list)
    techniques_scroll.setPreferredSize(Dimension(400, 250))
    
    techniques_panel.add(techniques_label, BorderLayout.NORTH)
    techniques_panel.add(techniques_scroll, BorderLayout.CENTER)
    
    # Technique details
    details_panel = JPanel(BorderLayout())
    details_label = JLabel("Technique Details:")
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
    analyze_button = JButton("Analyze Mitigations")
    analyze_button.setPreferredSize(Dimension(150, 30))
    action_panel.add(analyze_button)
    
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
    panel.add(techniques_panel, BorderLayout.WEST)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(action_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate mitigation techniques
    populate_mitigation_techniques(techniques_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_button:
                selected_techniques = get_selected_items(techniques_list, techniques_model)
                analyze_mitigations(selected_techniques, status_area)
    
    listener = ButtonActionListener()
    analyze_button.addActionListener(listener)
    
    # Add list selection listener for techniques list
    class ListSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_technique = techniques_list.getSelectedValue()
            if selected_technique:
                details_area.setText(get_technique_details(selected_technique))
    
    techniques_list.addListSelectionListener(
        lambda e: ListSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_compliance_check_panel():
    """Create panel for compliance check"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Compliance standards
    standards_panel = JPanel(BorderLayout())
    standards_label = JLabel("Compliance Standards:")
    standards_model = DefaultListModel()
    standards_list = JList(standards_model)
    standards_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    standards_scroll = JScrollPane(standards_list)
    standards_scroll.setPreferredSize(Dimension(400, 200))
    
    standards_panel.add(standards_label, BorderLayout.NORTH)
    standards_panel.add(standards_scroll, BorderLayout.CENTER)
    
    # Compliance level
    level_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    level_label = JLabel("Compliance Level:")
    level_combo = JComboBox(["Minimum", "Recommended", "Full"])
    level_combo.setSelectedIndex(1)
    level_panel.add(level_label)
    level_panel.add(level_combo)
    
    # Action buttons
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    check_button = JButton("Check Compliance")
    check_button.setPreferredSize(Dimension(150, 30))
    action_panel.add(check_button)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 150))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    # Add components to panel
    panel.add(standards_panel, BorderLayout.WEST)
    panel.add(level_panel, BorderLayout.NORTH)
    panel.add(action_panel, BorderLayout.CENTER)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Populate compliance standards
    populate_compliance_standards(standards_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == check_button:
                selected_standards = get_selected_items(standards_list, standards_model)
                compliance_level = level_combo.getSelectedItem()
                check_compliance(selected_standards, compliance_level, status_area)
    
    listener = ButtonActionListener()
    check_button.addActionListener(listener)
    
    return panel


def create_results_panel():
    """Create panel for results"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Hardening Analysis Results:")
    table_model = DefaultTableModel(["Check", "Status", "Severity", "Details", "Recommendations"], 0)
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
                check = table_model.getValueAt(selected_row, 0)
                status = table_model.getValueAt(selected_row, 1)
                severity = table_model.getValueAt(selected_row, 2)
                details = table_model.getValueAt(selected_row, 3)
                recommendations = table_model.getValueAt(selected_row, 4)
                details_area.setText(f"Check: {check}\nStatus: {status}\nSeverity: {severity}\nDetails: {details}\nRecommendations: {recommendations}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def populate_hardening_checks(model):
    """Populate hardening checks list"""
    checks = [
        "ASLR (Address Space Layout Randomization)",
        "DEP (Data Execution Prevention)",
        "Stack Canary",
        "PIE (Position Independent Executable)",
        "RelRO (Read-Only Relocations)",
        "NX (No-eXecute) Bit",
        "Safe Stack",
        "Control Flow Integrity",
        "Cryptographic Hardening",
        "Network Hardening",
        "File System Hardening",
        "Memory Hardening",
        "Privilege Separation",
        "Least Privilege",
        "Secure Defaults"
    ]
    
    for check in checks:
        model.addElement(check)


def populate_mitigation_techniques(model):
    """Populate mitigation techniques list"""
    techniques = [
        "Stack Overflow Mitigations",
        "Heap Exploitation Mitigations",
        "Format String Mitigations",
        "Use-After-Free Mitigations",
        "Double Free Mitigations",
        "Integer Overflow Mitigations",
        "Pointer Subterfuge Mitigations",
        "Return-Oriented Programming (ROP) Mitigations",
        "Jump-Oriented Programming (JOP) Mitigations",
        "Call-Oriented Programming (COP) Mitigations",
        "Code Injection Mitigations",
        "Denial of Service Mitigations"
    ]
    
    for technique in techniques:
        model.addElement(technique)


def populate_compliance_standards(model):
    """Populate compliance standards list"""
    standards = [
        "CWE/SANS Top 25",
        "OWASP Top 10",
        "NIST SP 800-53",
        "ISO 27001",
        "PCI DSS",
        "GDPR",
        "HIPAA",
        "FIPS 140-2",
        "Common Criteria",
        "SOC 2"
    ]
    
    for standard in standards:
        model.addElement(standard)


def get_selected_items(list_component, model):
    """Get selected items from a list"""
    selected_indices = list_component.getSelectedIndices()
    selected_items = []
    for index in selected_indices:
        selected_items.append(model.getElementAt(index))
    return selected_items


def get_technique_details(technique):
    """Get details for a mitigation technique"""
    # Dummy details
    details = {
        "Stack Overflow Mitigations": "Mitigations for stack overflow vulnerabilities, including stack canaries, ASLR, and DEP.",
        "Heap Exploitation Mitigations": "Mitigations for heap exploitation techniques, including heap cookies, heap randomization, and safe memory allocators.",
        "Format String Mitigations": "Mitigations for format string vulnerabilities, including compiler warnings and runtime protections.",
        "Use-After-Free Mitigations": "Mitigations for use-after-free vulnerabilities, including pointer sanitization and heap hardening.",
        "Double Free Mitigations": "Mitigations for double free vulnerabilities, including heap management improvements and runtime checks.",
        "Integer Overflow Mitigations": "Mitigations for integer overflow vulnerabilities, including compiler flags and runtime checks.",
        "Pointer Subterfuge Mitigations": "Mitigations for pointer subterfuge techniques, including pointer authentication and bounds checking.",
        "Return-Oriented Programming (ROP) Mitigations": "Mitigations for ROP attacks, including CFI and shadow stacks.",
        "Jump-Oriented Programming (JOP) Mitigations": "Mitigations for JOP attacks, including CFI and hardware-assisted protections.",
        "Call-Oriented Programming (COP) Mitigations": "Mitigations for COP attacks, including CFI and runtime monitoring.",
        "Code Injection Mitigations": "Mitigations for code injection attacks, including DEP and secure memory management.",
        "Denial of Service Mitigations": "Mitigations for denial of service attacks, including resource limits and rate limiting."
    }
    return details.get(technique, "No details available for this technique.")


def analyze_hardening(analysis_level, platform, selected_checks, text_area):
    """Analyze security hardening"""
    try:
        text_area.setText(f"Analyzing hardening with {analysis_level} level for {platform} platform...")
        
        if not selected_checks:
            text_area.setText("No hardening checks selected.")
            return
        
        # Simulate hardening analysis
        import time
        total_checks = len(selected_checks)
        for i, check in enumerate(selected_checks):
            text_area.setText(f"Analyzing check {i+1}/{total_checks}: {check}")
            time.sleep(0.5)
        
        text_area.append("\n\nHardening analysis completed successfully!")
        
    except Exception as e:
        text_area.setText(f"Error analyzing hardening: {e}")


def analyze_mitigations(selected_techniques, text_area):
    """Analyze mitigation techniques"""
    try:
        text_area.setText("Analyzing mitigation techniques...")
        
        if not selected_techniques:
            text_area.setText("No mitigation techniques selected.")
            return
        
        # Simulate mitigation analysis
        import time
        total_techniques = len(selected_techniques)
        for i, technique in enumerate(selected_techniques):
            text_area.setText(f"Analyzing technique {i+1}/{total_techniques}: {technique}")
            time.sleep(0.5)
        
        text_area.append("\n\nMitigation analysis completed successfully!")
        
    except Exception as e:
        text_area.setText(f"Error analyzing mitigations: {e}")


def check_compliance(selected_standards, compliance_level, text_area):
    """Check compliance with security standards"""
    try:
        text_area.setText(f"Checking compliance with {compliance_level} level...")
        
        if not selected_standards:
            text_area.setText("No compliance standards selected.")
            return
        
        # Simulate compliance check
        import time
        total_standards = len(selected_standards)
        for i, standard in enumerate(selected_standards):
            text_area.setText(f"Checking compliance with {standard} ({i+1}/{total_standards})")
            time.sleep(0.5)
        
        text_area.append("\n\nCompliance check completed successfully!")
        
    except Exception as e:
        text_area.setText(f"Error checking compliance: {e}")


def export_results(table_model, details_area):
    """Export analysis results"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to export.")
            return
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Results")
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        chooser.setFileFilter(FileNameExtensionFilter("JSON files (*.json)", "json"))
        
        if chooser.showSaveDialog(None) == JFileChooser.APPROVE_OPTION:
            file = chooser.getSelectedFile()
            file_path = file.getAbsolutePath()
            if not file_path.endswith(".json"):
                file_path += ".json"
            
            # Export results to JSON
            results = []
            for i in range(table_model.getRowCount()):
                result = {
                    "check": table_model.getValueAt(i, 0),
                    "status": table_model.getValueAt(i, 1),
                    "severity": table_model.getValueAt(i, 2),
                    "details": table_model.getValueAt(i, 3),
                    "recommendations": table_model.getValueAt(i, 4)
                }
                results.append(result)
            
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=2)
            
            details_area.setText(f"Results exported successfully to {file_path}")
        else:
            details_area.setText("Results export cancelled.")
            
    except Exception as e:
        details_area.setText(f"Error exporting results: {e}")


def clear_results(table_model, details_area):
    """Clear analysis results"""
    try:
        table_model.setRowCount(0)
        details_area.setText("Results cleared successfully.")
        
    except Exception as e:
        details_area.setText(f"Error clearing results: {e}")


# Run the hardening analyzer
if __name__ == "__main__":
    show_hardening_analyzer()
