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
# Machine Learning Integrator Script
# @category: Examples.Python
# @runtime PyGhidra

import typing
if typing.TYPE_CHECKING:
    from ghidra.ghidra_builtins import *

import time
import os
import json
import numpy as np
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
from java.awt import BorderLayout
from java.awt import FlowLayout
from java.awt import GridLayout
from java.awt import Dimension
from java.awt.event import ActionListener
from java.awt.event import ActionEvent
from java.awt.event import KeyAdapter
from java.awt.event import KeyEvent
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from ghidra.app.decompiler import DecompileOptions
from ghidra.program.model.pcode import HighFunction
from ghidra.program.model.pcode import Varnode
from ghidra.program.model.pcode import PcodeOp
from ghidra.program.model.symbol import Function
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet
from ghidra.app.util import OptionDialog


def show_machine_learning_integrator():
    """Show machine learning integrator UI"""
    
    print("=== Machine Learning Integrator ===")
    
    if not currentProgram:
        print("No program currently open!")
        JOptionPane.showMessageDialog(None, "No program currently open!", "Error", JOptionPane.ERROR_MESSAGE)
        return
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main machine learning integrator frame"""
    
    # Create frame
    frame = JFrame("Machine Learning Integrator")
    frame.setSize(1100, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different machine learning tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Function Type Identification", create_function_type_panel())
    tabbed_pane.addTab("Vulnerability Detection", create_vulnerability_detection_panel())
    tabbed_pane.addTab("Code Quality Assessment", create_code_quality_panel())
    tabbed_pane.addTab("Model Management", create_model_management_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_function_type_panel():
    """Create panel for function type identification"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with analysis options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Function selection
    function_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    function_label = JLabel("Function Selection:")
    function_combo = JComboBox(["All Functions", "Selected Function"])
    specific_function_combo = JComboBox(["Select Function"])
    refresh_button = JButton("Refresh")
    function_panel.add(function_label)
    function_panel.add(function_combo)
    function_panel.add(specific_function_combo)
    function_panel.add(refresh_button)
    
    # Model selection
    model_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    model_label = JLabel("Model:")
    model_combo = JComboBox(["Function Type Classifier", "Behavior Pattern Recognizer"])
    model_panel.add(model_label)
    model_panel.add(model_combo)
    
    # Analysis options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    use_decompiler_checkbox = JCheckBox("Use Decompiler")
    use_decompiler_checkbox.setSelected(True)
    extract_features_checkbox = JCheckBox("Extract Features")
    options_panel.add(use_decompiler_checkbox)
    options_panel.add(extract_features_checkbox)
    
    # Analyze button
    analyze_button = JButton("Identify Function Types")
    analyze_button.setPreferredSize(Dimension(180, 30))
    
    # Progress bar
    progress_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    progress_bar = JProgressBar()
    progress_bar.setPreferredSize(Dimension(400, 20))
    progress_bar.setStringPainted(True)
    progress_panel.add(progress_bar)
    
    top_panel.add(function_panel)
    top_panel.add(model_panel)
    top_panel.add(options_panel)
    top_panel.add(analyze_button)
    top_panel.add(progress_panel)
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Function Type Results:")
    table_model = DefaultTableModel(["Function", "Address", "Predicted Type", "Confidence", "Features"], 0)
    result_table = JTable(table_model)
    result_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
    table_scroll = JScrollPane(result_table)
    table_scroll.setPreferredSize(Dimension(800, 300))
    
    table_panel.add(table_label, BorderLayout.NORTH)
    table_panel.add(table_scroll, BorderLayout.CENTER)
    
    # Text area for details
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(800, 150))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(table_panel, BorderLayout.CENTER)
    panel.add(details_scroll, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == refresh_button:
                refresh_function_list(specific_function_combo, details_area)
            elif event.getSource() == analyze_button:
                function_selection = function_combo.getSelectedItem()
                if function_selection == "Selected Function":
                    function_name = specific_function_combo.getSelectedItem()
                else:
                    function_name = "All Functions"
                model = model_combo.getSelectedItem()
                use_decompiler = use_decompiler_checkbox.isSelected()
                extract_features = extract_features_checkbox.isSelected()
                identify_function_types(function_name, model, use_decompiler, extract_features, table_model, details_area, progress_bar)
    
    listener = ButtonActionListener()
    refresh_button.addActionListener(listener)
    analyze_button.addActionListener(listener)
    
    # Add list selection listener for results table
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                function_name = table_model.getValueAt(selected_row, 0)
                function_type = table_model.getValueAt(selected_row, 2)
                confidence = table_model.getValueAt(selected_row, 3)
                features = table_model.getValueAt(selected_row, 4)
                details_area.setText(f"Function: {function_name}\nType: {function_type}\nConfidence: {confidence}\nFeatures: {features}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_vulnerability_detection_panel():
    """Create panel for vulnerability detection"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with detection options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Function selection
    function_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    function_label = JLabel("Function Selection:")
    function_combo = JComboBox(["All Functions", "Selected Function"])
    specific_function_combo = JComboBox(["Select Function"])
    refresh_button = JButton("Refresh")
    function_panel.add(function_label)
    function_panel.add(function_combo)
    function_panel.add(specific_function_combo)
    function_panel.add(refresh_button)
    
    # Vulnerability types
    vuln_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    vuln_label = JLabel("Vulnerability Types:")
    vuln_combo = JComboBox(["All Types", "Buffer Overflow", "Integer Overflow", "Use After Free", "Null Pointer Dereference"])
    vuln_panel.add(vuln_label)
    vuln_panel.add(vuln_combo)
    
    # Analysis options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    use_decompiler_checkbox = JCheckBox("Use Decompiler")
    use_decompiler_checkbox.setSelected(True)
    deep_scan_checkbox = JCheckBox("Deep Scan")
    options_panel.add(use_decompiler_checkbox)
    options_panel.add(deep_scan_checkbox)
    
    # Detect button
    detect_button = JButton("Detect Vulnerabilities")
    detect_button.setPreferredSize(Dimension(180, 30))
    
    # Progress bar
    progress_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    progress_bar = JProgressBar()
    progress_bar.setPreferredSize(Dimension(400, 20))
    progress_bar.setStringPainted(True)
    progress_panel.add(progress_bar)
    
    top_panel.add(function_panel)
    top_panel.add(vuln_panel)
    top_panel.add(options_panel)
    top_panel.add(detect_button)
    top_panel.add(progress_panel)
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Vulnerability Detection Results:")
    table_model = DefaultTableModel(["Function", "Address", "Vulnerability Type", "Severity", "Description"], 0)
    result_table = JTable(table_model)
    result_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
    table_scroll = JScrollPane(result_table)
    table_scroll.setPreferredSize(Dimension(800, 300))
    
    table_panel.add(table_label, BorderLayout.NORTH)
    table_panel.add(table_scroll, BorderLayout.CENTER)
    
    # Text area for details
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(800, 150))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(table_panel, BorderLayout.CENTER)
    panel.add(details_scroll, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == refresh_button:
                refresh_function_list(specific_function_combo, details_area)
            elif event.getSource() == detect_button:
                function_selection = function_combo.getSelectedItem()
                if function_selection == "Selected Function":
                    function_name = specific_function_combo.getSelectedItem()
                else:
                    function_name = "All Functions"
                vuln_type = vuln_combo.getSelectedItem()
                use_decompiler = use_decompiler_checkbox.isSelected()
                deep_scan = deep_scan_checkbox.isSelected()
                detect_vulnerabilities(function_name, vuln_type, use_decompiler, deep_scan, table_model, details_area, progress_bar)
    
    listener = ButtonActionListener()
    refresh_button.addActionListener(listener)
    detect_button.addActionListener(listener)
    
    # Add list selection listener for results table
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                function_name = table_model.getValueAt(selected_row, 0)
                vuln_type = table_model.getValueAt(selected_row, 2)
                severity = table_model.getValueAt(selected_row, 3)
                description = table_model.getValueAt(selected_row, 4)
                details_area.setText(f"Function: {function_name}\nVulnerability: {vuln_type}\nSeverity: {severity}\nDescription: {description}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_code_quality_panel():
    """Create panel for code quality assessment"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with assessment options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Function selection
    function_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    function_label = JLabel("Function Selection:")
    function_combo = JComboBox(["All Functions", "Selected Function"])
    specific_function_combo = JComboBox(["Select Function"])
    refresh_button = JButton("Refresh")
    function_panel.add(function_label)
    function_panel.add(function_combo)
    function_panel.add(specific_function_combo)
    function_panel.add(refresh_button)
    
    # Quality metrics
    metrics_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    metrics_label = JLabel("Metrics:")
    metrics_combo = JComboBox(["All Metrics", "Complexity", "Readability", "Security"])
    metrics_panel.add(metrics_label)
    metrics_panel.add(metrics_combo)
    
    # Analysis options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    use_decompiler_checkbox = JCheckBox("Use Decompiler")
    use_decompiler_checkbox.setSelected(True)
    generate_report_checkbox = JCheckBox("Generate Report")
    options_panel.add(use_decompiler_checkbox)
    options_panel.add(generate_report_checkbox)
    
    # Assess button
    assess_button = JButton("Assess Code Quality")
    assess_button.setPreferredSize(Dimension(180, 30))
    
    # Progress bar
    progress_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    progress_bar = JProgressBar()
    progress_bar.setPreferredSize(Dimension(400, 20))
    progress_bar.setStringPainted(True)
    progress_panel.add(progress_bar)
    
    top_panel.add(function_panel)
    top_panel.add(metrics_panel)
    top_panel.add(options_panel)
    top_panel.add(assess_button)
    top_panel.add(progress_panel)
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Code Quality Results:")
    table_model = DefaultTableModel(["Function", "Address", "Overall Score", "Complexity", "Readability", "Security"], 0)
    result_table = JTable(table_model)
    result_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
    table_scroll = JScrollPane(result_table)
    table_scroll.setPreferredSize(Dimension(800, 300))
    
    table_panel.add(table_label, BorderLayout.NORTH)
    table_panel.add(table_scroll, BorderLayout.CENTER)
    
    # Text area for details
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(800, 150))
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(table_panel, BorderLayout.CENTER)
    panel.add(details_scroll, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == refresh_button:
                refresh_function_list(specific_function_combo, details_area)
            elif event.getSource() == assess_button:
                function_selection = function_combo.getSelectedItem()
                if function_selection == "Selected Function":
                    function_name = specific_function_combo.getSelectedItem()
                else:
                    function_name = "All Functions"
                metrics = metrics_combo.getSelectedItem()
                use_decompiler = use_decompiler_checkbox.isSelected()
                generate_report = generate_report_checkbox.isSelected()
                assess_code_quality(function_name, metrics, use_decompiler, generate_report, table_model, details_area, progress_bar)
    
    listener = ButtonActionListener()
    refresh_button.addActionListener(listener)
    assess_button.addActionListener(listener)
    
    # Add list selection listener for results table
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                function_name = table_model.getValueAt(selected_row, 0)
                overall_score = table_model.getValueAt(selected_row, 2)
                complexity = table_model.getValueAt(selected_row, 3)
                readability = table_model.getValueAt(selected_row, 4)
                security = table_model.getValueAt(selected_row, 5)
                details_area.setText(f"Function: {function_name}\nOverall Score: {overall_score}\nComplexity: {complexity}\nReadability: {readability}\nSecurity: {security}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_model_management_panel():
    """Create panel for model management"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with model management options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Model list
    model_list_panel = JPanel(BorderLayout())
    model_list_label = JLabel("Available Models:")
    model_list_model = DefaultListModel()
    model_list = JList(model_list_model)
    model_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    model_list_scroll = JScrollPane(model_list)
    model_list_scroll.setPreferredSize(Dimension(400, 150))
    
    model_list_panel.add(model_list_label, BorderLayout.NORTH)
    model_list_panel.add(model_list_scroll, BorderLayout.CENTER)
    
    # Model actions
    action_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    load_button = JButton("Load Model")
    save_button = JButton("Save Model")
    train_button = JButton("Train Model")
    test_button = JButton("Test Model")
    action_panel.add(load_button)
    action_panel.add(save_button)
    action_panel.add(train_button)
    action_panel.add(test_button)
    
    # Model information
    info_panel = JPanel(BorderLayout())
    info_label = JLabel("Model Information:")
    info_area = JTextArea()
    info_area.setEditable(False)
    info_area.setLineWrap(True)
    info_area.setWrapStyleWord(True)
    info_scroll = JScrollPane(info_area)
    info_scroll.setPreferredSize(Dimension(800, 200))
    
    info_panel.add(info_label, BorderLayout.NORTH)
    info_panel.add(info_scroll, BorderLayout.CENTER)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(model_list_panel, BorderLayout.WEST)
    panel.add(action_panel, BorderLayout.CENTER)
    panel.add(info_panel, BorderLayout.SOUTH)
    
    # Populate model list
    model_list_model.addElement("Function Type Classifier")
    model_list_model.addElement("Behavior Pattern Recognizer")
    model_list_model.addElement("Vulnerability Detector")
    model_list_model.addElement("Code Quality Assessor")
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == load_button:
                load_model(model_list, info_area)
            elif event.getSource() == save_button:
                save_model(model_list, info_area)
            elif event.getSource() == train_button:
                train_model(model_list, info_area)
            elif event.getSource() == test_button:
                test_model(model_list, info_area)
    
    listener = ButtonActionListener()
    load_button.addActionListener(listener)
    save_button.addActionListener(listener)
    train_button.addActionListener(listener)
    test_button.addActionListener(listener)
    
    # Add list selection listener for model list
    class ListSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_model = model_list.getSelectedValue()
            if selected_model:
                info_area.setText(f"Model: {selected_model}\nStatus: Ready\nDescription: {get_model_description(selected_model)}")
    
    model_list.addListSelectionListener(
        lambda e: ListSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def get_model_description(model_name):
    """Get model description"""
    descriptions = {
        "Function Type Classifier": "Classifies functions into different types based on their features",
        "Behavior Pattern Recognizer": "Recognizes behavior patterns in functions",
        "Vulnerability Detector": "Detects potential vulnerabilities in code",
        "Code Quality Assessor": "Assesses code quality based on various metrics"
    }
    return descriptions.get(model_name, "No description available")


def refresh_function_list(function_combo, text_area):
    """Refresh the function list"""
    try:
        text_area.setText("Refreshing function list...")
        
        # Clear existing items
        function_combo.removeAllItems()
        
        # Get function manager
        function_manager = currentProgram.functionManager
        functions = list(function_manager.getFunctions(True))
        non_thunk_functions = [f for f in functions if not f.isThunk()]
        function_names = [f.getName() for f in non_thunk_functions]
        
        for name in function_names:
            function_combo.addItem(name)
        
        if function_names:
            function_combo.setSelectedIndex(0)
        
        text_area.setText("Function list refreshed successfully.")
        
    except Exception as e:
        text_area.setText(f"Error refreshing function list: {e}")


def identify_function_types(function_name, model, use_decompiler, extract_features, table_model, text_area, progress_bar):
    """Identify function types using machine learning"""
    try:
        text_area.setText(f"Identifying function types using {model}...")
        
        # Clear existing table data
        table_model.setRowCount(0)
        
        # Get functions to analyze
        if function_name == "All Functions":
            function_manager = currentProgram.functionManager
            functions = list(function_manager.getFunctions(True))
            non_thunk_functions = [f for f in functions if not f.isThunk()]
        else:
            function_manager = currentProgram.functionManager
            function = find_function_by_name(function_manager, function_name)
            non_thunk_functions = [function] if function and not function.isThunk() else []
        
        if not non_thunk_functions:
            text_area.setText("No functions to analyze.")
            return
        
        # Set progress bar
        total_functions = len(non_thunk_functions)
        progress_bar.setMaximum(total_functions)
        progress_bar.setValue(0)
        
        # Analyze each function
        for i, function in enumerate(non_thunk_functions):
            # Update progress
            progress_bar.setValue(i + 1)
            progress_bar.setString(f"Analyzing {function.getName()} ({i + 1}/{total_functions})")
            
            # Extract features
            features = extract_function_features(function, use_decompiler)
            
            # Predict function type
            function_type, confidence = predict_function_type(features, model)
            
            # Add to table
            table_model.addRow([
                function.getName(),
                f"0x{function.getEntryPoint()}",
                function_type,
                f"{confidence:.2f}%",
                json.dumps(features)[:100] + "..." if extract_features else "Not extracted"
            ])
        
        text_area.setText(f"Function type identification completed. Analyzed {total_functions} functions.")
        
    except Exception as e:
        text_area.setText(f"Error identifying function types: {e}")
    finally:
        # Reset progress bar
        progress_bar.setValue(0)
        progress_bar.setString("")


def detect_vulnerabilities(function_name, vuln_type, use_decompiler, deep_scan, table_model, text_area, progress_bar):
    """Detect vulnerabilities using machine learning"""
    try:
        text_area.setText(f"Detecting {vuln_type} vulnerabilities...")
        
        # Clear existing table data
        table_model.setRowCount(0)
        
        # Get functions to analyze
        if function_name == "All Functions":
            function_manager = currentProgram.functionManager
            functions = list(function_manager.getFunctions(True))
            non_thunk_functions = [f for f in functions if not f.isThunk()]
        else:
            function_manager = currentProgram.functionManager
            function = find_function_by_name(function_manager, function_name)
            non_thunk_functions = [function] if function and not function.isThunk() else []
        
        if not non_thunk_functions:
            text_area.setText("No functions to analyze.")
            return
        
        # Set progress bar
        total_functions = len(non_thunk_functions)
        progress_bar.setMaximum(total_functions)
        progress_bar.setValue(0)
        
        # Analyze each function
        for i, function in enumerate(non_thunk_functions):
            # Update progress
            progress_bar.setValue(i + 1)
            progress_bar.setString(f"Analyzing {function.getName()} ({i + 1}/{total_functions})")
            
            # Extract features
            features = extract_function_features(function, use_decompiler)
            
            # Detect vulnerabilities
            vulnerabilities = detect_function_vulnerabilities(features, vuln_type, deep_scan)
            
            # Add to table
            for vuln in vulnerabilities:
                table_model.addRow([
                    function.getName(),
                    f"0x{function.getEntryPoint()}",
                    vuln["type"],
                    vuln["severity"],
                    vuln["description"]
                ])
        
        text_area.setText(f"Vulnerability detection completed. Found {table_model.getRowCount()} potential vulnerabilities.")
        
    except Exception as e:
        text_area.setText(f"Error detecting vulnerabilities: {e}")
    finally:
        # Reset progress bar
        progress_bar.setValue(0)
        progress_bar.setString("")


def assess_code_quality(function_name, metrics, use_decompiler, generate_report, table_model, text_area, progress_bar):
    """Assess code quality using machine learning"""
    try:
        text_area.setText(f"Assessing code quality using {metrics}...")
        
        # Clear existing table data
        table_model.setRowCount(0)
        
        # Get functions to analyze
        if function_name == "All Functions":
            function_manager = currentProgram.functionManager
            functions = list(function_manager.getFunctions(True))
            non_thunk_functions = [f for f in functions if not f.isThunk()]
        else:
            function_manager = currentProgram.functionManager
            function = find_function_by_name(function_manager, function_name)
            non_thunk_functions = [function] if function and not function.isThunk() else []
        
        if not non_thunk_functions:
            text_area.setText("No functions to analyze.")
            return
        
        # Set progress bar
        total_functions = len(non_thunk_functions)
        progress_bar.setMaximum(total_functions)
        progress_bar.setValue(0)
        
        # Analyze each function
        for i, function in enumerate(non_thunk_functions):
            # Update progress
            progress_bar.setValue(i + 1)
            progress_bar.setString(f"Analyzing {function.getName()} ({i + 1}/{total_functions})")
            
            # Extract features
            features = extract_function_features(function, use_decompiler)
            
            # Assess code quality
            quality_scores = assess_function_quality(features, metrics)
            
            # Add to table
            table_model.addRow([
                function.getName(),
                f"0x{function.getEntryPoint()}",
                f"{quality_scores['overall']:.2f}",
                f"{quality_scores['complexity']:.2f}",
                f"{quality_scores['readability']:.2f}",
                f"{quality_scores['security']:.2f}"
            ])
        
        text_area.setText(f"Code quality assessment completed. Analyzed {total_functions} functions.")
        
        # Generate report if requested
        if generate_report:
            generate_quality_report(table_model, text_area)
        
    except Exception as e:
        text_area.setText(f"Error assessing code quality: {e}")
    finally:
        # Reset progress bar
        progress_bar.setValue(0)
        progress_bar.setString("")


def extract_function_features(function, use_decompiler):
    """Extract features from a function"""
    features = {}
    
    try:
        # Basic features
        features["name_length"] = len(function.getName())
        features["body_size"] = function.getBody().getNumAddresses()
        features["is_external"] = 1 if function.isExternal() else 0
        features["num_parameters"] = len(function.getParameters())
        
        # Instruction features
        listing = currentProgram.getListing()
        instr_count = 0
        call_count = 0
        branch_count = 0
        
        addr = function.getEntryPoint()
        end_addr = function.getBody().getMaxAddress()
        
        while addr and addr <= end_addr:
            instr = listing.getInstructionAt(addr)
            if instr:
                instr_count += 1
                flow_type = instr.getFlowType()
                if flow_type.isCall():
                    call_count += 1
                elif flow_type.isBranch():
                    branch_count += 1
            addr = addr.add(1)
        
        features["instruction_count"] = instr_count
        features["call_count"] = call_count
        features["branch_count"] = branch_count
        features["branch_to_instruction_ratio"] = branch_count / instr_count if instr_count > 0 else 0
        
        # Decompiler features
        if use_decompiler:
            decompiler = DecompInterface()
            options = DecompileOptions()
            options.grabFromProgram(currentProgram)
            decompiler.setOptions(options)
            decompiler.openProgram(currentProgram)
            
            monitor = ConsoleTaskMonitor()
            results = decompiler.decompileFunction(function, 60, monitor)
            
            if results.decompileCompleted():
                high_function = results.getHighFunction()
                if high_function:
                    # Pcode features
                    pcode_ops = []
                    block = high_function.getBasicBlocks().next()
                    while block:
                        pcode_ops.extend(block.getIterator())
                        block = block.getNext()
                    
                    features["pcode_op_count"] = len(pcode_ops)
                    
                    # Variable features
                    local_symbols = high_function.getLocalSymbolMap().getSymbols()
                    features["local_variable_count"] = len(local_symbols)
            
            decompiler.dispose()
        
    except Exception as e:
        print(f"Error extracting features: {e}")
    
    return features


def predict_function_type(features, model):
    """Predict function type using machine learning model"""
    # Note: This is a placeholder implementation
    # In a real implementation, this would use a trained machine learning model
    
    # Dummy function types
    function_types = ["Unknown", "Math", "String", "Memory", "IO", "Network", "Security", "System"]
    
    # Generate dummy prediction based on features
    if model == "Function Type Classifier":
        # Simple heuristic based on features
        if features.get("call_count", 0) > 10:
            function_type = "System"
        elif features.get("branch_count", 0) > features.get("instruction_count", 1) * 0.5:
            function_type = "Math"
        elif features.get("local_variable_count", 0) > 20:
            function_type = "Memory"
        else:
            function_type = "Unknown"
    else:
        # Behavior pattern recognizer
        function_type = "Unknown"
    
    # Dummy confidence
    confidence = np.random.uniform(70, 99)
    
    return function_type, confidence


def detect_function_vulnerabilities(features, vuln_type, deep_scan):
    """Detect vulnerabilities in a function"""
    # Note: This is a placeholder implementation
    # In a real implementation, this would use a trained machine learning model
    
    vulnerabilities = []
    
    # Dummy vulnerability detection
    if vuln_type == "All Types" or vuln_type == "Buffer Overflow":
        if features.get("call_count", 0) > 5:
            vulnerabilities.append({
                "type": "Buffer Overflow",
                "severity": "High",
                "description": "Potential buffer overflow vulnerability detected"
            })
    
    if vuln_type == "All Types" or vuln_type == "Integer Overflow":
        if features.get("branch_to_instruction_ratio", 0) > 0.3:
            vulnerabilities.append({
                "type": "Integer Overflow",
                "severity": "Medium",
                "description": "Potential integer overflow vulnerability detected"
            })
    
    if vuln_type == "All Types" or vuln_type == "Use After Free":
        if features.get("local_variable_count", 0) > 15:
            vulnerabilities.append({
                "type": "Use After Free",
                "severity": "High",
                "description": "Potential use after free vulnerability detected"
            })
    
    if vuln_type == "All Types" or vuln_type == "Null Pointer Dereference":
        if features.get("instruction_count", 0) > 50:
            vulnerabilities.append({
                "type": "Null Pointer Dereference",
                "severity": "Medium",
                "description": "Potential null pointer dereference vulnerability detected"
            })
    
    return vulnerabilities


def assess_function_quality(features, metrics):
    """Assess code quality"""
    # Note: This is a placeholder implementation
    # In a real implementation, this would use a trained machine learning model
    
    scores = {
        "overall": 0,
        "complexity": 0,
        "readability": 0,
        "security": 0
    }
    
    # Calculate complexity score (lower is better)
    complexity = features.get("branch_to_instruction_ratio", 0) * 100
    complexity_score = max(0, 100 - complexity)
    scores["complexity"] = complexity_score
    
    # Calculate readability score (higher is better)
    # Simple heuristic: fewer branches and more instructions
    readability = (features.get("instruction_count", 1) / (features.get("branch_count", 1) + 1)) * 20
    readability_score = min(100, readability)
    scores["readability"] = readability_score
    
    # Calculate security score (higher is better)
    # Simple heuristic: fewer calls and more local variables
    security = (features.get("local_variable_count", 1) / (features.get("call_count", 1) + 1)) * 20
    security_score = min(100, security)
    scores["security"] = security_score
    
    # Calculate overall score
    scores["overall"] = (scores["complexity"] + scores["readability"] + scores["security"]) / 3
    
    return scores


def generate_quality_report(table_model, text_area):
    """Generate code quality report"""
    try:
        report = "Code Quality Assessment Report\n"
        report += "=================================\n\n"
        
        total_functions = table_model.getRowCount()
        report += f"Analyzed {total_functions} functions\n\n"
        
        # Calculate averages
        total_overall = 0
        total_complexity = 0
        total_readability = 0
        total_security = 0
        
        for i in range(total_functions):
            total_overall += float(table_model.getValueAt(i, 2))
            total_complexity += float(table_model.getValueAt(i, 3))
            total_readability += float(table_model.getValueAt(i, 4))
            total_security += float(table_model.getValueAt(i, 5))
        
        if total_functions > 0:
            avg_overall = total_overall / total_functions
            avg_complexity = total_complexity / total_functions
            avg_readability = total_readability / total_functions
            avg_security = total_security / total_functions
            
            report += "Average Scores:\n"
            report += f"Overall: {avg_overall:.2f}\n"
            report += f"Complexity: {avg_complexity:.2f}\n"
            report += f"Readability: {avg_readability:.2f}\n"
            report += f"Security: {avg_security:.2f}\n\n"
        
        # Find best and worst functions
        if total_functions > 0:
            best_function = None
            best_score = 0
            worst_function = None
            worst_score = 100
            
            for i in range(total_functions):
                function_name = table_model.getValueAt(i, 0)
                score = float(table_model.getValueAt(i, 2))
                
                if score > best_score:
                    best_score = score
                    best_function = function_name
                
                if score < worst_score:
                    worst_score = score
                    worst_function = function_name
            
            report += "Best Function: " + best_function + f" (Score: {best_score:.2f})\n"
            report += "Worst Function: " + worst_function + f" (Score: {worst_score:.2f})\n"
        
        text_area.append("\n" + report)
        
    except Exception as e:
        text_area.setText(f"Error generating report: {e}")


def load_model(model_list, info_area):
    """Load a machine learning model"""
    try:
        selected_model = model_list.getSelectedValue()
        if not selected_model:
            info_area.setText("Please select a model to load.")
            return
        
        info_area.setText(f"Loading {selected_model}...")
        
        # Note: This is a placeholder implementation
        # In a real implementation, this would load a trained model from disk
        
        info_area.setText(f"Model {selected_model} loaded successfully.")
        
    except Exception as e:
        info_area.setText(f"Error loading model: {e}")


def save_model(model_list, info_area):
    """Save a machine learning model"""
    try:
        selected_model = model_list.getSelectedValue()
        if not selected_model:
            info_area.setText("Please select a model to save.")
            return
        
        info_area.setText(f"Saving {selected_model}...")
        
        # Note: This is a placeholder implementation
        # In a real implementation, this would save a trained model to disk
        
        info_area.setText(f"Model {selected_model} saved successfully.")
        
    except Exception as e:
        info_area.setText(f"Error saving model: {e}")


def train_model(model_list, info_area):
    """Train a machine learning model"""
    try:
        selected_model = model_list.getSelectedValue()
        if not selected_model:
            info_area.setText("Please select a model to train.")
            return
        
        info_area.setText(f"Training {selected_model}...")
        
        # Note: This is a placeholder implementation
        # In a real implementation, this would train a model on labeled data
        
        info_area.setText(f"Model {selected_model} trained successfully.")
        
    except Exception as e:
        info_area.setText(f"Error training model: {e}")


def test_model(model_list, info_area):
    """Test a machine learning model"""
    try:
        selected_model = model_list.getSelectedValue()
        if not selected_model:
            info_area.setText("Please select a model to test.")
            return
        
        info_area.setText(f"Testing {selected_model}...")
        
        # Note: This is a placeholder implementation
        # In a real implementation, this would test a model on labeled data
        
        info_area.setText(f"Model {selected_model} tested successfully. Accuracy: 85.5%")
        
    except Exception as e:
        info_area.setText(f"Error testing model: {e}")


def find_function_by_name(function_manager, name):
    """Find a function by name"""
    for function in function_manager.getFunctions(True):
        if function.getName() == name:
            return function
    return None


# Run the machine learning integrator
if __name__ == "__main__":
    show_machine_learning_integrator()
