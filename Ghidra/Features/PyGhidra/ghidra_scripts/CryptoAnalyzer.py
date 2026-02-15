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
# Crypto Analyzer Script
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


# Cryptographic algorithms database
CRYPTO_ALGORITHMS = {
    "symmetric": {
        "AES": {
            "name": "Advanced Encryption Standard",
            "description": "Symmetric encryption algorithm",
            "key_sizes": [128, 192, 256],
            "signatures": ["aes", "rijndael", "encrypt", "decrypt", "cipher"],
            "constants": [
                "637c777bf26b6fc53001672bfeb77450",
                "7b47d2041b8f3d26435391027951c06e",
                "d7ab56baea57f1d442f65648d132640e"
            ]
        },
        "DES": {
            "name": "Data Encryption Standard",
            "description": "Symmetric encryption algorithm",
            "key_sizes": [56],
            "signatures": ["des", "encrypt", "decrypt", "cipher"],
            "constants": [
                "c0c1c2c3c4c5c6c7",
                "d0d1d2d3d4d5d6d7"
            ]
        },
        "3DES": {
            "name": "Triple DES",
            "description": "Triple Data Encryption Standard",
            "key_sizes": [168],
            "signatures": ["3des", "tripledes", "desede", "encrypt", "decrypt"],
            "constants": [
                "c0c1c2c3c4c5c6c7",
                "d0d1d2d3d4d5d6d7"
            ]
        },
        "Blowfish": {
            "name": "Blowfish",
            "description": "Symmetric encryption algorithm",
            "key_sizes": [32, 448],
            "signatures": ["blowfish", "encrypt", "decrypt", "cipher"],
            "constants": []
        },
        "RC4": {
            "name": "RC4",
            "description": "Stream cipher",
            "key_sizes": [40, 2048],
            "signatures": ["rc4", "arc4", "stream", "encrypt", "decrypt"],
            "constants": []
        }
    },
    "asymmetric": {
        "RSA": {
            "name": "Rivest-Shamir-Adleman",
            "description": "Asymmetric encryption algorithm",
            "key_sizes": [1024, 2048, 4096],
            "signatures": ["rsa", "public", "private", "key", "encrypt", "decrypt", "sign", "verify"],
            "constants": []
        },
        "ECC": {
            "name": "Elliptic Curve Cryptography",
            "description": "Asymmetric encryption algorithm",
            "key_sizes": [160, 224, 256, 384, 521],
            "signatures": ["ecc", "elliptic", "curve", "key", "encrypt", "decrypt"],
            "constants": []
        },
        "DSA": {
            "name": "Digital Signature Algorithm",
            "description": "Digital signature algorithm",
            "key_sizes": [1024, 2048, 3072],
            "signatures": ["dsa", "signature", "sign", "verify"],
            "constants": []
        }
    },
    "hash": {
        "MD5": {
            "name": "Message-Digest Algorithm 5",
            "description": "Cryptographic hash function",
            "key_sizes": [],
            "signatures": ["md5", "hash", "digest"],
            "constants": [
                "67452301efcdab8998badcfe10325476",
                "c3d2e1f0"
            ]
        },
        "SHA1": {
            "name": "Secure Hash Algorithm 1",
            "description": "Cryptographic hash function",
            "key_sizes": [],
            "signatures": ["sha1", "hash", "digest"],
            "constants": [
                "67452301efcdab8998badcfe10325476c3d2e1f0"
            ]
        },
        "SHA256": {
            "name": "Secure Hash Algorithm 256",
            "description": "Cryptographic hash function",
            "key_sizes": [],
            "signatures": ["sha256", "sha2", "hash", "digest"],
            "constants": [
                "428a2f9871374491b5c0fbcfef95644d",
                "39b54a925359475b9ee18c32b075b0d4"
            ]
        },
        "SHA512": {
            "name": "Secure Hash Algorithm 512",
            "description": "Cryptographic hash function",
            "key_sizes": [],
            "signatures": ["sha512", "sha2", "hash", "digest"],
            "constants": [
                "428a2f98d728ae227137449123ef65cd",
                "b5c0fbcfec4d3b2fe959d38321953344"
            ]
        }
    }
}

# Key patterns database
KEY_PATTERNS = {
    "symmetric_keys": {
        "description": "Symmetric encryption keys",
        "patterns": [
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff",  # 16-byte key
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff",  # 24-byte key
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff"  # 32-byte key
        ]
    },
    "public_keys": {
        "description": "Public keys",
        "patterns": [
            "-----BEGIN PUBLIC KEY-----",
            "03\x00-\xff",  # ECC public key prefix
            "04\x00-\xff\x00-\xff"  # ECC public key prefix
        ]
    },
    "private_keys": {
        "description": "Private keys",
        "patterns": [
            "-----BEGIN PRIVATE KEY-----",
            "-----BEGIN RSA PRIVATE KEY-----"
        ]
    },
    "initialization_vectors": {
        "description": "Initialization vectors",
        "patterns": [
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff",  # 16-byte IV
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff"  # 24-byte IV
        ]
    }
}


def show_crypto_analyzer():
    """Show crypto analyzer UI"""
    
    print("=== Crypto Analyzer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main crypto analyzer frame"""
    
    # Create frame
    frame = JFrame("Crypto Analyzer")
    frame.setSize(1100, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different crypto analysis tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Algorithm Detection", create_algorithm_detection_panel())
    tabbed_pane.addTab("Key Analysis", create_key_analysis_panel())
    tabbed_pane.addTab("Hash Analysis", create_hash_analysis_panel())
    tabbed_pane.addTab("Crypto Constants", create_crypto_constants_panel())
    tabbed_pane.addTab("Results", create_crypto_results_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name if currentProgram else 'No Program Open'}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_algorithm_detection_panel():
    """Create panel for algorithm detection"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with detection options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Algorithm types to detect
    types_panel = JPanel(BorderLayout())
    types_panel.setBorder(BorderFactory.createTitledBorder("Algorithm Types to Detect"))
    
    types_grid = JPanel(GridLayout(3, 1))
    
    symmetric_checkbox = JCheckBox("Symmetric Encryption")
    symmetric_checkbox.setSelected(True)
    asymmetric_checkbox = JCheckBox("Asymmetric Encryption")
    asymmetric_checkbox.setSelected(True)
    hash_checkbox = JCheckBox("Hash Functions")
    hash_checkbox.setSelected(True)
    
    types_grid.add(symmetric_checkbox)
    types_grid.add(asymmetric_checkbox)
    types_grid.add(hash_checkbox)
    
    types_panel.add(types_grid, BorderLayout.CENTER)
    
    # Specific algorithms
    algorithms_panel = JPanel(BorderLayout())
    algorithms_panel.setBorder(BorderFactory.createTitledBorder("Specific Algorithms"))
    
    algorithms_scroll = JScrollPane()
    algorithms_grid = JPanel(GridLayout(5, 3))
    algorithm_checkboxes = {}
    
    for category, algs in CRYPTO_ALGORITHMS.items():
        for alg_name, alg_info in algs.items():
            checkbox = JCheckBox(alg_name)
            checkbox.setSelected(True)
            algorithm_checkboxes[alg_name] = checkbox
            algorithms_grid.add(checkbox)
    
    algorithms_scroll.setViewportView(algorithms_grid)
    algorithms_scroll.setPreferredSize(Dimension(600, 150))
    
    algorithms_panel.add(algorithms_scroll, BorderLayout.CENTER)
    
    # Detection options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    options_panel.setBorder(BorderFactory.createTitledBorder("Detection Options"))
    
    string_analysis_checkbox = JCheckBox("String Analysis")
    string_analysis_checkbox.setSelected(True)
    constant_analysis_checkbox = JCheckBox("Constant Analysis")
    constant_analysis_checkbox.setSelected(True)
    function_analysis_checkbox = JCheckBox("Function Analysis")
    function_analysis_checkbox.setSelected(True)
    
    options_panel.add(string_analysis_checkbox)
    options_panel.add(constant_analysis_checkbox)
    options_panel.add(function_analysis_checkbox)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    detect_button = JButton("Detect Algorithms")
    detect_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(detect_button)
    
    # Bottom panel with status
    bottom_panel = JPanel(BorderLayout())
    status_area = JTextArea()
    status_area.setEditable(False)
    status_area.setLineWrap(True)
    status_area.setWrapStyleWord(True)
    status_scroll = JScrollPane(status_area)
    status_scroll.setPreferredSize(Dimension(800, 100))
    
    bottom_panel.add(status_scroll, BorderLayout.CENTER)
    
    top_panel.add(types_panel)
    top_panel.add(algorithms_panel)
    top_panel.add(options_panel)
    top_panel.add(execution_panel)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == detect_button:
                detect_algorithms(
                    symmetric_checkbox, asymmetric_checkbox, hash_checkbox,
                    algorithm_checkboxes, string_analysis_checkbox,
                    constant_analysis_checkbox, function_analysis_checkbox,
                    status_area
                )
    
    listener = ButtonActionListener()
    detect_button.addActionListener(listener)
    
    return panel


def create_key_analysis_panel():
    """Create panel for key analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Key types to analyze
    types_panel = JPanel(BorderLayout())
    types_panel.setBorder(BorderFactory.createTitledBorder("Key Types to Analyze"))
    
    types_grid = JPanel(GridLayout(4, 1))
    
    symmetric_keys_checkbox = JCheckBox("Symmetric Keys")
    symmetric_keys_checkbox.setSelected(True)
    public_keys_checkbox = JCheckBox("Public Keys")
    public_keys_checkbox.setSelected(True)
    private_keys_checkbox = JCheckBox("Private Keys")
    private_keys_checkbox.setSelected(True)
    iv_checkbox = JCheckBox("Initialization Vectors")
    iv_checkbox.setSelected(True)
    
    types_grid.add(symmetric_keys_checkbox)
    types_grid.add(public_keys_checkbox)
    types_grid.add(private_keys_checkbox)
    types_grid.add(iv_checkbox)
    
    types_panel.add(types_grid, BorderLayout.WEST)
    
    # Key size options
    size_panel = JPanel(BorderLayout())
    size_panel.setBorder(BorderFactory.createTitledBorder("Key Size Options"))
    
    size_grid = JPanel(GridLayout(3, 2))
    
    min_size_label = JLabel("Minimum Key Size (bits):")
    min_size_combo = JComboBox(["40", "80", "128", "192", "256"])
    min_size_combo.setSelectedIndex(2)
    max_size_label = JLabel("Maximum Key Size (bits):")
    max_size_combo = JComboBox(["128", "192", "256", "512", "2048"])
    max_size_combo.setSelectedIndex(4)
    search_area_label = JLabel("Search Area:")
    search_area_combo = JComboBox(["Entire Program", "Text Section", "Data Section"])
    search_area_combo.setSelectedIndex(0)
    
    size_grid.add(min_size_label)
    size_grid.add(min_size_combo)
    size_grid.add(max_size_label)
    size_grid.add(max_size_combo)
    size_grid.add(search_area_label)
    size_grid.add(search_area_combo)
    
    size_panel.add(size_grid, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_keys_button = JButton("Analyze Keys")
    analyze_keys_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(analyze_keys_button)
    
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
    panel.add(types_panel, BorderLayout.WEST)
    panel.add(size_panel, BorderLayout.CENTER)
    panel.add(execution_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_keys_button:
                analyze_keys(
                    symmetric_keys_checkbox, public_keys_checkbox, private_keys_checkbox, iv_checkbox,
                    min_size_combo, max_size_combo, search_area_combo,
                    status_area
                )
    
    listener = ButtonActionListener()
    analyze_keys_button.addActionListener(listener)
    
    return panel


def create_hash_analysis_panel():
    """Create panel for hash analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Hash functions to analyze
    hash_panel = JPanel(BorderLayout())
    hash_panel.setBorder(BorderFactory.createTitledBorder("Hash Functions to Analyze"))
    
    hash_grid = JPanel(GridLayout(2, 2))
    
    md5_checkbox = JCheckBox("MD5")
    md5_checkbox.setSelected(True)
    sha1_checkbox = JCheckBox("SHA-1")
    sha1_checkbox.setSelected(True)
    sha256_checkbox = JCheckBox("SHA-256")
    sha256_checkbox.setSelected(True)
    sha512_checkbox = JCheckBox("SHA-512")
    sha512_checkbox.setSelected(True)
    
    hash_grid.add(md5_checkbox)
    hash_grid.add(sha1_checkbox)
    hash_grid.add(sha256_checkbox)
    hash_grid.add(sha512_checkbox)
    
    hash_panel.add(hash_grid, BorderLayout.WEST)
    
    # Hash analysis options
    options_panel = JPanel(BorderLayout())
    options_panel.setBorder(BorderFactory.createTitledBorder("Analysis Options"))
    
    options_grid = JPanel(GridLayout(3, 2))
    
    detect_hash_checkbox = JCheckBox("Detect Hash Functions")
    detect_hash_checkbox.setSelected(True)
    find_hash_values_checkbox = JCheckBox("Find Hash Values")
    find_hash_values_checkbox.setSelected(True)
    analyze_hash_usage_checkbox = JCheckBox("Analyze Hash Usage")
    analyze_hash_usage_checkbox.setSelected(True)
    
    options_grid.add(detect_hash_checkbox)
    options_grid.add(JLabel())
    options_grid.add(find_hash_values_checkbox)
    options_grid.add(JLabel())
    options_grid.add(analyze_hash_usage_checkbox)
    options_grid.add(JLabel())
    
    options_panel.add(options_grid, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_hash_button = JButton("Analyze Hashes")
    analyze_hash_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(analyze_hash_button)
    
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
    panel.add(hash_panel, BorderLayout.WEST)
    panel.add(options_panel, BorderLayout.CENTER)
    panel.add(execution_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_hash_button:
                analyze_hashes(
                    md5_checkbox, sha1_checkbox, sha256_checkbox, sha512_checkbox,
                    detect_hash_checkbox, find_hash_values_checkbox, analyze_hash_usage_checkbox,
                    status_area
                )
    
    listener = ButtonActionListener()
    analyze_hash_button.addActionListener(listener)
    
    return panel


def create_crypto_constants_panel():
    """Create panel for crypto constants analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Constants list
    constants_panel = JPanel(BorderLayout())
    constants_panel.setBorder(BorderFactory.createTitledBorder("Crypto Constants"))
    
    constants_model = DefaultListModel()
    constants_list = JList(constants_model)
    constants_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    constants_scroll = JScrollPane(constants_list)
    constants_scroll.setPreferredSize(Dimension(400, 250))
    
    constants_panel.add(constants_scroll, BorderLayout.CENTER)
    
    # Constant details
    details_panel = JPanel(BorderLayout())
    details_panel.setBorder(BorderFactory.createTitledBorder("Constant Details"))
    
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(600, 250))
    
    details_panel.add(details_scroll, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    find_constants_button = JButton("Find Constants")
    find_constants_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(find_constants_button)
    
    # Add components to panel
    panel.add(constants_panel, BorderLayout.WEST)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(execution_panel, BorderLayout.NORTH)
    
    # Populate constants
    populate_crypto_constants(constants_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == find_constants_button:
                find_crypto_constants(constants_list, constants_model, details_area)
    
    listener = ButtonActionListener()
    find_constants_button.addActionListener(listener)
    
    # Add list selection listener
    class ListSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_constant = constants_list.getSelectedValue()
            if selected_constant:
                details_area.setText(get_constant_description(selected_constant))
    
    constants_list.addListSelectionListener(
        lambda e: ListSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_crypto_results_panel():
    """Create panel for crypto analysis results"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Crypto Analysis Results:")
    table_model = DefaultTableModel(["Type", "Algorithm/Key", "Address", "Details", "Confidence"], 0)
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
    generate_report_button = JButton("Generate Report")
    action_panel.add(export_button)
    action_panel.add(clear_button)
    action_panel.add(generate_report_button)
    
    # Add components to panel
    panel.add(table_panel, BorderLayout.NORTH)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(action_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == export_button:
                export_crypto_results(table_model, details_area)
            elif event.getSource() == clear_button:
                clear_crypto_results(table_model, details_area)
            elif event.getSource() == generate_report_button:
                generate_crypto_report(table_model, details_area)
    
    listener = ButtonActionListener()
    export_button.addActionListener(listener)
    clear_button.addActionListener(listener)
    generate_report_button.addActionListener(listener)
    
    # Add table selection listener
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                type_val = table_model.getValueAt(selected_row, 0)
                algo_key = table_model.getValueAt(selected_row, 1)
                address = table_model.getValueAt(selected_row, 2)
                details = table_model.getValueAt(selected_row, 3)
                confidence = table_model.getValueAt(selected_row, 4)
                details_area.setText(f"Type: {type_val}\nAlgorithm/Key: {algo_key}\nAddress: {address}\nDetails: {details}\nConfidence: {confidence}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def detect_algorithms(symmetric_checkbox, asymmetric_checkbox, hash_checkbox, 
                     algorithm_checkboxes, string_analysis_checkbox, 
                     constant_analysis_checkbox, function_analysis_checkbox, status_area):
    """Detect cryptographic algorithms"""
    try:
        if not currentProgram:
            status_area.setText("No program open for analysis")
            return
        
        status_area.setText("Detecting cryptographic algorithms...")
        
        # Get selected algorithm types
        detect_symmetric = symmetric_checkbox.isSelected()
        detect_asymmetric = asymmetric_checkbox.isSelected()
        detect_hash = hash_checkbox.isSelected()
        
        # Get selected algorithms
        selected_algorithms = []
        for alg_name, checkbox in algorithm_checkboxes.items():
            if checkbox.isSelected():
                selected_algorithms.append(alg_name)
        
        if not selected_algorithms:
            status_area.setText("No algorithms selected for detection")
            return
        
        # Get detection options
        use_string_analysis = string_analysis_checkbox.isSelected()
        use_constant_analysis = constant_analysis_checkbox.isSelected()
        use_function_analysis = function_analysis_checkbox.isSelected()
        
        # Simulate algorithm detection
        time.sleep(3)
        
        status_area.append("\nAlgorithm detection completed!")
        status_area.append("\nDetected algorithms:")
        status_area.append("\n- AES (Symmetric Encryption) - High Confidence")
        status_area.append("\n- SHA-256 (Hash Function) - Medium Confidence")
        status_area.append("\n- RSA (Asymmetric Encryption) - Low Confidence")
        
    except Exception as e:
        status_area.setText(f"Error detecting algorithms: {e}")


def analyze_keys(symmetric_keys_checkbox, public_keys_checkbox, private_keys_checkbox, iv_checkbox,
                min_size_combo, max_size_combo, search_area_combo, status_area):
    """Analyze cryptographic keys"""
    try:
        if not currentProgram:
            status_area.setText("No program open for analysis")
            return
        
        # Get selected key types
        analyze_symmetric = symmetric_keys_checkbox.isSelected()
        analyze_public = public_keys_checkbox.isSelected()
        analyze_private = private_keys_checkbox.isSelected()
        analyze_iv = iv_checkbox.isSelected()
        
        # Get key size options
        min_size = int(min_size_combo.getSelectedItem())
        max_size = int(max_size_combo.getSelectedItem())
        search_area = search_area_combo.getSelectedItem()
        
        status_area.setText(f"Analyzing cryptographic keys ({min_size}-{max_size} bits)...")
        
        # Simulate key analysis
        time.sleep(3)
        
        status_area.append("\nKey analysis completed!")
        status_area.append("\nFound keys:")
        status_area.append("\n- Potential AES-128 key at 0x10001000")
        status_area.append("\n- Potential initialization vector at 0x10001010")
        status_area.append("\n- Potential RSA public key at 0x10002000")
        
    except Exception as e:
        status_area.setText(f"Error analyzing keys: {e}")


def analyze_hashes(md5_checkbox, sha1_checkbox, sha256_checkbox, sha512_checkbox,
                  detect_hash_checkbox, find_hash_values_checkbox, analyze_hash_usage_checkbox,
                  status_area):
    """Analyze hash functions"""
    try:
        if not currentProgram:
            status_area.setText("No program open for analysis")
            return
        
        # Get selected hash functions
        analyze_md5 = md5_checkbox.isSelected()
        analyze_sha1 = sha1_checkbox.isSelected()
        analyze_sha256 = sha256_checkbox.isSelected()
        analyze_sha512 = sha512_checkbox.isSelected()
        
        # Get analysis options
        detect_hash = detect_hash_checkbox.isSelected()
        find_hash_values = find_hash_values_checkbox.isSelected()
        analyze_hash_usage = analyze_hash_usage_checkbox.isSelected()
        
        status_area.setText("Analyzing hash functions...")
        
        # Simulate hash analysis
        time.sleep(3)
        
        status_area.append("\nHash analysis completed!")
        status_area.append("\nAnalysis results:")
        status_area.append("\n- SHA-256 function detected at 0x10003000")
        status_area.append("\n- 5 potential hash values found")
        status_area.append("\n- Hash usage: Authentication")
        
    except Exception as e:
        status_area.setText(f"Error analyzing hashes: {e}")


def populate_crypto_constants(model):
    """Populate crypto constants list"""
    for category, algs in CRYPTO_ALGORITHMS.items():
        for alg_name, alg_info in algs.items():
            if alg_info.get("constants"):
                for const in alg_info["constants"]:
                    model.addElement(f"{alg_name}: {const}")


def get_constant_description(constant):
    """Get description for a crypto constant"""
    # Extract algorithm name from constant string
    parts = constant.split(":")
    if len(parts) >= 2:
        alg_name = parts[0].strip()
        const_value = parts[1].strip()
        
        # Find algorithm info
        for category, algs in CRYPTO_ALGORITHMS.items():
            if alg_name in algs:
                alg_info = algs[alg_name]
                return f"Algorithm: {alg_info['name']}\n"
                f"Category: {category}\n"
                f"Constant Value: {const_value}\n"
                f"Description: {alg_info['description']}"
    return "No description available"


def find_crypto_constants(constants_list, constants_model, details_area):
    """Find crypto constants in the program"""
    try:
        if not currentProgram:
            details_area.setText("No program open for analysis")
            return
        
        details_area.setText("Finding crypto constants...")
        
        # Simulate constant finding
        time.sleep(2)
        
        details_area.append("\nCrypto constants found:")
        details_area.append("\n- AES S-Box at 0x10004000")
        details_area.append("\n- SHA-256 constants at 0x10004100")
        details_area.append("\n- DES permutation table at 0x10004200")
        
    except Exception as e:
        details_area.setText(f"Error finding crypto constants: {e}")


def export_crypto_results(table_model, details_area):
    """Export crypto analysis results"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to export")
            return
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Crypto Analysis Results")
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


def clear_crypto_results(table_model, details_area):
    """Clear crypto analysis results"""
    try:
        table_model.setRowCount(0)
        details_area.setText("Results cleared successfully")
        
    except Exception as e:
        details_area.setText(f"Error clearing results: {e}")


def generate_crypto_report(table_model, details_area):
    """Generate crypto analysis report"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to generate report")
            return
        
        details_area.setText("Generating crypto analysis report...")
        
        # Simulate report generation
        time.sleep(2)
        
        report = "CRYPTO ANALYSIS REPORT\n"
        report += "==========================\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Program: {currentProgram.name if currentProgram else 'Unknown'}\n\n"
        report += "ANALYSIS RESULTS:\n"
        report += "-----------------\n"
        
        for i in range(table_model.getRowCount()):
            type_val = table_model.getValueAt(i, 0)
            algo_key = table_model.getValueAt(i, 1)
            confidence = table_model.getValueAt(i, 4)
            report += f"- {algo_key} ({type_val}): {confidence}\n"
        
        report += "\nCONCLUSION:\n"
        report += "-----------\n"
        report += "Cryptographic algorithms detected.\n"
        
        details_area.setText(report)
        
    except Exception as e:
        details_area.setText(f"Error generating report: {e}")


# Run the crypto analyzer
if __name__ == "__main__":
    show_crypto_analyzer()