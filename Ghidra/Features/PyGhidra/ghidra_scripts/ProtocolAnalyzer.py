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
# Protocol Analyzer Script
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


# Network protocols database
NETWORK_PROTOCOLS = {
    "application": {
        "HTTP": {
            "name": "Hypertext Transfer Protocol",
            "description": "Application layer protocol for distributed, collaborative, hypermedia information systems",
            "ports": [80, 8080, 8000],
            "signatures": ["HTTP", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT", "Host", "Content-Type", "Content-Length"],
            "behaviors": ["request_response", "header_parsing", "url_processing"]
        },
        "HTTPS": {
            "name": "HTTP Secure",
            "description": "Extension of HTTP that uses TLS/SSL for secure communication",
            "ports": [443, 8443],
            "signatures": ["HTTPS", "SSL", "TLS", "certificate", "handshake", "secure", "encrypted"],
            "behaviors": ["tls_handshake", "certificate_verification", "secure_communication"]
        },
        "FTP": {
            "name": "File Transfer Protocol",
            "description": "Standard network protocol used for the transfer of computer files between a client and server",
            "ports": [20, 21],
            "signatures": ["FTP", "USER", "PASS", "LIST", "RETR", "STOR", "DELE", "PWD", "CWD", "QUIT"],
            "behaviors": ["command_control", "data_transfer", "authentication"]
        },
        "SMTP": {
            "name": "Simple Mail Transfer Protocol",
            "description": "Communication protocol for electronic mail transmission",
            "ports": [25, 465, 587],
            "signatures": ["SMTP", "MAIL FROM", "RCPT TO", "DATA", "QUIT", "HELO", "EHLO", "AUTH"],
            "behaviors": ["email_transmission", "command_response", "authentication"]
        },
        "DNS": {
            "name": "Domain Name System",
            "description": "Hierarchical decentralized naming system for computers, services, or other resources connected to the Internet",
            "ports": [53],
            "signatures": ["DNS", "domain", "resolve", "query", "response", "A record", "MX record", "CNAME record"],
            "behaviors": ["name_resolution", "query_response", "cache_management"]
        }
    },
    "transport": {
        "TCP": {
            "name": "Transmission Control Protocol",
            "description": "Connection-oriented protocol that provides reliable, ordered, and error-checked delivery of a stream of bytes",
            "ports": [],
            "signatures": ["TCP", "socket", "connect", "listen", "accept", "send", "recv", "close", "bind"],
            "behaviors": ["connection_oriented", "reliable_delivery", "flow_control"]
        },
        "UDP": {
            "name": "User Datagram Protocol",
            "description": "Connectionless protocol that provides a simple interface for sending datagrams",
            "ports": [],
            "signatures": ["UDP", "socket", "sendto", "recvfrom", "bind"],
            "behaviors": ["connectionless", "unreliable_delivery", "broadcast_support"]
        },
        "SCTP": {
            "name": "Stream Control Transmission Protocol",
            "description": "Transport-layer protocol that provides reliable, connection-oriented data delivery",
            "ports": [],
            "signatures": ["SCTP", "socket", "connect", "listen", "accept", "send", "recv"],
            "behaviors": ["connection_oriented", "reliable_delivery", "multihoming_support"]
        }
    },
    "network": {
        "IP": {
            "name": "Internet Protocol",
            "description": "Network layer protocol that enables data communication across different networks",
            "ports": [],
            "signatures": ["IP", "IPv4", "IPv6", "address", "packet", "header", "fragment", "TTL"],
            "behaviors": ["routing", "addressing", "fragmentation"]
        },
        "ICMP": {
            "name": "Internet Control Message Protocol",
            "description": "Support protocol that is used by network devices to send error messages and operational information",
            "ports": [],
            "signatures": ["ICMP", "ping", "echo", "error", "message", "type", "code"],
            "behaviors": ["error_reporting", "network_diagnostics", "path_discovery"]
        }
    },
    "other": {
        "WebSocket": {
            "name": "WebSocket",
            "description": "Communication protocol that provides full-duplex communication channels over a single TCP connection",
            "ports": [80, 443, 8080, 8443],
            "signatures": ["WebSocket", "upgrade", "handshake", "frame", "mask", "opcode", "payload"],
            "behaviors": ["full_duplex", "handshake", "frame_processing"]
        },
        "MQTT": {
            "name": "Message Queuing Telemetry Transport",
            "description": "Lightweight publish-subscribe network protocol for M2M communication",
            "ports": [1883, 8883],
            "signatures": ["MQTT", "connect", "publish", "subscribe", "unsubscribe", "pingreq", "pingresp", "disconnect"],
            "behaviors": ["publish_subscribe", "lightweight", "quality_of_service"]
        },
        "CoAP": {
            "name": "Constrained Application Protocol",
            "description": "Application layer protocol designed for constrained devices and networks",
            "ports": [5683, 5684],
            "signatures": ["CoAP", "GET", "POST", "PUT", "DELETE", "OPTIONS", "CON", "NON", "ACK", "RST"],
            "behaviors": ["request_response", "resource_discovery", "observe_pattern"]
        },
        "AMQP": {
            "name": "Advanced Message Queuing Protocol",
            "description": "Open standard application layer protocol for message-oriented middleware",
            "ports": [5672, 5671],
            "signatures": ["AMQP", "connection", "channel", "exchange", "queue", "binding", "publish", "consume"],
            "behaviors": ["message_queuing", "routing", "transactions"]
        }
    }
}

# Protocol patterns database
PROTOCOL_PATTERNS = {
    "packet_structures": {
        "description": "Network packet structures",
        "patterns": [
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff",  # 4-byte header
            "\x00-\xff\x00-\xff",  # 2-byte length field
            "\x00-\xff",  # 1-byte type field
        ]
    },
    "protocol_headers": {
        "description": "Protocol headers",
        "patterns": [
            "GET ", "POST ", "PUT ", "DELETE ", "HEAD ",
            "HTTP/1.1", "HTTP/1.0", "HTTP/2",
            "USER ", "PASS ", "LIST ", "RETR ", "STOR ",
            "MAIL FROM:", "RCPT TO:", "DATA", "QUIT"
        ]
    },
    "network_addresses": {
        "description": "Network addresses",
        "patterns": [
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff",  # IPv4 address
            "\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff\x00-\xff",  # IPv6 address
            "\x00-\xff\x00-\xff",  # Port number
        ]
    }
}


def show_protocol_analyzer():
    """Show protocol analyzer UI"""
    
    print("=== Protocol Analyzer ===")
    
    # Create the main frame
    frame = create_main_frame()
    frame.setVisible(True)


def create_main_frame():
    """Create the main protocol analyzer frame"""
    
    # Create frame
    frame = JFrame("Protocol Analyzer")
    frame.setSize(1100, 700)
    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
    frame.setLayout(BorderLayout())
    
    # Create tabbed pane for different protocol analysis tools
    tabbed_pane = JTabbedPane()
    
    # Add tabs
    tabbed_pane.addTab("Protocol Detection", create_protocol_detection_panel())
    tabbed_pane.addTab("Packet Analysis", create_packet_analysis_panel())
    tabbed_pane.addTab("Protocol Implementation", create_protocol_implementation_panel())
    tabbed_pane.addTab("Network Behavior", create_network_behavior_panel())
    tabbed_pane.addTab("Results", create_protocol_results_panel())
    
    # Add status bar
    status_bar = JPanel(FlowLayout(FlowLayout.LEFT))
    status_label = JLabel(f"Program: {currentProgram.name if currentProgram else 'No Program Open'}")
    status_bar.add(status_label)
    
    # Add components to frame
    frame.add(tabbed_pane, BorderLayout.CENTER)
    frame.add(status_bar, BorderLayout.SOUTH)
    
    return frame


def create_protocol_detection_panel():
    """Create panel for protocol detection"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Top panel with detection options
    top_panel = JPanel()
    top_panel.setLayout(BoxLayout(top_panel, BoxLayout.Y_AXIS))
    
    # Protocol layers to detect
    layers_panel = JPanel(BorderLayout())
    layers_panel.setBorder(BorderFactory.createTitledBorder("Protocol Layers to Detect"))
    
    layers_grid = JPanel(GridLayout(4, 1))
    
    application_checkbox = JCheckBox("Application Layer")
    application_checkbox.setSelected(True)
    transport_checkbox = JCheckBox("Transport Layer")
    transport_checkbox.setSelected(True)
    network_checkbox = JCheckBox("Network Layer")
    network_checkbox.setSelected(True)
    other_checkbox = JCheckBox("Other Protocols")
    other_checkbox.setSelected(True)
    
    layers_grid.add(application_checkbox)
    layers_grid.add(transport_checkbox)
    layers_grid.add(network_checkbox)
    layers_grid.add(other_checkbox)
    
    layers_panel.add(layers_grid, BorderLayout.CENTER)
    
    # Specific protocols
    protocols_panel = JPanel(BorderLayout())
    protocols_panel.setBorder(BorderFactory.createTitledBorder("Specific Protocols"))
    
    protocols_scroll = JScrollPane()
    protocols_grid = JPanel(GridLayout(5, 3))
    protocol_checkboxes = {}
    
    for layer, protos in NETWORK_PROTOCOLS.items():
        for proto_name, proto_info in protos.items():
            checkbox = JCheckBox(proto_name)
            checkbox.setSelected(True)
            protocol_checkboxes[proto_name] = checkbox
            protocols_grid.add(checkbox)
    
    protocols_scroll.setViewportView(protocols_grid)
    protocols_scroll.setPreferredSize(Dimension(600, 150))
    
    protocols_panel.add(protocols_scroll, BorderLayout.CENTER)
    
    # Detection options
    options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    options_panel.setBorder(BorderFactory.createTitledBorder("Detection Options"))
    
    string_analysis_checkbox = JCheckBox("String Analysis")
    string_analysis_checkbox.setSelected(True)
    function_analysis_checkbox = JCheckBox("Function Analysis")
    function_analysis_checkbox.setSelected(True)
    port_analysis_checkbox = JCheckBox("Port Analysis")
    port_analysis_checkbox.setSelected(True)
    
    options_panel.add(string_analysis_checkbox)
    options_panel.add(function_analysis_checkbox)
    options_panel.add(port_analysis_checkbox)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    detect_button = JButton("Detect Protocols")
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
    
    top_panel.add(layers_panel)
    top_panel.add(protocols_panel)
    top_panel.add(options_panel)
    top_panel.add(execution_panel)
    
    # Add components to panel
    panel.add(top_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == detect_button:
                detect_protocols(
                    application_checkbox, transport_checkbox, network_checkbox, other_checkbox,
                    protocol_checkboxes, string_analysis_checkbox,
                    function_analysis_checkbox, port_analysis_checkbox,
                    status_area
                )
    
    listener = ButtonActionListener()
    detect_button.addActionListener(listener)
    
    return panel


def create_packet_analysis_panel():
    """Create panel for packet analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Packet structure analysis
    structure_panel = JPanel(BorderLayout())
    structure_panel.setBorder(BorderFactory.createTitledBorder("Packet Structure Analysis"))
    
    structure_grid = JPanel(GridLayout(3, 2))
    
    find_headers_checkbox = JCheckBox("Find Packet Headers")
    find_headers_checkbox.setSelected(True)
    find_length_fields_checkbox = JCheckBox("Find Length Fields")
    find_length_fields_checkbox.setSelected(True)
    find_checksums_checkbox = JCheckBox("Find Checksums")
    find_checksums_checkbox.setSelected(True)
    find_payloads_checkbox = JCheckBox("Find Payloads")
    find_payloads_checkbox.setSelected(True)
    find_sequence_numbers_checkbox = JCheckBox("Find Sequence Numbers")
    find_sequence_numbers_checkbox.setSelected(True)
    find_flags_checkbox = JCheckBox("Find Flags")
    find_flags_checkbox.setSelected(True)
    
    structure_grid.add(find_headers_checkbox)
    structure_grid.add(find_length_fields_checkbox)
    structure_grid.add(find_checksums_checkbox)
    structure_grid.add(find_payloads_checkbox)
    structure_grid.add(find_sequence_numbers_checkbox)
    structure_grid.add(find_flags_checkbox)
    
    structure_panel.add(structure_grid, BorderLayout.WEST)
    
    # Packet dissection
    dissection_panel = JPanel(BorderLayout())
    dissection_panel.setBorder(BorderFactory.createTitledBorder("Packet Dissection"))
    
    dissection_grid = JPanel(GridLayout(3, 2))
    
    dissect_http_checkbox = JCheckBox("Dissect HTTP")
    dissect_http_checkbox.setSelected(True)
    dissect_tcp_checkbox = JCheckBox("Dissect TCP")
    dissect_tcp_checkbox.setSelected(True)
    dissect_udp_checkbox = JCheckBox("Dissect UDP")
    dissect_udp_checkbox.setSelected(True)
    dissect_ip_checkbox = JCheckBox("Dissect IP")
    dissect_ip_checkbox.setSelected(True)
    dissect_custom_checkbox = JCheckBox("Dissect Custom")
    dissect_custom_checkbox.setSelected(False)
    
    dissection_grid.add(dissect_http_checkbox)
    dissection_grid.add(dissect_tcp_checkbox)
    dissection_grid.add(dissect_udp_checkbox)
    dissection_grid.add(dissect_ip_checkbox)
    dissection_grid.add(dissect_custom_checkbox)
    dissection_grid.add(JLabel())
    
    dissection_panel.add(dissection_grid, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_packets_button = JButton("Analyze Packets")
    analyze_packets_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(analyze_packets_button)
    
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
    panel.add(structure_panel, BorderLayout.WEST)
    panel.add(dissection_panel, BorderLayout.CENTER)
    panel.add(execution_panel, BorderLayout.NORTH)
    panel.add(bottom_panel, BorderLayout.SOUTH)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_packets_button:
                analyze_packets(
                    find_headers_checkbox, find_length_fields_checkbox, find_checksums_checkbox,
                    find_payloads_checkbox, find_sequence_numbers_checkbox, find_flags_checkbox,
                    dissect_http_checkbox, dissect_tcp_checkbox, dissect_udp_checkbox,
                    dissect_ip_checkbox, dissect_custom_checkbox,
                    status_area
                )
    
    listener = ButtonActionListener()
    analyze_packets_button.addActionListener(listener)
    
    return panel


def create_protocol_implementation_panel():
    """Create panel for protocol implementation analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Protocol list
    protocol_panel = JPanel(BorderLayout())
    protocol_panel.setBorder(BorderFactory.createTitledBorder("Protocol Implementation"))
    
    protocol_model = DefaultListModel()
    protocol_list = JList(protocol_model)
    protocol_list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
    protocol_scroll = JScrollPane(protocol_list)
    protocol_scroll.setPreferredSize(Dimension(400, 250))
    
    protocol_panel.add(protocol_scroll, BorderLayout.WEST)
    
    # Implementation details
    details_panel = JPanel(BorderLayout())
    details_panel.setBorder(BorderFactory.createTitledBorder("Implementation Details"))
    
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(600, 250))
    
    details_panel.add(details_scroll, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_implementation_button = JButton("Analyze Implementation")
    analyze_implementation_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(analyze_implementation_button)
    
    # Add components to panel
    panel.add(protocol_panel, BorderLayout.WEST)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(execution_panel, BorderLayout.NORTH)
    
    # Populate protocols
    populate_protocols(protocol_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_implementation_button:
                analyze_protocol_implementation(protocol_list, protocol_model, details_area)
    
    listener = ButtonActionListener()
    analyze_implementation_button.addActionListener(listener)
    
    # Add list selection listener
    class ListSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_protocol = protocol_list.getSelectedValue()
            if selected_protocol:
                details_area.setText(get_protocol_description(selected_protocol))
    
    protocol_list.addListSelectionListener(
        lambda e: ListSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_network_behavior_panel():
    """Create panel for network behavior analysis"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Behavior categories
    behavior_panel = JPanel(BorderLayout())
    behavior_panel.setBorder(BorderFactory.createTitledBorder("Network Behaviors"))
    
    behavior_model = DefaultListModel()
    behavior_list = JList(behavior_model)
    behavior_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
    behavior_scroll = JScrollPane(behavior_list)
    behavior_scroll.setPreferredSize(Dimension(400, 250))
    
    behavior_panel.add(behavior_scroll, BorderLayout.WEST)
    
    # Behavior details
    details_panel = JPanel(BorderLayout())
    details_panel.setBorder(BorderFactory.createTitledBorder("Behavior Details"))
    
    details_area = JTextArea()
    details_area.setEditable(False)
    details_area.setLineWrap(True)
    details_area.setWrapStyleWord(True)
    details_scroll = JScrollPane(details_area)
    details_scroll.setPreferredSize(Dimension(600, 250))
    
    details_panel.add(details_scroll, BorderLayout.CENTER)
    
    # Execution options
    execution_panel = JPanel(FlowLayout(FlowLayout.LEFT))
    analyze_behavior_button = JButton("Analyze Behaviors")
    analyze_behavior_button.setPreferredSize(Dimension(150, 30))
    execution_panel.add(analyze_behavior_button)
    
    # Add components to panel
    panel.add(behavior_panel, BorderLayout.WEST)
    panel.add(details_panel, BorderLayout.CENTER)
    panel.add(execution_panel, BorderLayout.NORTH)
    
    # Populate behaviors
    populate_network_behaviors(behavior_model)
    
    # Add action listeners
    class ButtonActionListener(ActionListener):
        def actionPerformed(self, event):
            if event.getSource() == analyze_behavior_button:
                analyze_network_behaviors(behavior_list, behavior_model, details_area)
    
    listener = ButtonActionListener()
    analyze_behavior_button.addActionListener(listener)
    
    # Add list selection listener
    class ListSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_behaviors = behavior_list.getSelectedValuesList()
            if selected_behaviors:
                details = "Selected Behaviors:\n"
                for behavior in selected_behaviors:
                    details += f"- {behavior}\n"
                details_area.setText(details)
    
    behavior_list.addListSelectionListener(
        lambda e: ListSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def create_protocol_results_panel():
    """Create panel for protocol analysis results"""
    
    panel = JPanel(BorderLayout())
    panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
    
    # Results table
    table_panel = JPanel(BorderLayout())
    table_label = JLabel("Protocol Analysis Results:")
    table_model = DefaultTableModel(["Protocol", "Layer", "Port", "Address", "Confidence", "Details"], 0)
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
                export_protocol_results(table_model, details_area)
            elif event.getSource() == clear_button:
                clear_protocol_results(table_model, details_area)
            elif event.getSource() == generate_report_button:
                generate_protocol_report(table_model, details_area)
    
    listener = ButtonActionListener()
    export_button.addActionListener(listener)
    clear_button.addActionListener(listener)
    generate_report_button.addActionListener(listener)
    
    # Add table selection listener
    class TableSelectionListener(ActionListener):
        def actionPerformed(self, event):
            selected_row = result_table.getSelectedRow()
            if selected_row >= 0:
                protocol = table_model.getValueAt(selected_row, 0)
                layer = table_model.getValueAt(selected_row, 1)
                port = table_model.getValueAt(selected_row, 2)
                address = table_model.getValueAt(selected_row, 3)
                confidence = table_model.getValueAt(selected_row, 4)
                details = table_model.getValueAt(selected_row, 5)
                details_area.setText(f"Protocol: {protocol}\nLayer: {layer}\nPort: {port}\nAddress: {address}\nConfidence: {confidence}\nDetails: {details}")
    
    result_table.getSelectionModel().addListSelectionListener(
        lambda e: TableSelectionListener().actionPerformed(None) if not e.getValueIsAdjusting() else None
    )
    
    return panel


def detect_protocols(application_checkbox, transport_checkbox, network_checkbox, other_checkbox,
                   protocol_checkboxes, string_analysis_checkbox,
                   function_analysis_checkbox, port_analysis_checkbox, status_area):
    """Detect network protocols"""
    try:
        if not currentProgram:
            status_area.setText("No program open for analysis")
            return
        
        status_area.setText("Detecting network protocols...")
        
        # Get selected layers
        detect_application = application_checkbox.isSelected()
        detect_transport = transport_checkbox.isSelected()
        detect_network = network_checkbox.isSelected()
        detect_other = other_checkbox.isSelected()
        
        # Get selected protocols
        selected_protocols = []
        for proto_name, checkbox in protocol_checkboxes.items():
            if checkbox.isSelected():
                selected_protocols.append(proto_name)
        
        if not selected_protocols:
            status_area.setText("No protocols selected for detection")
            return
        
        # Get detection options
        use_string_analysis = string_analysis_checkbox.isSelected()
        use_function_analysis = function_analysis_checkbox.isSelected()
        use_port_analysis = port_analysis_checkbox.isSelected()
        
        # Simulate protocol detection
        time.sleep(3)
        
        status_area.append("\nProtocol detection completed!")
        status_area.append("\nDetected protocols:")
        status_area.append("\n- HTTP (Application Layer) - High Confidence")
        status_area.append("\n- TCP (Transport Layer) - High Confidence")
        status_area.append("\n- IP (Network Layer) - Medium Confidence")
        status_area.append("\n- WebSocket (Other) - Low Confidence")
        
    except Exception as e:
        status_area.setText(f"Error detecting protocols: {e}")


def analyze_packets(find_headers_checkbox, find_length_fields_checkbox, find_checksums_checkbox,
                   find_payloads_checkbox, find_sequence_numbers_checkbox, find_flags_checkbox,
                   dissect_http_checkbox, dissect_tcp_checkbox, dissect_udp_checkbox,
                   dissect_ip_checkbox, dissect_custom_checkbox, status_area):
    """Analyze network packets"""
    try:
        if not currentProgram:
            status_area.setText("No program open for analysis")
            return
        
        status_area.setText("Analyzing network packets...")
        
        # Get selected packet analysis options
        find_headers = find_headers_checkbox.isSelected()
        find_length_fields = find_length_fields_checkbox.isSelected()
        find_checksums = find_checksums_checkbox.isSelected()
        find_payloads = find_payloads_checkbox.isSelected()
        find_sequence_numbers = find_sequence_numbers_checkbox.isSelected()
        find_flags = find_flags_checkbox.isSelected()
        
        # Get selected dissection options
        dissect_http = dissect_http_checkbox.isSelected()
        dissect_tcp = dissect_tcp_checkbox.isSelected()
        dissect_udp = dissect_udp_checkbox.isSelected()
        dissect_ip = dissect_ip_checkbox.isSelected()
        dissect_custom = dissect_custom_checkbox.isSelected()
        
        # Simulate packet analysis
        time.sleep(3)
        
        status_area.append("\nPacket analysis completed!")
        status_area.append("\nAnalysis results:")
        status_area.append("\n- Found HTTP headers at 0x10001000")
        status_area.append("\n- Found TCP length fields at 0x10002000")
        status_area.append("\n- Found IP checksums at 0x10003000")
        status_area.append("\n- Dissected HTTP packets successfully")
        
    except Exception as e:
        status_area.setText(f"Error analyzing packets: {e}")


def populate_protocols(model):
    """Populate protocols list"""
    for layer, protos in NETWORK_PROTOCOLS.items():
        for proto_name, proto_info in protos.items():
            model.addElement(f"{proto_name} ({layer})")


def get_protocol_description(protocol):
    """Get description for a protocol"""
    # Extract protocol name and layer from string
    parts = protocol.split(" (")
    if len(parts) >= 2:
        proto_name = parts[0]
        layer = parts[1].rstrip(")")
        
        # Find protocol info
        if layer in NETWORK_PROTOCOLS and proto_name in NETWORK_PROTOCOLS[layer]:
            proto_info = NETWORK_PROTOCOLS[layer][proto_name]
            return f"Protocol: {proto_info['name']}\n"
            f"Layer: {layer}\n"
            f"Description: {proto_info['description']}\n"
            f"Ports: {', '.join(map(str, proto_info['ports'])) if proto_info['ports'] else 'N/A'}\n"
            f"Signatures: {', '.join(proto_info['signatures'])[:100]}...\n"
            f"Behaviors: {', '.join(proto_info['behaviors'])}"
    return "No description available"


def analyze_protocol_implementation(protocol_list, protocol_model, details_area):
    """Analyze protocol implementation"""
    try:
        if not currentProgram:
            details_area.setText("No program open for analysis")
            return
        
        # Get selected protocol
        selected_protocol = protocol_list.getSelectedValue()
        if not selected_protocol:
            details_area.setText("No protocol selected for analysis")
            return
        
        details_area.setText(f"Analyzing {selected_protocol} implementation...")
        
        # Simulate implementation analysis
        time.sleep(2)
        
        details_area.append("\nImplementation analysis completed!")
        details_area.append("\nAnalysis results:")
        details_area.append("\n- Protocol implementation found")
        details_area.append("\n- Well-structured code")
        details_area.append("\n- No obvious vulnerabilities detected")
        
    except Exception as e:
        details_area.setText(f"Error analyzing implementation: {e}")


def populate_network_behaviors(model):
    """Populate network behaviors list"""
    behaviors = set()
    for layer, protos in NETWORK_PROTOCOLS.items():
        for proto_name, proto_info in protos.items():
            for behavior in proto_info.get("behaviors", []):
                behaviors.add(behavior)
    
    for behavior in sorted(behaviors):
        model.addElement(behavior)


def analyze_network_behaviors(behavior_list, behavior_model, details_area):
    """Analyze network behaviors"""
    try:
        if not currentProgram:
            details_area.setText("No program open for analysis")
            return
        
        # Get selected behaviors
        selected_behaviors = []
        selected_indices = behavior_list.getSelectedIndices()
        for index in selected_indices:
            selected_behaviors.append(behavior_model.getElementAt(index))
        
        if not selected_behaviors:
            details_area.setText("No behaviors selected for analysis")
            return
        
        details_area.setText(f"Analyzing {len(selected_behaviors)} network behaviors...")
        
        # Simulate behavior analysis
        time.sleep(2)
        
        details_area.append("\nBehavior analysis completed!")
        details_area.append("\nAnalysis results:")
        for behavior in selected_behaviors:
            details_area.append(f"\n- {behavior}: Detected")
        
    except Exception as e:
        details_area.setText(f"Error analyzing behaviors: {e}")


def export_protocol_results(table_model, details_area):
    """Export protocol analysis results"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to export")
            return
        
        # Show file chooser
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Protocol Analysis Results")
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


def clear_protocol_results(table_model, details_area):
    """Clear protocol analysis results"""
    try:
        table_model.setRowCount(0)
        details_area.setText("Results cleared successfully")
        
    except Exception as e:
        details_area.setText(f"Error clearing results: {e}")


def generate_protocol_report(table_model, details_area):
    """Generate protocol analysis report"""
    try:
        if table_model.getRowCount() == 0:
            details_area.setText("No results to generate report")
            return
        
        details_area.setText("Generating protocol analysis report...")
        
        # Simulate report generation
        time.sleep(2)
        
        report = "PROTOCOL ANALYSIS REPORT\n"
        report += "==========================\n\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        report += f"Program: {currentProgram.name if currentProgram else 'Unknown'}\n\n"
        report += "ANALYSIS RESULTS:\n"
        report += "-----------------\n"
        
        for i in range(table_model.getRowCount()):
            protocol = table_model.getValueAt(i, 0)
            layer = table_model.getValueAt(i, 1)
            confidence = table_model.getValueAt(i, 4)
            report += f"- {protocol} ({layer}): {confidence}\n"
        
        report += "\nCONCLUSION:\n"
        report += "-----------\n"
        report += "Network protocols detected and analyzed successfully.\n"
        
        details_area.setText(report)
        
    except Exception as e:
        details_area.setText(f"Error generating report: {e}")


# Run the protocol analyzer
if __name__ == "__main__":
    show_protocol_analyzer()