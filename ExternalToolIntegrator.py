# Ghidra script for integrating with external tools
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
import os
import subprocess
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import (JFrame, JPanel, JScrollPane, JTree, JTable, JTextArea, JList, 
                         JTabbedPane, JComboBox, JCheckBox, JButton, JLabel, JTextField, 
                         JOptionPane, JMenu, JMenuBar, JMenuItem, JSplitPane, SwingConstants)
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel, TreeSelectionModel
from javax.swing.table import DefaultTableModel
from javax.swing.event import TreeSelectionListener, ListSelectionListener
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSetView, AddressRange, AddressSet
from ghidra.program.model.listing import Function, Variable, CodeUnit
from ghidra.program.model.symbol import Symbol, SymbolTable, SymbolType
from docking.widgets.combobox import GComboBox
from docking.widgets.label import GLabel
from docking.widgets.textfield import GTextField
from ghidra.app.script import GhidraScript
from ghidra.app.util import Swing
from ghidra.util.task import Task, TaskMonitor
from ghidra.util.exception import CancelledException

class ExternalTool:
    def __init__(self, name, description, executable, arguments=""):
        self.name = name
        self.description = description
        self.executable = executable
        self.arguments = arguments
        self.enabled = True
        self.configuration = {}
    
    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'executable': self.executable,
            'arguments': self.arguments,
            'enabled': self.enabled,
            'configuration': self.configuration
        }
    
    @classmethod
    def from_dict(cls, data):
        tool = cls(
            data['name'],
            data['description'],
            data.get('executable', ''),
            data.get('arguments', '')
        )
        tool.enabled = data.get('enabled', True)
        tool.configuration = data.get('configuration', {})
        return tool
    
    def is_available(self):
        # Check if the tool executable exists
        return os.path.exists(self.executable) or self._is_in_path(self.executable)
    
    def _is_in_path(self, executable):
        # Check if executable is in system PATH
        for path in os.environ['PATH'].split(os.pathsep):
            exe_path = os.path.join(path, executable)
            if os.path.exists(exe_path) and os.access(exe_path, os.X_OK):
                return True
        return False
    
    def run(self, input_file, output_dir=None, monitor=None):
        # Run the external tool
        cmd = [self.executable]
        if self.arguments:
            cmd.extend(self.arguments.split())
        cmd.append(input_file)
        
        if output_dir:
            cmd.append(output_dir)
        
        if monitor:
            monitor.setMessage("Running " + self.name + "...")
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()
            
            if monitor:
                monitor.setMessage(self.name + " completed")
            
            return {
                'success': process.returncode == 0,
                'stdout': stdout,
                'stderr': stderr,
                'returncode': process.returncode
            }
        except Exception as e:
            if monitor:
                monitor.setMessage("Error running " + self.name + ": " + str(e))
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }
    
    def get_configuration(self):
        return self.configuration
    
    def set_configuration(self, config):
        self.configuration = config

class IDAProTool(ExternalTool):
    def __init__(self):
        super(IDAProTool, self).__init__(
            "IDA Pro",
            "Interactive Disassembler Professional",
            "ida64",
            "-A"
        )
        self.configuration = {
            'script': '',
            'timeout': 300
        }

class BinwalkTool(ExternalTool):
    def __init__(self):
        super(BinwalkTool, self).__init__(
            "Binwalk",
            "Firmware analysis tool",
            "binwalk",
            "-Me"
        )
        self.configuration = {
            'extract': True,
            'signature': True,
            'entropy': True
        }

class Radare2Tool(ExternalTool):
    def __init__(self):
        super(Radare2Tool, self).__init__(
            "Radare2",
            "Open source reverse engineering framework",
            "r2",
            "-A"
        )
        self.configuration = {
            'script': '',
            'analysis_level': 3
        }

class GhidraTool(ExternalTool):
    def __init__(self):
        super(GhidraTool, self).__init__(
            "Ghidra Headless",
            "Ghidra headless mode",
            "ghidraRun",
            "-Headless"
        )
        self.configuration = {
            'script': '',
            'project': '',
            'import': True
        }

class ExternalToolIntegrator(GhidraScript):
    def __init__(self):
        super(ExternalToolIntegrator, self).__init__()
        self.frame = None
        self.tools = []
        self.results = {}
    
    def run(self):
        try:
            # Initialize external tools
            self.initializeTools()
            
            # Create main frame
            self.frame = JFrame("External Tool Integrator")
            self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.frame.setSize(1000, 700)
            self.frame.setLocationRelativeTo(None)
            
            # Create menu bar
            menuBar = JMenuBar()
            fileMenu = JMenu("File")
            
            exportConfigMenuItem = JMenuItem("Export Configuration")
            exportConfigMenuItem.addActionListener(self.exportConfiguration)
            fileMenu.add(exportConfigMenuItem)
            
            importConfigMenuItem = JMenuItem("Import Configuration")
            importConfigMenuItem.addActionListener(self.importConfiguration)
            fileMenu.add(importConfigMenuItem)
            menuBar.add(fileMenu)
            
            toolsMenu = JMenu("Tools")
            addToolMenuItem = JMenuItem("Add Tool")
            addToolMenuItem.addActionListener(self.addTool)
            toolsMenu.add(addToolMenuItem)
            menuBar.add(toolsMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create top panel with tool selection
            topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            runButton = JButton("Run Selected Tool")
            runButton.addActionListener(self.runSelectedTool)
            
            topPanel.add(runButton)
            mainPanel.add(topPanel, BorderLayout.NORTH)
            
            # Create tabbed pane for different views
            tabbedPane = JTabbedPane()
            
            # Create tools list view
            self.createToolsView(tabbedPane)
            
            # Create tool configuration view
            self.createToolConfigView(tabbedPane)
            
            # Create results view
            self.createResultsView(tabbedPane)
            
            # Create tool status view
            self.createToolStatusView(tabbedPane)
            
            mainPanel.add(tabbedPane, BorderLayout.CENTER)
            
            # Create status bar
            self.statusBar = GLabel("Ready")
            self.statusBar.setHorizontalAlignment(SwingConstants.LEFT)
            mainPanel.add(self.statusBar, BorderLayout.SOUTH)
            
            self.frame.add(mainPanel)
            self.frame.setVisible(True)
            
        except Exception as e:
            self.statusBar.setText("Error: " + str(e))
            traceback.print_exc()
    
    def initializeTools(self):
        # Initialize default external tools
        self.tools = [
            IDAProTool(),
            BinwalkTool(),
            Radare2Tool(),
            GhidraTool()
        ]
    
    def createToolsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create tools list
        self.toolsListModel = DefaultListModel()
        self.toolsList = JList(self.toolsListModel)
        
        # Add tools to list
        for tool in self.tools:
            status = "[Available]" if tool.is_available() else "[Not Available]"
            self.toolsListModel.addElement(tool.name + " " + status)
        
        scrollPane = JScrollPane(self.toolsList)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        # Create tool details panel
        self.toolDetailsPanel = JPanel(BorderLayout())
        self.toolDetailsText = JTextArea()
        self.toolDetailsText.setEditable(False)
        self.toolDetailsText.setText("Select a tool to see details")
        
        detailsScrollPane = JScrollPane(self.toolDetailsText)
        self.toolDetailsPanel.add(detailsScrollPane, BorderLayout.CENTER)
        
        panel.add(self.toolDetailsPanel, BorderLayout.SOUTH)
        
        # Add list selection listener
        self.toolsList.addListSelectionListener(self.onToolSelection)
        
        tabbedPane.addTab("Tools", panel)
    
    def createToolConfigView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create configuration panel
        self.configPanel = JPanel(GridLayout(0, 2, 5, 5))
        self.configPanel.setBorder(javax.swing.border.TitledBorder("Tool Configuration"))
        
        # Add default config fields
        self.executableField = GTextField()
        self.argumentsField = GTextField()
        self.enabledCheckBox = JCheckBox("Enabled")
        
        self.configPanel.add(GLabel("Executable:"))
        self.configPanel.add(self.executableField)
        self.configPanel.add(GLabel("Arguments:"))
        self.configPanel.add(self.argumentsField)
        self.configPanel.add(GLabel("Enabled:"))
        self.configPanel.add(self.enabledCheckBox)
        
        # Create save config button
        saveConfigButton = JButton("Save Configuration")
        saveConfigButton.addActionListener(self.saveToolConfiguration)
        
        panel.add(self.configPanel, BorderLayout.CENTER)
        panel.add(saveConfigButton, BorderLayout.SOUTH)
        
        tabbedPane.addTab("Configuration", panel)
    
    def createResultsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create results text area
        self.resultsText = JTextArea()
        self.resultsText.setEditable(False)
        self.resultsText.setText("Run a tool to see results")
        
        resultsScrollPane = JScrollPane(self.resultsText)
        panel.add(resultsScrollPane, BorderLayout.CENTER)
        
        # Create results control buttons
        resultsButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        saveResultsButton = JButton("Save Results")
        saveResultsButton.addActionListener(self.saveResults)
        
        clearResultsButton = JButton("Clear Results")
        clearResultsButton.addActionListener(self.clearResults)
        
        resultsButtonsPanel.add(saveResultsButton)
        resultsButtonsPanel.add(clearResultsButton)
        
        panel.add(resultsButtonsPanel, BorderLayout.SOUTH)
        
        tabbedPane.addTab("Results", panel)
    
    def createToolStatusView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create status table
        columnNames = ["Tool", "Status", "Executable", "Available"]
        self.statusTableModel = DefaultTableModel(columnNames, 0)
        self.statusTable = JTable(self.statusTableModel)
        self.statusTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        # Set column widths
        self.statusTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.statusTable.getColumnModel().getColumn(1).setPreferredWidth(100)
        self.statusTable.getColumnModel().getColumn(2).setPreferredWidth(300)
        self.statusTable.getColumnModel().getColumn(3).setPreferredWidth(100)
        
        # Add tool statuses
        for tool in self.tools:
            available = "Yes" if tool.is_available() else "No"
            self.statusTableModel.addRow([tool.name, "Ready", tool.executable, available])
        
        statusScrollPane = JScrollPane(self.statusTable)
        panel.add(statusScrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Tool Status", panel)
    
    def onToolSelection(self, event):
        selectedIndex = self.toolsList.getSelectedIndex()
        if selectedIndex >= 0:
            tool = self.tools[selectedIndex]
            details = "Tool: " + tool.name + "\n"
            details += "Description: " + tool.description + "\n"
            details += "Executable: " + tool.executable + "\n"
            details += "Arguments: " + tool.arguments + "\n"
            details += "Available: " + ("Yes" if tool.is_available() else "No") + "\n"
            details += "Enabled: " + str(tool.enabled)
            self.toolDetailsText.setText(details)
            
            # Update configuration fields
            self.executableField.setText(tool.executable)
            self.argumentsField.setText(tool.arguments)
            self.enabledCheckBox.setSelected(tool.enabled)
    
    def saveToolConfiguration(self, event):
        selectedIndex = self.toolsList.getSelectedIndex()
        if selectedIndex >= 0:
            tool = self.tools[selectedIndex]
            tool.executable = self.executableField.getText()
            tool.arguments = self.argumentsField.getText()
            tool.enabled = self.enabledCheckBox.isSelected()
            
            # Update tools list
            status = "[Available]" if tool.is_available() else "[Not Available]"
            self.toolsListModel.setElementAt(tool.name + " " + status, selectedIndex)
            
            # Update status table
            for i in range(self.statusTableModel.getRowCount()):
                if self.statusTableModel.getValueAt(i, 0) == tool.name:
                    self.statusTableModel.setValueAt(tool.executable, i, 2)
                    self.statusTableModel.setValueAt("Yes" if tool.is_available() else "No", i, 3)
                    break
            
            JOptionPane.showMessageDialog(self.frame, "Tool configuration saved", "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def runSelectedTool(self, event):
        selectedIndex = self.toolsList.getSelectedIndex()
        if selectedIndex >= 0:
            tool = self.tools[selectedIndex]
            
            if not tool.enabled:
                JOptionPane.showMessageDialog(self.frame, "Tool is disabled", "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            if not tool.is_available():
                JOptionPane.showMessageDialog(self.frame, "Tool executable not found", "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            # Prompt for input file
            input_file = JOptionPane.showInputDialog(self.frame, "Enter input file path:")
            if not input_file or not os.path.exists(input_file):
                JOptionPane.showMessageDialog(self.frame, "Invalid input file", "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            # Prompt for output directory (optional)
            output_dir = JOptionPane.showInputDialog(self.frame, "Enter output directory (optional):")
            if output_dir and not os.path.exists(output_dir):
                try:
                    os.makedirs(output_dir)
                except Exception as e:
                    JOptionPane.showMessageDialog(self.frame, "Error creating output directory: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
                    return
            
            # Run tool in a task
            from ghidra.util.task import TaskRunner
            
            class ToolExecutionTask(Task):
                def __init__(self, tool, input_file, output_dir, parent):
                    super(ToolExecutionTask, self).__init__("Running " + tool.name, True, True, True)
                    self.tool = tool
                    self.input_file = input_file
                    self.output_dir = output_dir
                    self.parent = parent
                
                def run(self, monitor):
                    try:
                        result = self.tool.run(self.input_file, self.output_dir, monitor)
                        
                        def on_success():
                            self.parent.updateResults(result, self.tool.name)
                            self.parent.statusBar.setText(self.tool.name + " execution completed")
                            if result['success']:
                                JOptionPane.showMessageDialog(self.parent.frame, self.tool.name + " completed successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
                            else:
                                JOptionPane.showMessageDialog(self.parent.frame, self.tool.name + " failed with return code " + str(result['returncode']), "Error", JOptionPane.ERROR_MESSAGE)
                        
                        Swing.runLater(on_success)
                    except CancelledException:
                        def on_cancelled():
                            self.parent.statusBar.setText("Tool execution cancelled")
                            JOptionPane.showMessageDialog(self.parent.frame, "Tool execution cancelled", "Cancelled", JOptionPane.INFORMATION_MESSAGE)
                        Swing.runLater(on_cancelled)
                    except Exception as e:
                        def on_error():
                            self.parent.statusBar.setText("Error running tool: " + str(e))
                            JOptionPane.showMessageDialog(self.parent.frame, "Error running tool: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
                        Swing.runLater(on_error)
            
            executionTask = ToolExecutionTask(tool, input_file, output_dir, self)
            TaskRunner.run(executionTask)
    
    def updateResults(self, result, tool_name):
        results_text = "Tool: " + tool_name + "\n"
        results_text += "Success: " + str(result['success']) + "\n"
        results_text += "Return Code: " + str(result['returncode']) + "\n\n"
        
        if result['stdout']:
            results_text += "STDOUT:\n" + result['stdout'] + "\n\n"
        
        if result['stderr']:
            results_text += "STDERR:\n" + result['stderr'] + "\n"
        
        self.resultsText.setText(results_text)
    
    def saveResults(self, event):
        results = self.resultsText.getText()
        if not results or results == "Run a tool to see results":
            JOptionPane.showMessageDialog(self.frame, "No results to save", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            # Save results to file
            import java.io.FileWriter
            import java.io.IOException
            
            fileName = "external_tool_results.txt"
            fileWriter = java.io.FileWriter(fileName)
            fileWriter.write(results)
            fileWriter.close()
            
            JOptionPane.showMessageDialog(self.frame, "Results saved to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error saving results: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def clearResults(self, event):
        self.resultsText.setText("Run a tool to see results")
    
    def addTool(self, event):
        # Prompt for tool details
        name = JOptionPane.showInputDialog(self.frame, "Enter tool name:")
        if not name:
            return
        
        description = JOptionPane.showInputDialog(self.frame, "Enter tool description:")
        executable = JOptionPane.showInputDialog(self.frame, "Enter tool executable:")
        arguments = JOptionPane.showInputDialog(self.frame, "Enter tool arguments (optional):")
        
        # Create new tool
        new_tool = ExternalTool(name, description, executable, arguments or "")
        self.tools.append(new_tool)
        
        # Update tools list
        status = "[Available]" if new_tool.is_available() else "[Not Available]"
        self.toolsListModel.addElement(new_tool.name + " " + status)
        
        # Update status table
        available = "Yes" if new_tool.is_available() else "No"
        self.statusTableModel.addRow([new_tool.name, "Ready", new_tool.executable, available])
        
        JOptionPane.showMessageDialog(self.frame, "Tool added successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def exportConfiguration(self, event):
        try:
            # Export tool configurations to JSON
            import json
            import java.io.FileWriter
            
            config_data = {
                'tools': [tool.to_dict() for tool in self.tools]
            }
            
            fileName = "external_tool_config.json"
            fileWriter = java.io.FileWriter(fileName)
            fileWriter.write(json.dumps(config_data, indent=2))
            fileWriter.close()
            
            JOptionPane.showMessageDialog(self.frame, "Configuration exported to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error exporting configuration: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def importConfiguration(self, event):
        try:
            # Import tool configurations from JSON
            import json
            import java.io.File
            import javax.swing.JFileChooser
            
            fileChooser = javax.swing.JFileChooser()
            fileChooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"))
            
            result = fileChooser.showOpenDialog(self.frame)
            if result == javax.swing.JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                with open(file.getPath(), 'r') as f:
                    config_data = json.load(f)
                
                # Update tools
                self.tools = []
                for tool_data in config_data.get('tools', []):
                    tool = ExternalTool.from_dict(tool_data)
                    self.tools.append(tool)
                
                # Update UI
                self.toolsListModel.clear()
                for tool in self.tools:
                    status = "[Available]" if tool.is_available() else "[Not Available]"
                    self.toolsListModel.addElement(tool.name + " " + status)
                
                # Update status table
                self.statusTableModel.setRowCount(0)
                for tool in self.tools:
                    available = "Yes" if tool.is_available() else "No"
                    self.statusTableModel.addRow([tool.name, "Ready", tool.executable, available])
                
                JOptionPane.showMessageDialog(self.frame, "Configuration imported successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error importing configuration: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def showAbout(self, event):
        aboutText = "ExternalToolIntegrator.py\n"
        aboutText += "Integrates Ghidra with external tools like IDA Pro, Binwalk, etc.\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Integrates with popular reverse engineering tools\n"
        aboutText += "- Tool configuration management\n"
        aboutText += "- Tool availability checking\n"
        aboutText += "- Results capture and export\n"
        aboutText += "- Configuration import/export"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About ExternalToolIntegrator", JOptionPane.INFORMATION_MESSAGE)

# Run the script
ExternalToolIntegrator().run()