# Ghidra script for analyzing external API usage patterns
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import (JFrame, JPanel, JScrollPane, JTree, JTable, JTextArea, JList, 
                         JTabbedPane, JComboBox, JCheckBox, JButton, JLabel, JTextField, 
                         JOptionPane, JMenu, JMenuBar, JMenuItem, JSplitPane, SwingConstants)
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel, TreeSelectionModel
from javax.swing.table import DefaultTableModel
from javax.swing.event import TreeSelectionListener, ListSelectionListener
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.listing import Function, Variable, CodeUnit
from ghidra.program.model.symbol import Symbol, SymbolTable, SymbolType, SourceType
from ghidra.program.model.scalar import Scalar
from ghidra.program.model.data import PointerDataType
from docking.widgets.combobox import GComboBox
from docking.widgets.label import GLabel
from docking.widgets.textfield import GTextField
from ghidra.app.script import GhidraScript

class APIUsageAnalyzer(GhidraScript):
    def __init__(self):
        super(APIUsageAnalyzer, self).__init__()
        self.frame = None
        self.decompiler = None
        self.apiCalls = {}
        self.selectedApi = None
    
    def run(self):
        try:
            # Initialize decompiler
            self.decompiler = DecompInterface()
            self.decompiler.openProgram(currentProgram)
            
            # Create main frame
            self.frame = JFrame("API Usage Analyzer")
            self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.frame.setSize(1000, 700)
            self.frame.setLocationRelativeTo(None)
            
            # Create menu bar
            menuBar = JMenuBar()
            fileMenu = JMenu("File")
            exportMenuItem = JMenuItem("Export Results")
            exportMenuItem.addActionListener(self.exportResults)
            fileMenu.add(exportMenuItem)
            menuBar.add(fileMenu)
            
            analyzeMenu = JMenu("Analyze")
            scanMenuItem = JMenuItem("Scan for API Calls")
            scanMenuItem.addActionListener(self.scanForApiCalls)
            analyzeMenu.add(scanMenuItem)
            menuBar.add(analyzeMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create top panel with scan options
            topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            scanButton = JButton("Scan for API Calls")
            scanButton.addActionListener(self.scanForApiCalls)
            
            self.apiFilterField = GTextField(20)
            self.apiFilterField.setToolTipText("Filter API names")
            filterButton = JButton("Filter")
            filterButton.addActionListener(self.filterApiCalls)
            
            topPanel.add(scanButton)
            topPanel.add(GLabel("Filter:"))
            topPanel.add(self.apiFilterField)
            topPanel.add(filterButton)
            
            mainPanel.add(topPanel, BorderLayout.NORTH)
            
            # Create tabbed pane for different views
            tabbedPane = JTabbedPane()
            
            # Create API list view
            self.createApiListView(tabbedPane)
            
            # Create API details view
            self.createApiDetailsView(tabbedPane)
            
            # Create API usage statistics view
            self.createApiStatisticsView(tabbedPane)
            
            # Create API call graph view
            self.createApiCallGraphView(tabbedPane)
            
            mainPanel.add(tabbedPane, BorderLayout.CENTER)
            
            # Create status bar
            self.statusBar = GLabel("Ready")
            self.statusBar.setHorizontalAlignment(SwingConstants.LEFT)
            mainPanel.add(self.statusBar, BorderLayout.SOUTH)
            
            self.frame.add(mainPanel)
            self.frame.setVisible(True)
            
            # Auto-scan for API calls on startup
            self.scanForApiCalls(None)
            
        except Exception as e:
            self.statusBar.setText("Error: " + str(e))
            traceback.print_exc()
    
    def createApiListView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create API list model
        self.apiListModel = javax.swing.DefaultListModel()
        self.apiList = JList(self.apiListModel)
        self.apiList.addListSelectionListener(self.onApiListSelection)
        
        scrollPane = JScrollPane(self.apiList)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("API List", panel)
    
    def createApiDetailsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create details text area
        self.detailsText = JTextArea()
        self.detailsText.setEditable(False)
        self.detailsText.setText("Select an API to see details")
        
        scrollPane = JScrollPane(self.detailsText)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        # Create call sites table
        callSitePanel = JPanel(BorderLayout())
        callSiteLabel = GLabel("Call Sites:")
        callSitePanel.add(callSiteLabel, BorderLayout.NORTH)
        
        columnNames = ["Function", "Address", "Context"]
        self.callSiteTableModel = DefaultTableModel(columnNames, 0)
        self.callSiteTable = JTable(self.callSiteTableModel)
        self.callSiteTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        # Set column widths
        self.callSiteTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.callSiteTable.getColumnModel().getColumn(1).setPreferredWidth(150)
        self.callSiteTable.getColumnModel().getColumn(2).setPreferredWidth(400)
        
        scrollPane = JScrollPane(self.callSiteTable)
        callSitePanel.add(scrollPane, BorderLayout.CENTER)
        
        panel.add(callSitePanel, BorderLayout.SOUTH)
        
        tabbedPane.addTab("API Details", panel)
    
    def createApiStatisticsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create statistics text area
        self.statsText = JTextArea()
        self.statsText.setEditable(False)
        self.statsText.setText("Statistics will appear here after scanning")
        
        scrollPane = JScrollPane(self.statsText)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Statistics", panel)
    
    def createApiCallGraphView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create graph control panel
        controlPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        layoutLabel = GLabel("Layout:")
        self.layoutComboBox = GComboBox(["Hierarchical", "Force-Directed", "Circular"])
        refreshButton = JButton("Refresh Graph")
        refreshButton.addActionListener(self.refreshApiGraph)
        
        controlPanel.add(layoutLabel)
        controlPanel.add(self.layoutComboBox)
        controlPanel.add(refreshButton)
        
        panel.add(controlPanel, BorderLayout.NORTH)
        
        # Create graph display area
        self.graphArea = JTextArea()
        self.graphArea.setEditable(False)
        self.graphArea.setText("API call graph will appear here")
        
        scrollPane = JScrollPane(self.graphArea)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Call Graph", panel)
    
    def scanForApiCalls(self, event):
        self.statusBar.setText("Scanning for API calls...")
        
        # Clear existing data
        self.apiCalls = {}
        self.apiListModel.clear()
        
        try:
            # Get all functions
            functionManager = currentProgram.getFunctionManager()
            functions = functionManager.getFunctions(True)
            
            totalFunctions = len(functions)
            processedFunctions = 0
            
            for function in functions:
                processedFunctions += 1
                self.statusBar.setText("Scanning function " + str(processedFunctions) + "/" + str(totalFunctions))
                
                # Decompile function to get high-level code
                results = self.decompiler.decompileFunction(function, 0, None)
                if results and results.decompileCompleted():
                    decompiledFunction = results.getDecompiledFunction()
                    if decompiledFunction:
                        # Get C code
                        cCode = decompiledFunction.getC()
                        
                        # Analyze API calls in the code
                        self.analyzeApiCallsInCode(function, cCode)
                
                # Also analyze direct calls in the listing
                self.analyzeDirectApiCalls(function)
            
            # Update API list
            self.updateApiList()
            
            # Update statistics
            self.updateStatistics()
            
            # Update graph
            self.refreshApiGraph(None)
            
            self.statusBar.setText("Scan completed. Found " + str(len(self.apiCalls)) + " unique APIs.")
            
        except Exception as e:
            self.statusBar.setText("Error during scan: " + str(e))
            traceback.print_exc()
    
    def analyzeApiCallsInCode(self, function, cCode):
        # Simple pattern matching to find API calls
        # This is a basic implementation - more sophisticated parsing could be done
        lines = cCode.split('\n')
        for line in lines:
            # Look for function calls with parentheses
            if '(' in line and ')' in line:
                # Extract potential API names
                parts = line.split('(')[0].split()
                if parts:
                    apiName = parts[-1]
                    # Filter out local variables and keywords
                    if self.isPotentialApi(apiName):
                        self.addApiCall(apiName, function)
    
    def analyzeDirectApiCalls(self, function):
        # Analyze direct function calls in the listing
        listing = currentProgram.getListing()
        addressSet = function.getBody()
        codeUnits = listing.getCodeUnits(addressSet, True)
        
        for codeUnit in codeUnits:
            if codeUnit.getInstruction():
                instruction = codeUnit.getInstruction()
                # Check for call instructions
                if instruction.getMnemonicString().startswith('CALL'):
                    # Get the target of the call
                    for i in range(instruction.getNumOperands()):
                        operand = instruction.getOperand(i)
                        if isinstance(operand, Scalar):
                            # Direct call to address
                            addr = currentProgram.getAddressFactory().getAddress(operand.getValue())
                            symbol = currentProgram.getSymbolTable().getPrimarySymbol(addr)
                            if symbol and symbol.getName():
                                apiName = symbol.getName()
                                if self.isPotentialApi(apiName):
                                    self.addApiCall(apiName, function)
                        elif isinstance(operand, java.util.List):
                            # Indirect call
                            pass
    
    def isPotentialApi(self, name):
        # Filter out local variables and keywords
        keywords = ['if', 'for', 'while', 'return', 'void', 'int', 'char', 'float', 'double', 'bool']
        if name in keywords:
            return False
        
        # Filter out single-character names
        if len(name) <= 1:
            return False
        
        # Filter out names starting with underscore (likely local)
        if name.startswith('_'):
            return False
        
        return True
    
    def addApiCall(self, apiName, function):
        if apiName not in self.apiCalls:
            self.apiCalls[apiName] = {
                'count': 0,
                'functions': {},
                'callSites': []
            }
        
        self.apiCalls[apiName]['count'] += 1
        
        # Add to functions that call this API
        functionName = function.getName()
        if functionName not in self.apiCalls[apiName]['functions']:
            self.apiCalls[apiName]['functions'][functionName] = {
                'count': 0,
                'address': function.getEntryPoint()
            }
        
        self.apiCalls[apiName]['functions'][functionName]['count'] += 1
        
        # Add call site
        callSite = {
            'function': functionName,
            'address': function.getEntryPoint(),
            'context': function.getSignature()
        }
        self.apiCalls[apiName]['callSites'].append(callSite)
    
    def updateApiList(self):
        # Clear existing list
        self.apiListModel.clear()
        
        # Add APIs to the list, sorted by count
        sortedApis = sorted(self.apiCalls.items(), key=lambda x: x[1]['count'], reverse=True)
        for apiName, apiInfo in sortedApis:
            self.apiListModel.addElement(apiName + " (" + str(apiInfo['count']) + " calls)")
    
    def updateStatistics(self):
        stats = "API Usage Statistics:\n\n"
        
        totalApis = len(self.apiCalls)
        totalCalls = sum(api['count'] for api in self.apiCalls.values())
        
        stats += "Total APIs: " + str(totalApis) + "\n"
        stats += "Total API Calls: " + str(totalCalls) + "\n\n"
        
        # Top 10 most frequently called APIs
        if self.apiCalls:
            stats += "Top 10 Most Frequently Called APIs:\n"
            sortedApis = sorted(self.apiCalls.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
            for i, (apiName, apiInfo) in enumerate(sortedApis, 1):
                stats += str(i) + ". " + apiName + " - " + str(apiInfo['count']) + " calls\n"
        
        self.statsText.setText(stats)
    
    def onApiListSelection(self, event):
        selectedIndex = self.apiList.getSelectedIndex()
        if selectedIndex >= 0:
            # Get selected API name
            listItem = str(self.apiListModel.getElementAt(selectedIndex))
            apiName = listItem.split(' (')[0]
            
            self.selectedApi = apiName
            self.showApiDetails(apiName)
    
    def showApiDetails(self, apiName):
        if apiName not in self.apiCalls:
            return
        
        apiInfo = self.apiCalls[apiName]
        
        # Show API details
        details = "API Details:\n\n"
        details += "Name: " + apiName + "\n"
        details += "Total Calls: " + str(apiInfo['count']) + "\n"
        details += "Calling Functions: " + str(len(apiInfo['functions'])) + "\n\n"
        
        # Show calling functions
        details += "Calling Functions:\n"
        for functionName, funcInfo in sorted(apiInfo['functions'].items(), key=lambda x: x[1]['count'], reverse=True):
            details += "  " + functionName + " - " + str(funcInfo['count']) + " calls\n"
        
        self.detailsText.setText(details)
        
        # Update call sites table
        self.callSiteTableModel.setRowCount(0)
        for callSite in apiInfo['callSites']:
            self.callSiteTableModel.addRow([callSite['function'], str(callSite['address']), callSite['context']])
    
    def refreshApiGraph(self, event):
        if not self.apiCalls:
            self.graphArea.setText("No API calls found")
            return
        
        # Create a simple text-based graph representation
        graphText = "API Call Graph\n\n"
        
        # Show top APIs and their calling functions
        sortedApis = sorted(self.apiCalls.items(), key=lambda x: x[1]['count'], reverse=True)[:10]
        for apiName, apiInfo in sortedApis:
            graphText += apiName + "\n"
            
            # Show top calling functions
            sortedFunctions = sorted(apiInfo['functions'].items(), key=lambda x: x[1]['count'], reverse=True)[:5]
            for functionName, funcInfo in sortedFunctions:
                graphText += "  --> " + functionName + " (" + str(funcInfo['count']) + " calls)\n"
            
            graphText += "\n"
        
        self.graphArea.setText(graphText)
    
    def filterApiCalls(self, event):
        filterText = self.apiFilterField.getText().strip().lower()
        
        # Clear existing list
        self.apiListModel.clear()
        
        # Add filtered APIs to the list
        for apiName, apiInfo in self.apiCalls.items():
            if filterText in apiName.lower():
                self.apiListModel.addElement(apiName + " (" + str(apiInfo['count']) + " calls)")
    
    def exportResults(self, event):
        if not self.apiCalls:
            JOptionPane.showMessageDialog(self.frame, "No API calls found to export", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            # Create export text
            exportText = "API Usage Analysis Report\n"
            exportText += "Generated by APIUsageAnalyzer.py\n\n"
            
            # Add summary
            totalApis = len(self.apiCalls)
            totalCalls = sum(api['count'] for api in self.apiCalls.values())
            
            exportText += "Summary:\n"
            exportText += "Total APIs: " + str(totalApis) + "\n"
            exportText += "Total API Calls: " + str(totalCalls) + "\n\n"
            
            # Add detailed API usage
            exportText += "Detailed API Usage:\n\n"
            sortedApis = sorted(self.apiCalls.items(), key=lambda x: x[1]['count'], reverse=True)
            for apiName, apiInfo in sortedApis:
                exportText += "API: " + apiName + "\n"
                exportText += "Calls: " + str(apiInfo['count']) + "\n"
                exportText += "Calling Functions: " + str(len(apiInfo['functions'])) + "\n"
                
                if apiInfo['functions']:
                    exportText += "Functions:\n"
                    for functionName, funcInfo in apiInfo['functions'].items():
                        exportText += "  - " + functionName + " (" + str(funcInfo['count']) + " calls)\n"
                
                exportText += "\n"
            
            # Save to file
            import java.io.FileWriter
            import java.io.IOException
            
            fileName = "api_usage_analysis.txt"
            fileWriter = java.io.FileWriter(fileName)
            fileWriter.write(exportText)
            fileWriter.close()
            
            JOptionPane.showMessageDialog(self.frame, "Results exported to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error during export: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def showAbout(self, event):
        aboutText = "APIUsageAnalyzer.py\n"
        aboutText += "Analyzes program usage of external APIs\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Identifies external API calls\n"
        aboutText += "- Analyzes API usage patterns\n"
        aboutText += "- Provides usage statistics\n"
        aboutText += "- Visualizes API call graph\n"
        aboutText += "- Exports analysis results"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About APIUsageAnalyzer", JOptionPane.INFORMATION_MESSAGE)

# Run the script
APIUsageAnalyzer().run()