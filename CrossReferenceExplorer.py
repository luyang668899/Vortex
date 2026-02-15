# Ghidra script for advanced cross-reference analysis and visualization
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout, Point
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import (JFrame, JPanel, JScrollPane, JTree, JTable, JTextArea, JList, 
                         JTabbedPane, JComboBox, JCheckBox, JButton, JLabel, JTextField, 
                         JOptionPane, JMenu, JMenuBar, JMenuItem, JSplitPane, SwingConstants)
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel, TreeSelectionModel
from javax.swing.table import DefaultTableModel
from javax.swing.event import TreeSelectionListener
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSetView
from ghidra.program.model.listing import Function, Variable
from ghidra.program.model.symbol import Reference, ReferenceManager, SourceType
from ghidra.util.graph import DirectedGraph
from ghidra.util.graph import Vertex
from ghidra.util.graph import Edge
from docking.widgets.combobox import GComboBox
from docking.widgets.label import GLabel
from docking.widgets.textfield import GTextField
from ghidra.app.script import GhidraScript

class CrossReferenceExplorer(GhidraScript):
    def __init__(self):
        super(CrossReferenceExplorer, self).__init__()
        self.frame = None
        self.currentAddress = None
        self.refManager = None
        self.decompiler = None
        self.graph = None
        self.selectedRef = None
    
    def run(self):
        try:
            # Initialize decompiler
            self.decompiler = DecompInterface()
            self.decompiler.openProgram(currentProgram)
            
            # Get reference manager
            self.refManager = currentProgram.getReferenceManager()
            
            # Create main frame
            self.frame = JFrame("Cross-Reference Explorer")
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
            
            viewMenu = JMenu("View")
            refreshMenuItem = JMenuItem("Refresh")
            refreshMenuItem.addActionListener(self.refreshView)
            viewMenu.add(refreshMenuItem)
            menuBar.add(viewMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create top panel with address input
            topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            addressLabel = GLabel("Address:")
            self.addressField = GTextField(20)
            if currentAddress:
                self.addressField.setText(str(currentAddress))
            goButton = JButton("Go")
            goButton.addActionListener(self.goToAddress)
            
            topPanel.add(addressLabel)
            topPanel.add(self.addressField)
            topPanel.add(goButton)
            
            mainPanel.add(topPanel, BorderLayout.NORTH)
            
            # Create tabbed pane for different views
            tabbedPane = JTabbedPane()
            
            # Create reference tree view
            self.createReferenceTreeView(tabbedPane)
            
            # Create reference table view
            self.createReferenceTableView(tabbedPane)
            
            # Create reference graph view
            self.createReferenceGraphView(tabbedPane)
            
            # Create cross-reference details view
            self.createReferenceDetailsView(tabbedPane)
            
            mainPanel.add(tabbedPane, BorderLayout.CENTER)
            
            # Create status bar
            self.statusBar = GLabel("Ready")
            self.statusBar.setHorizontalAlignment(SwingConstants.LEFT)
            mainPanel.add(self.statusBar, BorderLayout.SOUTH)
            
            self.frame.add(mainPanel)
            self.frame.setVisible(True)
            
            # If current address is set, show references
            if currentAddress:
                self.analyzeAddress(currentAddress)
                
        except Exception as e:
            self.statusBar.setText("Error: " + str(e))
            traceback.print_exc()
    
    def createReferenceTreeView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create filter options
        filterPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        filterLabel = GLabel("Filter:")
        self.refTypeFilter = GComboBox(["All", "Read", "Write", "Call", "Data", "Code"])
        self.showForwardRefs = JCheckBox("Show Forward Refs")
        self.showForwardRefs.setSelected(True)
        self.showBackwardRefs = JCheckBox("Show Backward Refs")
        self.showBackwardRefs.setSelected(True)
        
        filterPanel.add(filterLabel)
        filterPanel.add(self.refTypeFilter)
        filterPanel.add(self.showForwardRefs)
        filterPanel.add(self.showBackwardRefs)
        
        # Add filter listener
        self.refTypeFilter.addActionListener(self.refreshReferenceTree)
        self.showForwardRefs.addActionListener(self.refreshReferenceTree)
        self.showBackwardRefs.addActionListener(self.refreshReferenceTree)
        
        panel.add(filterPanel, BorderLayout.NORTH)
        
        # Create reference tree
        self.refTreeRoot = DefaultMutableTreeNode("References")
        self.refTreeModel = DefaultTreeModel(self.refTreeRoot)
        self.refTree = JTree(self.refTreeModel)
        self.refTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION)
        self.refTree.addTreeSelectionListener(self.onTreeSelection)
        self.refTree.setShowsRootHandles(True)
        
        scrollPane = JScrollPane(self.refTree)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Reference Tree", panel)
    
    def createReferenceTableView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create table model
        columnNames = ["Type", "From Address", "To Address", "Symbol", "Context"]
        self.refTableModel = DefaultTableModel(columnNames, 0)
        self.refTable = JTable(self.refTableModel)
        self.refTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        # Set column widths
        self.refTable.getColumnModel().getColumn(0).setPreferredWidth(80)
        self.refTable.getColumnModel().getColumn(1).setPreferredWidth(150)
        self.refTable.getColumnModel().getColumn(2).setPreferredWidth(150)
        self.refTable.getColumnModel().getColumn(3).setPreferredWidth(150)
        self.refTable.getColumnModel().getColumn(4).setPreferredWidth(300)
        
        # Add table listener
        self.refTable.getSelectionModel().addListSelectionListener(self.onTableSelection)
        
        scrollPane = JScrollPane(self.refTable)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Reference Table", panel)
    
    def createReferenceGraphView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create graph control panel
        controlPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        layoutLabel = GLabel("Layout:")
        self.layoutComboBox = GComboBox(["Force-Directed", "Hierarchical", "Circular"])
        refreshButton = JButton("Refresh Graph")
        refreshButton.addActionListener(self.refreshGraph)
        
        controlPanel.add(layoutLabel)
        controlPanel.add(self.layoutComboBox)
        controlPanel.add(refreshButton)
        
        panel.add(controlPanel, BorderLayout.NORTH)
        
        # Create graph display area
        self.graphArea = JTextArea()
        self.graphArea.setEditable(False)
        self.graphArea.setText("Graph visualization will appear here")
        
        scrollPane = JScrollPane(self.graphArea)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Reference Graph", panel)
    
    def createReferenceDetailsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create details text area
        self.detailsText = JTextArea()
        self.detailsText.setEditable(False)
        self.detailsText.setText("Select a reference to see details")
        
        scrollPane = JScrollPane(self.detailsText)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        # Create action buttons
        actionPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        followButton = JButton("Follow Reference")
        followButton.addActionListener(self.followReference)
        decompileButton = JButton("Decompile")
        decompileButton.addActionListener(self.decompileAtReference)
        
        actionPanel.add(followButton)
        actionPanel.add(decompileButton)
        
        panel.add(actionPanel, BorderLayout.SOUTH)
        
        tabbedPane.addTab("Reference Details", panel)
    
    def goToAddress(self, event):
        addressText = self.addressField.getText().strip()
        if not addressText:
            JOptionPane.showMessageDialog(self.frame, "Please enter an address", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            address = currentProgram.getAddressFactory().getAddress(addressText)
            self.analyzeAddress(address)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Invalid address: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def analyzeAddress(self, address):
        self.currentAddress = address
        self.statusBar.setText("Analyzing references at " + str(address))
        
        # Refresh all views
        self.refreshReferenceTree(None)
        self.refreshReferenceTable()
        self.refreshGraph()
        
        self.statusBar.setText("Analysis complete for " + str(address))
    
    def refreshReferenceTree(self, event):
        # Clear existing tree
        self.refTreeRoot.removeAllChildren()
        
        if not self.currentAddress:
            self.refTreeModel.reload()
            return
        
        # Get filter settings
        filterType = str(self.refTypeFilter.getSelectedItem())
        showForward = self.showForwardRefs.isSelected()
        showBackward = self.showBackwardRefs.isSelected()
        
        # Add forward references
        if showForward:
            forwardRoot = DefaultMutableTreeNode("Forward References")
            self.refTreeRoot.add(forwardRoot)
            
            refs = self.refManager.getReferencesFrom(self.currentAddress)
            for ref in refs:
                if self.matchesFilter(ref, filterType):
                    refNode = DefaultMutableTreeNode(self.formatReference(ref))
                    refNode.setUserObject(ref)
                    forwardRoot.add(refNode)
        
        # Add backward references
        if showBackward:
            backwardRoot = DefaultMutableTreeNode("Backward References")
            self.refTreeRoot.add(backwardRoot)
            
            refs = self.refManager.getReferencesTo(self.currentAddress)
            for ref in refs:
                if self.matchesFilter(ref, filterType):
                    refNode = DefaultMutableTreeNode(self.formatReference(ref))
                    refNode.setUserObject(ref)
                    backwardRoot.add(refNode)
        
        self.refTreeModel.reload()
        # Expand all nodes
        for i in range(self.refTree.getRowCount()):
            self.refTree.expandRow(i)
    
    def refreshReferenceTable(self):
        # Clear existing table
        self.refTableModel.setRowCount(0)
        
        if not self.currentAddress:
            return
        
        # Get forward references
        forwardRefs = self.refManager.getReferencesFrom(self.currentAddress)
        for ref in forwardRefs:
            self.addReferenceToTable(ref, "Forward")
        
        # Get backward references
        backwardRefs = self.refManager.getReferencesTo(self.currentAddress)
        for ref in backwardRefs:
            self.addReferenceToTable(ref, "Backward")
    
    def addReferenceToTable(self, ref, direction):
        refType = self.getReferenceType(ref)
        fromAddr = ref.getFromAddress()
        toAddr = ref.getToAddress()
        
        # Get symbol
        symbol = currentProgram.getSymbolTable().getPrimarySymbol(toAddr)
        symbolName = symbol.getName() if symbol else ""
        
        # Get context
        context = self.getContextAtAddress(fromAddr)
        
        self.refTableModel.addRow([direction + " " + refType, str(fromAddr), str(toAddr), symbolName, context])
    
    def refreshGraph(self, event=None):
        if not self.currentAddress:
            self.graphArea.setText("No address selected")
            return
        
        # Create a simple text-based graph representation
        graphText = "Reference Graph for " + str(self.currentAddress) + "\n\n"
        
        # Get forward references
        forwardRefs = self.refManager.getReferencesFrom(self.currentAddress)
        if forwardRefs:
            graphText += "Forward References:\n"
            for ref in forwardRefs:
                refType = self.getReferenceType(ref)
                toAddr = ref.getToAddress()
                symbol = currentProgram.getSymbolTable().getPrimarySymbol(toAddr)
                symbolName = symbol.getName() if symbol else ""
                graphText += "  " + str(self.currentAddress) + " --> " + str(toAddr) + " (" + refType + ") " + symbolName + "\n"
        
        # Get backward references
        backwardRefs = self.refManager.getReferencesTo(self.currentAddress)
        if backwardRefs:
            graphText += "\nBackward References:\n"
            for ref in backwardRefs:
                refType = self.getReferenceType(ref)
                fromAddr = ref.getFromAddress()
                symbol = currentProgram.getSymbolTable().getPrimarySymbol(fromAddr)
                symbolName = symbol.getName() if symbol else ""
                graphText += "  " + str(fromAddr) + " --> " + str(self.currentAddress) + " (" + refType + ") " + symbolName + "\n"
        
        self.graphArea.setText(graphText)
    
    def matchesFilter(self, ref, filterType):
        if filterType == "All":
            return True
        
        refType = self.getReferenceType(ref)
        return refType == filterType
    
    def getReferenceType(self, ref):
        if ref.isRead(): return "Read"
        if ref.isWrite(): return "Write"
        if ref.isCall(): return "Call"
        if ref.isData(): return "Data"
        if ref.isCode(): return "Code"
        return "Unknown"
    
    def formatReference(self, ref):
        refType = self.getReferenceType(ref)
        if ref.getFromAddress() == self.currentAddress:
            # Forward reference
            toAddr = ref.getToAddress()
            symbol = currentProgram.getSymbolTable().getPrimarySymbol(toAddr)
            symbolName = symbol.getName() if symbol else ""
            return refType + " to " + str(toAddr) + " " + symbolName
        else:
            # Backward reference
            fromAddr = ref.getFromAddress()
            symbol = currentProgram.getSymbolTable().getPrimarySymbol(fromAddr)
            symbolName = symbol.getName() if symbol else ""
            return refType + " from " + str(fromAddr) + " " + symbolName
    
    def getContextAtAddress(self, address):
        listing = currentProgram.getListing()
        codeUnit = listing.getCodeUnitAt(address)
        if codeUnit:
            return str(codeUnit)
        return ""
    
    def onTreeSelection(self, event):
        selectionPath = self.refTree.getSelectionPath()
        if not selectionPath:
            return
        
        selectedNode = selectionPath.getLastPathComponent()
        if isinstance(selectedNode, DefaultMutableTreeNode):
            userObject = selectedNode.getUserObject()
            if isinstance(userObject, Reference):
                self.selectedRef = userObject
                self.showReferenceDetails(userObject)
    
    def onTableSelection(self, event):
        if event.getValueIsAdjusting():
            return
        
        selectedRow = self.refTable.getSelectedRow()
        if selectedRow >= 0:
            # Get reference details from table
            fromAddr = self.refTableModel.getValueAt(selectedRow, 1)
            toAddr = self.refTableModel.getValueAt(selectedRow, 2)
            
            # Find the reference
            fromAddress = currentProgram.getAddressFactory().getAddress(str(fromAddr))
            toAddress = currentProgram.getAddressFactory().getAddress(str(toAddr))
            
            refs = self.refManager.getReferencesFrom(fromAddress)
            for ref in refs:
                if ref.getToAddress() == toAddress:
                    self.selectedRef = ref
                    self.showReferenceDetails(ref)
                    break
    
    def showReferenceDetails(self, ref):
        details = "Reference Details:\n\n"
        details += "Type: " + self.getReferenceType(ref) + "\n"
        details += "From Address: " + str(ref.getFromAddress()) + "\n"
        details += "To Address: " + str(ref.getToAddress()) + "\n"
        details += "Source Type: " + str(ref.getSourceType()) + "\n"
        
        # Get symbol information
        toAddr = ref.getToAddress()
        symbol = currentProgram.getSymbolTable().getPrimarySymbol(toAddr)
        if symbol:
            details += "\nSymbol Information:\n"
            details += "Name: " + symbol.getName() + "\n"
            details += "Symbol Type: " + str(symbol.getSymbolType()) + "\n"
        
        # Get context at from address
        details += "\nContext at From Address:\n"
        details += self.getContextAtAddress(ref.getFromAddress()) + "\n"
        
        self.detailsText.setText(details)
    
    def followReference(self, event):
        if not self.selectedRef:
            JOptionPane.showMessageDialog(self.frame, "No reference selected", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        toAddr = self.selectedRef.getToAddress()
        self.addressField.setText(str(toAddr))
        self.analyzeAddress(toAddr)
    
    def decompileAtReference(self, event):
        if not self.selectedRef:
            JOptionPane.showMessageDialog(self.frame, "No reference selected", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            fromAddr = self.selectedRef.getFromAddress()
            function = currentProgram.getFunctionManager().getFunctionContaining(fromAddr)
            if function:
                # Decompile the function
                results = self.decompiler.decompileFunction(function, 0, None)
                if results and results.decompileCompleted():
                    decompiledCode = str(results.getDecompiledFunction().getC())
                    
                    # Show decompiled code in a dialog
                    dialog = JFrame("Decompiled Code")
                    dialog.setSize(800, 600)
                    dialog.setLocationRelativeTo(self.frame)
                    
                    textArea = JTextArea(decompiledCode)
                    textArea.setEditable(False)
                    scrollPane = JScrollPane(textArea)
                    dialog.add(scrollPane)
                    
                    dialog.setVisible(True)
                else:
                    JOptionPane.showMessageDialog(self.frame, "Decompilation failed", "Error", JOptionPane.ERROR_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self.frame, "No function found at address", "Error", JOptionPane.ERROR_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error during decompilation: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def goToAddress(self, event):
        addressText = self.addressField.getText().strip()
        if not addressText:
            JOptionPane.showMessageDialog(self.frame, "Please enter an address", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            address = currentProgram.getAddressFactory().getAddress(addressText)
            self.analyzeAddress(address)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Invalid address: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def exportResults(self, event):
        if not self.currentAddress:
            JOptionPane.showMessageDialog(self.frame, "No address selected", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            # Create export text
            exportText = "Cross-Reference Analysis for " + str(self.currentAddress) + "\n"
            exportText += "Generated by CrossReferenceExplorer.py\n\n"
            
            # Add forward references
            forwardRefs = self.refManager.getReferencesFrom(self.currentAddress)
            if forwardRefs:
                exportText += "Forward References:\n"
                for ref in forwardRefs:
                    exportText += "  " + self.formatReference(ref) + "\n"
            
            # Add backward references
            backwardRefs = self.refManager.getReferencesTo(self.currentAddress)
            if backwardRefs:
                exportText += "\nBackward References:\n"
                for ref in backwardRefs:
                    exportText += "  " + self.formatReference(ref) + "\n"
            
            # Save to file
            import java.io.FileWriter
            import java.io.IOException
            
            fileName = "xref_analysis_" + str(self.currentAddress).replace(":", "_") + ".txt"
            fileWriter = java.io.FileWriter(fileName)
            fileWriter.write(exportText)
            fileWriter.close()
            
            JOptionPane.showMessageDialog(self.frame, "Results exported to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error during export: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def refreshView(self, event):
        if self.currentAddress:
            self.analyzeAddress(self.currentAddress)
            JOptionPane.showMessageDialog(self.frame, "View refreshed", "Success", JOptionPane.INFORMATION_MESSAGE)
    
    def showAbout(self, event):
        aboutText = "CrossReferenceExplorer.py\n"
        aboutText += "Advanced cross-reference analysis and visualization tool\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Reference tree visualization\n"
        aboutText += "- Reference table view\n"
        aboutText += "- Reference graph visualization\n"
        aboutText += "- Detailed reference information\n"
        aboutText += "- Decompilation support\n"
        aboutText += "- Export functionality"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About CrossReferenceExplorer", JOptionPane.INFORMATION_MESSAGE)
    
    def matchesFilter(self, ref, filterType):
        if filterType == "All":
            return True
        
        refType = self.getReferenceType(ref)
        return refType == filterType
    
    def getReferenceType(self, ref):
        if ref.isRead():
            return "Read"
        elif ref.isWrite():
            return "Write"
        elif ref.isCall():
            return "Call"
        elif ref.isData():
            return "Data"
        elif ref.isCode():
            return "Code"
        else:
            return "Unknown"

# Run the script
CrossReferenceExplorer().run()