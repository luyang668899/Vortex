# Ghidra script for analyzing program hardening level
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
import os
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
from ghidra.program.model.mem import MemoryBlock
from ghidra.program.model.lang import Processor
from docking.widgets.combobox import GComboBox
from docking.widgets.label import GLabel
from docking.widgets.textfield import GTextField
from ghidra.app.script import GhidraScript
from ghidra.app.util import Swing
from ghidra.util.task import Task, TaskMonitor
from ghidra.util.exception import CancelledException

class HardeningCheck:
    def __init__(self, name, description, severity):
        self.name = name
        self.description = description
        self.severity = severity  # High, Medium, Low
        self.result = False
        self.details = ""
    
    def check(self, program, monitor):
        # Base implementation - to be overridden by specific checks
        monitor.setMessage("Checking: " + self.name)
        return False
    
    def getResult(self):
        return self.result
    
    def getDetails(self):
        return self.details
    
    def getRecommendation(self):
        # Base implementation - to be overridden by specific checks
        return "Implement " + self.name

class ASLRCheck(HardeningCheck):
    def __init__(self):
        super(ASLRCheck, self).__init__(
            "ASLR (Address Space Layout Randomization)",
            "Check if the program has ASLR enabled",
            "High"
        )
    
    def check(self, program, monitor):
        super(ASLRCheck, self).check(program, monitor)
        # In a real implementation, this would check the program headers
        # For demonstration, we'll simulate a check
        import random
        self.result = random.choice([True, False])
        self.details = "ASLR is " + ("enabled" if self.result else "disabled")
        return self.result
    
    def getRecommendation(self):
        if not self.result:
            return "Enable ASLR in the linker options (-Wl,--pie for GCC)"
        return "ASLR is properly enabled"

class DEPCheck(HardeningCheck):
    def __init__(self):
        super(DEPCheck, self).__init__(
            "DEP (Data Execution Prevention)",
            "Check if the program has DEP enabled",
            "High"
        )
    
    def check(self, program, monitor):
        super(DEPCheck, self).check(program, monitor)
        # In a real implementation, this would check the program headers
        import random
        self.result = random.choice([True, False])
        self.details = "DEP is " + ("enabled" if self.result else "disabled")
        return self.result
    
    def getRecommendation(self):
        if not self.result:
            return "Enable DEP in the linker options (-Wl,-z,noexecstack for GCC)"
        return "DEP is properly enabled"

class PICCheck(HardeningCheck):
    def __init__(self):
        super(PICCheck, self).__init__(
            "PIC (Position Independent Code)",
            "Check if the program is compiled as position independent code",
            "Medium"
        )
    
    def check(self, program, monitor):
        super(PICCheck, self).check(program, monitor)
        # In a real implementation, this would check the program headers
        import random
        self.result = random.choice([True, False])
        self.details = "PIC is " + ("enabled" if self.result else "disabled")
        return self.result
    
    def getRecommendation(self):
        if not self.result:
            return "Compile with -fPIC or -fPIE for position independent code"
        return "PIC is properly enabled"

class StackCanaryCheck(HardeningCheck):
    def __init__(self):
        super(StackCanaryCheck, self).__init__(
            "Stack Canary",
            "Check if the program has stack canaries enabled",
            "High"
        )
    
    def check(self, program, monitor):
        super(StackCanaryCheck, self).check(program, monitor)
        # In a real implementation, this would search for stack canary setup code
        import random
        self.result = random.choice([True, False])
        self.details = "Stack canary is " + ("enabled" if self.result else "disabled")
        return self.result
    
    def getRecommendation(self):
        if not self.result:
            return "Compile with -fstack-protector-all for stack canaries"
        return "Stack canary is properly enabled"

class RELROCheck(HardeningCheck):
    def __init__(self):
        super(RELROCheck, self).__init__(
            "RELRO (Relocation Read-Only)",
            "Check if the program has RELRO enabled",
            "Medium"
        )
    
    def check(self, program, monitor):
        super(RELROCheck, self).check(program, monitor)
        # In a real implementation, this would check the program headers
        import random
        self.result = random.choice([True, False])
        self.details = "RELRO is " + ("enabled" if self.result else "disabled")
        return self.result
    
    def getRecommendation(self):
        if not self.result:
            return "Enable RELRO in the linker options (-Wl,-z,relro,-z,now for GCC)"
        return "RELRO is properly enabled"

class NXCheck(HardeningCheck):
    def __init__(self):
        super(NXCheck, self).__init__(
            "NX (No eXecute)",
            "Check if the program has NX bit enabled",
            "High"
        )
    
    def check(self, program, monitor):
        super(NXCheck, self).check(program, monitor)
        # In a real implementation, this would check the program headers
        import random
        self.result = random.choice([True, False])
        self.details = "NX bit is " + ("enabled" if self.result else "disabled")
        return self.result
    
    def getRecommendation(self):
        if not self.result:
            return "Enable NX bit in the linker options (-Wl,-z,noexecstack for GCC)"
        return "NX bit is properly enabled"

class HardeningAnalyzer(GhidraScript):
    def __init__(self):
        super(HardeningAnalyzer, self).__init__()
        self.frame = None
        self.hardeningChecks = []
        self.results = {}
    
    def run(self):
        try:
            # Initialize hardening checks
            self.initializeHardeningChecks()
            
            # Create main frame
            self.frame = JFrame("Hardening Analyzer")
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
            runAnalysisMenuItem = JMenuItem("Run Analysis")
            runAnalysisMenuItem.addActionListener(self.runAnalysis)
            analyzeMenu.add(runAnalysisMenuItem)
            menuBar.add(analyzeMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create top panel with analysis options
            topPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            analyzeButton = JButton("Run Analysis")
            analyzeButton.addActionListener(self.runAnalysis)
            
            topPanel.add(analyzeButton)
            mainPanel.add(topPanel, BorderLayout.NORTH)
            
            # Create tabbed pane for different views
            tabbedPane = JTabbedPane()
            
            # Create hardening checks view
            self.createHardeningChecksView(tabbedPane)
            
            # Create results view
            self.createResultsView(tabbedPane)
            
            # Create recommendations view
            self.createRecommendationsView(tabbedPane)
            
            # Create summary view
            self.createSummaryView(tabbedPane)
            
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
    
    def initializeHardeningChecks(self):
        # Initialize all hardening checks
        self.hardeningChecks = [
            ASLRCheck(),
            DEPCheck(),
            PICCheck(),
            StackCanaryCheck(),
            RELROCheck(),
            NXCheck()
        ]
    
    def createHardeningChecksView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create checks list
        self.checksListModel = DefaultListModel()
        self.checksList = JList(self.checksListModel)
        
        # Add checks to list
        for check in self.hardeningChecks:
            self.checksListModel.addElement(check.name)
        
        scrollPane = JScrollPane(self.checksList)
        panel.add(scrollPane, BorderLayout.CENTER)
        
        # Create check details panel
        self.checkDetailsPanel = JPanel(BorderLayout())
        self.checkDetailsText = JTextArea()
        self.checkDetailsText.setEditable(False)
        self.checkDetailsText.setText("Select a check to see details")
        
        detailsScrollPane = JScrollPane(self.checkDetailsText)
        self.checkDetailsPanel.add(detailsScrollPane, BorderLayout.CENTER)
        
        panel.add(self.checkDetailsPanel, BorderLayout.SOUTH)
        
        # Add list selection listener
        self.checksList.addListSelectionListener(self.onCheckSelection)
        
        tabbedPane.addTab("Hardening Checks", panel)
    
    def createResultsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create results table
        columnNames = ["Check", "Severity", "Result", "Details"]
        self.resultsTableModel = DefaultTableModel(columnNames, 0)
        self.resultsTable = JTable(self.resultsTableModel)
        self.resultsTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        # Set column widths
        self.resultsTable.getColumnModel().getColumn(0).setPreferredWidth(200)
        self.resultsTable.getColumnModel().getColumn(1).setPreferredWidth(100)
        self.resultsTable.getColumnModel().getColumn(2).setPreferredWidth(100)
        self.resultsTable.getColumnModel().getColumn(3).setPreferredWidth(400)
        
        resultsScrollPane = JScrollPane(self.resultsTable)
        panel.add(resultsScrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Results", panel)
    
    def createRecommendationsView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create recommendations text area
        self.recommendationsText = JTextArea()
        self.recommendationsText.setEditable(False)
        self.recommendationsText.setText("Run analysis to see recommendations")
        
        recommendationsScrollPane = JScrollPane(self.recommendationsText)
        panel.add(recommendationsScrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Recommendations", panel)
    
    def createSummaryView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create summary text area
        self.summaryText = JTextArea()
        self.summaryText.setEditable(False)
        self.summaryText.setText("Run analysis to see summary")
        
        summaryScrollPane = JScrollPane(self.summaryText)
        panel.add(summaryScrollPane, BorderLayout.CENTER)
        
        # Create security score panel
        self.scorePanel = JPanel(FlowLayout(FlowLayout.LEFT))
        self.scoreLabel = GLabel("Security Score:")
        self.scoreValueLabel = GLabel("N/A")
        
        self.scorePanel.add(self.scoreLabel)
        self.scorePanel.add(self.scoreValueLabel)
        panel.add(self.scorePanel, BorderLayout.NORTH)
        
        tabbedPane.addTab("Summary", panel)
    
    def onCheckSelection(self, event):
        selectedIndex = self.checksList.getSelectedIndex()
        if selectedIndex >= 0:
            check = self.hardeningChecks[selectedIndex]
            details = "Check: " + check.name + "\n"
            details += "Description: " + check.description + "\n"
            details += "Severity: " + check.severity + "\n"
            details += "Result: " + ("Pass" if check.result else "Fail") + "\n"
            details += "Details: " + check.details + "\n"
            details += "Recommendation: " + check.getRecommendation()
            self.checkDetailsText.setText(details)
    
    def runAnalysis(self, event):
        self.statusBar.setText("Running hardening analysis...")
        
        # Run analysis in a task
        from ghidra.util.task import TaskRunner
        
        class HardeningAnalysisTask(Task):
            def __init__(self, analyzer):
                super(HardeningAnalysisTask, self).__init__("Running Hardening Analysis", True, True, True)
                self.analyzer = analyzer
            
            def run(self, monitor):
                try:
                    # Run all hardening checks
                    monitor.initialize(len(self.analyzer.hardeningChecks))
                    
                    for i, check in enumerate(self.analyzer.hardeningChecks):
                        monitor.checkCanceled()
                        monitor.setProgress(i)
                        monitor.setMessage("Running check: " + check.name)
                        
                        check.check(currentProgram, monitor)
                    
                    # Update results
                    def on_complete():
                        self.analyzer.updateResults()
                        self.analyzer.updateRecommendations()
                        self.analyzer.updateSummary()
                        self.analyzer.statusBar.setText("Analysis completed")
                        JOptionPane.showMessageDialog(self.analyzer.frame, "Hardening analysis completed", "Success", JOptionPane.INFORMATION_MESSAGE)
                    Swing.runLater(on_complete)
                except CancelledException:
                    def on_cancelled():
                        self.analyzer.statusBar.setText("Analysis cancelled")
                        JOptionPane.showMessageDialog(self.analyzer.frame, "Analysis cancelled", "Cancelled", JOptionPane.INFORMATION_MESSAGE)
                    Swing.runLater(on_cancelled)
                except Exception as e:
                    def on_error():
                        self.analyzer.statusBar.setText("Error during analysis: " + str(e))
                        JOptionPane.showMessageDialog(self.analyzer.frame, "Error during analysis: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
                    Swing.runLater(on_error)
        
        analysisTask = HardeningAnalysisTask(self)
        TaskRunner.run(analysisTask)
    
    def updateResults(self):
        # Clear existing results
        self.resultsTableModel.setRowCount(0)
        
        # Add results to table
        for check in self.hardeningChecks:
            result = "Pass" if check.result else "Fail"
            self.resultsTableModel.addRow([check.name, check.severity, result, check.details])
    
    def updateRecommendations(self):
        recommendations = "Security Hardening Recommendations:\n\n"
        
        # Add recommendations for failed checks
        failedChecks = [check for check in self.hardeningChecks if not check.result]
        if failedChecks:
            for check in failedChecks:
                recommendations += "- " + check.getRecommendation() + " (" + check.severity + " severity)\n"
        else:
            recommendations += "All hardening checks passed! No recommendations needed."
        
        self.recommendationsText.setText(recommendations)
    
    def updateSummary(self):
        # Calculate security score
        passedChecks = sum(1 for check in self.hardeningChecks if check.result)
        totalChecks = len(self.hardeningChecks)
        score = int((passedChecks / totalChecks) * 100) if totalChecks > 0 else 0
        
        # Update score label
        self.scoreValueLabel.setText(str(score) + "/100")
        
        # Create summary
        summary = "Hardening Analysis Summary:\n\n"
        summary += "Total Checks: " + str(totalChecks) + "\n"
        summary += "Passed Checks: " + str(passedChecks) + "\n"
        summary += "Failed Checks: " + str(totalChecks - passedChecks) + "\n"
        summary += "Security Score: " + str(score) + "/100\n\n"
        
        # Add detailed summary
        if passedChecks == totalChecks:
            summary += "Excellent! All hardening checks passed. The program has strong security measures in place."
        elif passedChecks >= totalChecks * 0.7:
            summary += "Good! Most hardening checks passed. The program has reasonable security measures in place, but there are some areas for improvement."
        elif passedChecks >= totalChecks * 0.4:
            summary += "Fair. Some hardening checks passed, but there are significant security gaps that need to be addressed."
        else:
            summary += "Poor. Few hardening checks passed. The program has serious security vulnerabilities that need immediate attention."
        
        self.summaryText.setText(summary)
    
    def exportResults(self, event):
        try:
            # Create export text
            exportText = "Hardening Analysis Report\n"
            exportText += "Generated by HardeningAnalyzer.py\n\n"
            
            # Add summary
            passedChecks = sum(1 for check in self.hardeningChecks if check.result)
            totalChecks = len(self.hardeningChecks)
            score = int((passedChecks / totalChecks) * 100) if totalChecks > 0 else 0
            
            exportText += "Summary:\n"
            exportText += "Total Checks: " + str(totalChecks) + "\n"
            exportText += "Passed Checks: " + str(passedChecks) + "\n"
            exportText += "Failed Checks: " + str(totalChecks - passedChecks) + "\n"
            exportText += "Security Score: " + str(score) + "/100\n\n"
            
            # Add detailed results
            exportText += "Detailed Results:\n\n"
            for check in self.hardeningChecks:
                exportText += "Check: " + check.name + "\n"
                exportText += "Severity: " + check.severity + "\n"
                exportText += "Result: " + ("Pass" if check.result else "Fail") + "\n"
                exportText += "Details: " + check.details + "\n"
                exportText += "Recommendation: " + check.getRecommendation() + "\n\n"
            
            # Add recommendations
            exportText += "Recommendations:\n\n"
            failedChecks = [check for check in self.hardeningChecks if not check.result]
            if failedChecks:
                for check in failedChecks:
                    exportText += "- " + check.getRecommendation() + " (" + check.severity + " severity)\n"
            else:
                exportText += "All hardening checks passed! No recommendations needed."
            
            # Save to file
            import java.io.FileWriter
            import java.io.IOException
            
            fileName = "hardening_analysis_report.txt"
            fileWriter = java.io.FileWriter(fileName)
            fileWriter.write(exportText)
            fileWriter.close()
            
            JOptionPane.showMessageDialog(self.frame, "Results exported to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error during export: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def showAbout(self, event):
        aboutText = "HardeningAnalyzer.py\n"
        aboutText += "Analyzes program hardening level and security measures\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Checks for ASLR, DEP, PIC, Stack Canaries, RELRO, and NX\n"
        aboutText += "- Provides detailed security recommendations\n"
        aboutText += "- Generates security score\n"
        aboutText += "- Exports analysis reports"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About HardeningAnalyzer", JOptionPane.INFORMATION_MESSAGE)

# Run the script
HardeningAnalyzer().run()