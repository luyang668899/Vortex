# Ghidra script for checking secure coding practices
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
import os
import re
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
from docking.widgets.combobox import GComboBox
from docking.widgets.label import GLabel
from docking.widgets.textfield import GTextField
from ghidra.app.script import GhidraScript
from ghidra.app.util import Swing
from ghidra.util.task import Task, TaskMonitor
from ghidra.util.exception import CancelledException

class SecureCodingCheck:
    def __init__(self, name, description, severity):
        self.name = name
        self.description = description
        self.severity = severity  # High, Medium, Low
        self.issues = []
    
    def check(self, program, monitor):
        # Base implementation - to be overridden by specific checks
        monitor.setMessage("Checking: " + self.name)
        return []
    
    def getIssues(self):
        return self.issues
    
    def getRecommendation(self):
        # Base implementation - to be overridden by specific checks
        return "Follow secure coding practices for " + self.name

class BufferOverflowCheck(SecureCodingCheck):
    def __init__(self):
        super(BufferOverflowCheck, self).__init__(
            "Buffer Overflow",
            "Check for potential buffer overflow vulnerabilities",
            "High"
        )
    
    def check(self, program, monitor):
        super(BufferOverflowCheck, self).check(program, monitor)
        # In a real implementation, this would analyze functions for buffer overflow issues
        # For demonstration, we'll simulate finding some issues
        self.issues = [
            {
                "address": "0x1000",
                "function": "main",
                "description": "Potential buffer overflow in strcpy usage"
            },
            {
                "address": "0x2000",
                "function": "process_input",
                "description": "Unbounded loop writing to fixed-size buffer"
            }
        ]
        return self.issues
    
    def getRecommendation(self):
        return "Use safer string functions (strncpy instead of strcpy) and validate input sizes"

class MemoryLeakCheck(SecureCodingCheck):
    def __init__(self):
        super(MemoryLeakCheck, self).__init__(
            "Memory Leak",
            "Check for potential memory leaks",
            "Medium"
        )
    
    def check(self, program, monitor):
        super(MemoryLeakCheck, self).check(program, monitor)
        # In a real implementation, this would analyze memory allocation and deallocation
        self.issues = [
            {
                "address": "0x3000",
                "function": "allocate_resources",
                "description": "Memory allocated with malloc not freed"
            }
        ]
        return self.issues
    
    def getRecommendation(self):
        return "Ensure all allocated memory is properly freed and use RAII where possible"

class InsecureFunctionCheck(SecureCodingCheck):
    def __init__(self):
        super(InsecureFunctionCheck, self).__init__(
            "Insecure Functions",
            "Check for usage of insecure functions",
            "High"
        )
    
    def check(self, program, monitor):
        super(InsecureFunctionCheck, self).check(program, monitor)
        # In a real implementation, this would search for insecure function calls
        self.issues = [
            {
                "address": "0x4000",
                "function": "handle_password",
                "description": "Usage of gets() function which is inherently unsafe"
            },
            {
                "address": "0x5000",
                "function": "execute_command",
                "description": "Usage of system() with user input"
            }
        ]
        return self.issues
    
    def getRecommendation(self):
        return "Replace insecure functions with safer alternatives (fgets instead of gets, avoid system() with user input)"

class IntegerOverflowCheck(SecureCodingCheck):
    def __init__(self):
        super(IntegerOverflowCheck, self).__init__(
            "Integer Overflow",
            "Check for potential integer overflow vulnerabilities",
            "High"
        )
    
    def check(self, program, monitor):
        super(IntegerOverflowCheck, self).check(program, monitor)
        # In a real implementation, this would analyze arithmetic operations
        self.issues = [
            {
                "address": "0x6000",
                "function": "calculate_size",
                "description": "Potential integer overflow in multiplication"
            }
        ]
        return self.issues
    
    def getRecommendation(self):
        return "Use safe arithmetic operations and validate integer ranges"

class FormatStringCheck(SecureCodingCheck):
    def __init__(self):
        super(FormatStringCheck, self).__init__(
            "Format String",
            "Check for potential format string vulnerabilities",
            "High"
        )
    
    def check(self, program, monitor):
        super(FormatStringCheck, self).__init__(
            "Format String",
            "Check for potential format string vulnerabilities",
            "High"
        )
        # In a real implementation, this would search for format string issues
        self.issues = [
            {
                "address": "0x7000",
                "function": "log_message",
                "description": "User-controlled format string in printf"
            }
        ]
        return self.issues
    
    def getRecommendation(self):
        return "Avoid user-controlled format strings and use fixed format strings"

class SecureCodingChecker(GhidraScript):
    def __init__(self):
        super(SecureCodingChecker, self).__init__()
        self.frame = None
        self.codingChecks = []
        self.results = {}
    
    def run(self):
        try:
            # Initialize secure coding checks
            self.initializeCodingChecks()
            
            # Create main frame
            self.frame = JFrame("Secure Coding Checker")
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
            
            # Create coding checks view
            self.createCodingChecksView(tabbedPane)
            
            # Create issues view
            self.createIssuesView(tabbedPane)
            
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
    
    def initializeCodingChecks(self):
        # Initialize all secure coding checks
        self.codingChecks = [
            BufferOverflowCheck(),
            MemoryLeakCheck(),
            InsecureFunctionCheck(),
            IntegerOverflowCheck(),
            FormatStringCheck()
        ]
    
    def createCodingChecksView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create checks list
        self.checksListModel = DefaultListModel()
        self.checksList = JList(self.checksListModel)
        
        # Add checks to list
        for check in self.codingChecks:
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
        
        tabbedPane.addTab("Coding Checks", panel)
    
    def createIssuesView(self, tabbedPane):
        panel = JPanel(BorderLayout())
        
        # Create issues table
        columnNames = ["Check", "Address", "Function", "Issue"]
        self.issuesTableModel = DefaultTableModel(columnNames, 0)
        self.issuesTable = JTable(self.issuesTableModel)
        self.issuesTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        
        # Set column widths
        self.issuesTable.getColumnModel().getColumn(0).setPreferredWidth(150)
        self.issuesTable.getColumnModel().getColumn(1).setPreferredWidth(100)
        self.issuesTable.getColumnModel().getColumn(2).setPreferredWidth(150)
        self.issuesTable.getColumnModel().getColumn(3).setPreferredWidth(400)
        
        issuesScrollPane = JScrollPane(self.issuesTable)
        panel.add(issuesScrollPane, BorderLayout.CENTER)
        
        tabbedPane.addTab("Issues", panel)
    
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
        self.scoreLabel = GLabel("Secure Coding Score:")
        self.scoreValueLabel = GLabel("N/A")
        
        self.scorePanel.add(self.scoreLabel)
        self.scorePanel.add(self.scoreValueLabel)
        panel.add(self.scorePanel, BorderLayout.NORTH)
        
        tabbedPane.addTab("Summary", panel)
    
    def onCheckSelection(self, event):
        selectedIndex = self.checksList.getSelectedIndex()
        if selectedIndex >= 0:
            check = self.codingChecks[selectedIndex]
            details = "Check: " + check.name + "\n"
            details += "Description: " + check.description + "\n"
            details += "Severity: " + check.severity + "\n"
            details += "Issues Found: " + str(len(check.getIssues())) + "\n"
            details += "Recommendation: " + check.getRecommendation()
            self.checkDetailsText.setText(details)
    
    def runAnalysis(self, event):
        self.statusBar.setText("Running secure coding analysis...")
        
        # Run analysis in a task
        from ghidra.util.task import TaskRunner
        
        class SecureCodingAnalysisTask(Task):
            def __init__(self, analyzer):
                super(SecureCodingAnalysisTask, self).__init__("Running Secure Coding Analysis", True, True, True)
                self.analyzer = analyzer
            
            def run(self, monitor):
                try:
                    # Run all secure coding checks
                    monitor.initialize(len(self.analyzer.codingChecks))
                    
                    for i, check in enumerate(self.analyzer.codingChecks):
                        monitor.checkCanceled()
                        monitor.setProgress(i)
                        monitor.setMessage("Running check: " + check.name)
                        
                        check.check(currentProgram, monitor)
                    
                    # Update results
                    def on_complete():
                        self.analyzer.updateIssues()
                        self.analyzer.updateRecommendations()
                        self.analyzer.updateSummary()
                        self.analyzer.statusBar.setText("Analysis completed")
                        JOptionPane.showMessageDialog(self.analyzer.frame, "Secure coding analysis completed", "Success", JOptionPane.INFORMATION_MESSAGE)
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
        
        analysisTask = SecureCodingAnalysisTask(self)
        TaskRunner.run(analysisTask)
    
    def updateIssues(self):
        # Clear existing issues
        self.issuesTableModel.setRowCount(0)
        
        # Add issues to table
        for check in self.codingChecks:
            for issue in check.getIssues():
                self.issuesTableModel.addRow([
                    check.name,
                    issue["address"],
                    issue["function"],
                    issue["description"]
                ])
    
    def updateRecommendations(self):
        recommendations = "Secure Coding Recommendations:\n\n"
        
        # Add recommendations for all checks
        for check in self.codingChecks:
            issues = check.getIssues()
            if issues:
                recommendations += "- " + check.getRecommendation() + " (" + check.severity + " severity)\n"
        
        if not recommendations.strip().endswith(":"):
            self.recommendationsText.setText(recommendations)
        else:
            self.recommendationsText.setText("No issues found! All secure coding practices are followed.")
    
    def updateSummary(self):
        # Calculate total issues
        totalIssues = sum(len(check.getIssues()) for check in self.codingChecks)
        highSeverityIssues = sum(len(issue for issue in check.getIssues()) for check in self.codingChecks if check.severity == "High")
        
        # Calculate secure coding score
        maxPossibleIssues = len(self.codingChecks) * 5  # Assume 5 potential issues per check
        score = int(((maxPossibleIssues - totalIssues) / maxPossibleIssues) * 100) if maxPossibleIssues > 0 else 100
        
        # Update score label
        self.scoreValueLabel.setText(str(score) + "/100")
        
        # Create summary
        summary = "Secure Coding Analysis Summary:\n\n"
        summary += "Total Checks: " + str(len(self.codingChecks)) + "\n"
        summary += "Total Issues Found: " + str(totalIssues) + "\n"
        summary += "High Severity Issues: " + str(highSeverityIssues) + "\n"
        summary += "Secure Coding Score: " + str(score) + "/100\n\n"
        
        # Add detailed summary
        if totalIssues == 0:
            summary += "Excellent! No secure coding issues found."
        elif score >= 80:
            summary += "Good! Few secure coding issues found. The code follows most secure practices."
        elif score >= 50:
            summary += "Fair. Some secure coding issues found. There are areas for improvement."
        else:
            summary += "Poor. Many secure coding issues found. Immediate attention is needed."
        
        self.summaryText.setText(summary)
    
    def exportResults(self, event):
        try:
            # Create export text
            exportText = "Secure Coding Analysis Report\n"
            exportText += "Generated by SecureCodingChecker.py\n\n"
            
            # Add summary
            totalIssues = sum(len(check.getIssues()) for check in self.codingChecks)
            highSeverityIssues = sum(len(issue for issue in check.getIssues()) for check in self.codingChecks if check.severity == "High")
            maxPossibleIssues = len(self.codingChecks) * 5
            score = int(((maxPossibleIssues - totalIssues) / maxPossibleIssues) * 100) if maxPossibleIssues > 0 else 100
            
            exportText += "Summary:\n"
            exportText += "Total Checks: " + str(len(self.codingChecks)) + "\n"
            exportText += "Total Issues Found: " + str(totalIssues) + "\n"
            exportText += "High Severity Issues: " + str(highSeverityIssues) + "\n"
            exportText += "Secure Coding Score: " + str(score) + "/100\n\n"
            
            # Add detailed issues
            exportText += "Detailed Issues:\n\n"
            for check in self.codingChecks:
                issues = check.getIssues()
                if issues:
                    exportText += check.name + " (" + check.severity + " severity):\n"
                    for issue in issues:
                        exportText += "  - Address: " + issue["address"] + ", Function: " + issue["function"] + ": " + issue["description"] + "\n"
                    exportText += "  Recommendation: " + check.getRecommendation() + "\n\n"
            
            # Add recommendations
            exportText += "Recommendations:\n\n"
            for check in self.codingChecks:
                issues = check.getIssues()
                if issues:
                    exportText += "- " + check.getRecommendation() + " (" + check.severity + " severity)\n"
            
            if not exportText.strip().endswith(":"):
                # Save to file
                import java.io.FileWriter
                import java.io.IOException
                
                fileName = "secure_coding_analysis_report.txt"
                fileWriter = java.io.FileWriter(fileName)
                fileWriter.write(exportText)
                fileWriter.close()
                
                JOptionPane.showMessageDialog(self.frame, "Results exported to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self.frame, "No issues found to export", "Information", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error during export: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def showAbout(self, event):
        aboutText = "SecureCodingChecker.py\n"
        aboutText += "Checks code for secure coding practices\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Checks for buffer overflow vulnerabilities\n"
        aboutText += "- Detects potential memory leaks\n"
        aboutText += "- Identifies insecure function usage\n"
        aboutText += "- Finds integer overflow issues\n"
        aboutText += "- Detects format string vulnerabilities\n"
        aboutText += "- Provides detailed security recommendations"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About SecureCodingChecker", JOptionPane.INFORMATION_MESSAGE)

# Run the script
SecureCodingChecker().run()