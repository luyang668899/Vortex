# Ghidra script for creating customizable analysis workflows
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
import json
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import (JFrame, JPanel, JScrollPane, JTree, JTable, JTextArea, JList, 
                         JTabbedPane, JComboBox, JCheckBox, JButton, JLabel, JTextField, 
                         JOptionPane, JMenu, JMenuBar, JMenuItem, JSplitPane, SwingConstants, 
                         DefaultListModel, TransferHandler)
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

class AnalysisStep:
    def __init__(self, name, description, parameters=None):
        self.name = name
        self.description = description
        self.parameters = parameters or {}
    
    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'parameters': self.parameters
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(data['name'], data['description'], data.get('parameters', {}))
    
    def execute(self, program, monitor):
        # Base implementation - to be overridden by specific steps
        monitor.setMessage("Executing step: " + self.name)
        return True

class FunctionDiscoveryStep(AnalysisStep):
    def __init__(self):
        super(FunctionDiscoveryStep, self).__init__(
            "Function Discovery",
            "Discover functions in the program",
            {"recursive": True, "threshold": 0.8}
        )
    
    def execute(self, program, monitor):
        super(FunctionDiscoveryStep, self).execute(program, monitor)
        # In a real implementation, this would call Ghidra's function discovery
        monitor.setMessage("Discovering functions...")
        monitor.checkCanceled()
        # Simulate work
        import time
        time.sleep(1)
        return True

class SymbolicAnalysisStep(AnalysisStep):
    def __init__(self):
        super(SymbolicAnalysisStep, self).__init__(
            "Symbolic Analysis",
            "Perform symbolic analysis on functions",
            {"depth": 5, "timeout": 30}
        )
    
    def execute(self, program, monitor):
        super(SymbolicAnalysisStep, self).execute(program, monitor)
        monitor.setMessage("Performing symbolic analysis...")
        monitor.checkCanceled()
        import time
        time.sleep(1.5)
        return True

class DataFlowAnalysisStep(AnalysisStep):
    def __init__(self):
        super(DataFlowAnalysisStep, self).__init__(
            "Data Flow Analysis",
            "Analyze data flow between functions",
            {"interprocedural": True, "backward": False}
        )
    
    def execute(self, program, monitor):
        super(DataFlowAnalysisStep, self).execute(program, monitor)
        monitor.setMessage("Analyzing data flow...")
        monitor.checkCanceled()
        import time
        time.sleep(1.2)
        return True

class ControlFlowAnalysisStep(AnalysisStep):
    def __init__(self):
        super(ControlFlowAnalysisStep, self).__init__(
            "Control Flow Analysis",
            "Build control flow graphs for functions",
            {"simplify": True, "inline": False}
        )
    
    def execute(self, program, monitor):
        super(ControlFlowAnalysisStep, self).execute(program, monitor)
        monitor.setMessage("Building control flow graphs...")
        monitor.checkCanceled()
        import time
        time.sleep(0.8)
        return True

class StringAnalysisStep(AnalysisStep):
    def __init__(self):
        super(StringAnalysisStep, self).__init__(
            "String Analysis",
            "Identify strings in the program",
            {"min_length": 4, "utf8": True, "utf16": False}
        )
    
    def execute(self, program, monitor):
        super(StringAnalysisStep, self).execute(program, monitor)
        monitor.setMessage("Identifying strings...")
        monitor.checkCanceled()
        import time
        time.sleep(0.5)
        return True

class AnalysisWorkflow:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.steps = []
    
    def add_step(self, step):
        self.steps.append(step)
    
    def remove_step(self, index):
        if 0 <= index < len(self.steps):
            self.steps.pop(index)
    
    def reorder_step(self, from_index, to_index):
        if 0 <= from_index < len(self.steps) and 0 <= to_index < len(self.steps):
            step = self.steps.pop(from_index)
            self.steps.insert(to_index, step)
    
    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'steps': [step.to_dict() for step in self.steps]
        }
    
    @classmethod
    def from_dict(cls, data):
        workflow = cls(data['name'], data['description'])
        for step_data in data.get('steps', []):
            # Map step names to step classes
            step_class = STEP_CLASSES.get(step_data['name'], AnalysisStep)
            step = step_class.from_dict(step_data)
            workflow.add_step(step)
        return workflow
    
    def execute(self, program, monitor):
        monitor.setMessage("Executing workflow: " + self.name)
        monitor.initialize(len(self.steps))
        
        for i, step in enumerate(self.steps):
            monitor.checkCanceled()
            monitor.setProgress(i)
            monitor.setMessage("Step " + str(i+1) + "/" + str(len(self.steps)) + ": " + step.name)
            
            success = step.execute(program, monitor)
            if not success:
                monitor.setMessage("Workflow failed at step: " + step.name)
                return False
        
        monitor.setMessage("Workflow completed successfully")
        return True

# Step classes mapping
STEP_CLASSES = {
    "Function Discovery": FunctionDiscoveryStep,
    "Symbolic Analysis": SymbolicAnalysisStep,
    "Data Flow Analysis": DataFlowAnalysisStep,
    "Control Flow Analysis": ControlFlowAnalysisStep,
    "String Analysis": StringAnalysisStep
}

class WorkflowEditorPanel(JPanel):
    def __init__(self, workflow, parent):
        super(WorkflowEditorPanel, self).__init__(BorderLayout())
        self.workflow = workflow
        self.parent = parent
        
        # Create top panel with workflow info
        infoPanel = JPanel(GridLayout(2, 2, 5, 5))
        infoPanel.setBorder(javax.swing.border.TitledBorder("Workflow Information"))
        
        nameLabel = GLabel("Name:")
        self.nameField = GTextField(workflow.name)
        
        descLabel = GLabel("Description:")
        self.descField = GTextField(workflow.description)
        
        infoPanel.add(nameLabel)
        infoPanel.add(self.nameField)
        infoPanel.add(descLabel)
        infoPanel.add(self.descField)
        
        self.add(infoPanel, BorderLayout.NORTH)
        
        # Create split pane for steps and available steps
        splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        
        # Create workflow steps panel
        stepsPanel = JPanel(BorderLayout())
        stepsPanel.setBorder(javax.swing.border.TitledBorder("Workflow Steps"))
        
        self.stepsListModel = DefaultListModel()
        self.stepsList = JList(self.stepsListModel)
        self.stepsList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION)
        self.stepsList.addListSelectionListener(self.onStepSelection)
        
        # Add steps to list
        for step in workflow.steps:
            self.stepsListModel.addElement(step.name)
        
        stepsScrollPane = JScrollPane(self.stepsList)
        stepsPanel.add(stepsScrollPane, BorderLayout.CENTER)
        
        # Create steps control panel
        stepsControlPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        upButton = JButton("Move Up")
        upButton.addActionListener(self.moveStepUp)
        
        downButton = JButton("Move Down")
        downButton.addActionListener(self.moveStepDown)
        
        removeButton = JButton("Remove Step")
        removeButton.addActionListener(self.removeStep)
        
        stepsControlPanel.add(upButton)
        stepsControlPanel.add(downButton)
        stepsControlPanel.add(removeButton)
        
        stepsPanel.add(stepsControlPanel, BorderLayout.SOUTH)
        
        splitPane.setLeftComponent(stepsPanel)
        
        # Create available steps panel
        availablePanel = JPanel(BorderLayout())
        availablePanel.setBorder(javax.swing.border.TitledBorder("Available Steps"))
        
        self.availableStepsListModel = DefaultListModel()
        self.availableStepsList = JList(self.availableStepsListModel)
        
        # Add available steps
        for step_name in STEP_CLASSES:
            self.availableStepsListModel.addElement(step_name)
        
        availableScrollPane = JScrollPane(self.availableStepsList)
        availablePanel.add(availableScrollPane, BorderLayout.CENTER)
        
        # Create add step button
        addButton = JButton("Add Step")
        addButton.addActionListener(self.addStep)
        availablePanel.add(addButton, BorderLayout.SOUTH)
        
        splitPane.setRightComponent(availablePanel)
        splitPane.setDividerLocation(300)
        
        self.add(splitPane, BorderLayout.CENTER)
        
        # Create step details panel
        self.stepDetailsPanel = JPanel(BorderLayout())
        self.stepDetailsPanel.setBorder(javax.swing.border.TitledBorder("Step Details"))
        
        self.stepDetailsText = JTextArea()
        self.stepDetailsText.setEditable(False)
        self.stepDetailsText.setText("Select a step to see details")
        
        detailsScrollPane = JScrollPane(self.stepDetailsText)
        self.stepDetailsPanel.add(detailsScrollPane, BorderLayout.CENTER)
        
        self.add(self.stepDetailsPanel, BorderLayout.SOUTH)
    
    def onStepSelection(self, event):
        selectedIndex = self.stepsList.getSelectedIndex()
        if selectedIndex >= 0:
            step = self.workflow.steps[selectedIndex]
            details = "Step: " + step.name + "\n"
            details += "Description: " + step.description + "\n"
            details += "Parameters: " + str(step.parameters)
            self.stepDetailsText.setText(details)
        else:
            self.stepDetailsText.setText("Select a step to see details")
    
    def addStep(self, event):
        selectedIndex = self.availableStepsList.getSelectedIndex()
        if selectedIndex >= 0:
            step_name = self.availableStepsListModel.getElementAt(selectedIndex)
            step_class = STEP_CLASSES.get(step_name)
            if step_class:
                step = step_class()
                self.workflow.add_step(step)
                self.stepsListModel.addElement(step.name)
                self.parent.updateWorkflowList()
    
    def removeStep(self, event):
        selectedIndex = self.stepsList.getSelectedIndex()
        if selectedIndex >= 0:
            self.workflow.remove_step(selectedIndex)
            self.stepsListModel.removeElementAt(selectedIndex)
            self.parent.updateWorkflowList()
    
    def moveStepUp(self, event):
        selectedIndex = self.stepsList.getSelectedIndex()
        if selectedIndex > 0:
            self.workflow.reorder_step(selectedIndex, selectedIndex - 1)
            self.stepsListModel.removeElementAt(selectedIndex)
            self.stepsListModel.insertElementAt(self.workflow.steps[selectedIndex - 1].name, selectedIndex - 1)
            self.stepsList.setSelectedIndex(selectedIndex - 1)
    
    def moveStepDown(self, event):
        selectedIndex = self.stepsList.getSelectedIndex()
        if selectedIndex < self.stepsListModel.getSize() - 1:
            self.workflow.reorder_step(selectedIndex, selectedIndex + 1)
            self.stepsListModel.removeElementAt(selectedIndex)
            self.stepsListModel.insertElementAt(self.workflow.steps[selectedIndex + 1].name, selectedIndex + 1)
            self.stepsList.setSelectedIndex(selectedIndex + 1)
    
    def saveChanges(self):
        # Update workflow info
        self.workflow.name = self.nameField.getText()
        self.workflow.description = self.descField.getText()

class AnalysisWorkflowAutomator(GhidraScript):
    def __init__(self):
        super(AnalysisWorkflowAutomator, self).__init__()
        self.frame = None
        self.workflows = []
        self.currentWorkflow = None
        self.workflowEditorPanel = None
    
    def run(self):
        try:
            # Create main frame
            self.frame = JFrame("Analysis Workflow Automator")
            self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.frame.setSize(1000, 700)
            self.frame.setLocationRelativeTo(None)
            
            # Create menu bar
            menuBar = JMenuBar()
            fileMenu = JMenu("File")
            
            newWorkflowMenuItem = JMenuItem("New Workflow")
            newWorkflowMenuItem.addActionListener(self.newWorkflow)
            fileMenu.add(newWorkflowMenuItem)
            
            saveWorkflowMenuItem = JMenuItem("Save Workflow")
            saveWorkflowMenuItem.addActionListener(self.saveWorkflow)
            fileMenu.add(saveWorkflowMenuItem)
            
            loadWorkflowMenuItem = JMenuItem("Load Workflow")
            loadWorkflowMenuItem.addActionListener(self.loadWorkflow)
            fileMenu.add(loadWorkflowMenuItem)
            
            exportWorkflowMenuItem = JMenuItem("Export Workflow")
            exportWorkflowMenuItem.addActionListener(self.exportWorkflow)
            fileMenu.add(exportWorkflowMenuItem)
            
            importWorkflowMenuItem = JMenuItem("Import Workflow")
            importWorkflowMenuItem.addActionListener(self.importWorkflow)
            fileMenu.add(importWorkflowMenuItem)
            
            menuBar.add(fileMenu)
            
            runMenu = JMenu("Run")
            executeWorkflowMenuItem = JMenuItem("Execute Workflow")
            executeWorkflowMenuItem.addActionListener(self.executeWorkflow)
            runMenu.add(executeWorkflowMenuItem)
            menuBar.add(runMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create left panel with workflows list
            leftPanel = JPanel(BorderLayout())
            leftPanel.setPreferredSize(Dimension(250, 700))
            
            workflowsLabel = GLabel("Workflows:")
            leftPanel.add(workflowsLabel, BorderLayout.NORTH)
            
            self.workflowsListModel = DefaultListModel()
            self.workflowsList = JList(self.workflowsListModel)
            self.workflowsList.addListSelectionListener(self.onWorkflowSelection)
            
            workflowsScrollPane = JScrollPane(self.workflowsList)
            leftPanel.add(workflowsScrollPane, BorderLayout.CENTER)
            
            # Create workflow control buttons
            workflowButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            
            newButton = JButton("New")
            newButton.addActionListener(self.newWorkflow)
            
            deleteButton = JButton("Delete")
            deleteButton.addActionListener(self.deleteWorkflow)
            
            workflowButtonsPanel.add(newButton)
            workflowButtonsPanel.add(deleteButton)
            
            leftPanel.add(workflowButtonsPanel, BorderLayout.SOUTH)
            
            # Create right panel with workflow editor
            self.rightPanel = JPanel(BorderLayout())
            
            # Create welcome panel
            welcomePanel = JPanel(BorderLayout())
            welcomeLabel = GLabel("Welcome to Analysis Workflow Automator")
            welcomeLabel.setHorizontalAlignment(SwingConstants.CENTER)
            welcomeLabel.setFont(welcomeLabel.getFont().deriveFont(16.0))
            
            welcomeText = JTextArea()
            welcomeText.setEditable(False)
            welcomeText.setText("Create or select a workflow to begin editing.")
            welcomeText.setLineWrap(True)
            welcomeText.setWrapStyleWord(True)
            
            welcomePanel.add(welcomeLabel, BorderLayout.NORTH)
            welcomePanel.add(welcomeText, BorderLayout.CENTER)
            
            self.rightPanel.add(welcomePanel, BorderLayout.CENTER)
            
            # Create split pane
            splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, leftPanel, self.rightPanel)
            splitPane.setDividerLocation(250)
            
            mainPanel.add(splitPane, BorderLayout.CENTER)
            
            # Create status bar
            self.statusBar = GLabel("Ready")
            self.statusBar.setHorizontalAlignment(SwingConstants.LEFT)
            mainPanel.add(self.statusBar, BorderLayout.SOUTH)
            
            self.frame.add(mainPanel)
            self.frame.setVisible(True)
            
            # Create default workflows
            self.createDefaultWorkflows()
            
        except Exception as e:
            self.statusBar.setText("Error: " + str(e))
            traceback.print_exc()
    
    def createDefaultWorkflows(self):
        # Create a default workflow
        defaultWorkflow = AnalysisWorkflow(
            "Default Analysis Workflow",
            "A default workflow with common analysis steps"
        )
        
        # Add default steps
        defaultWorkflow.add_step(FunctionDiscoveryStep())
        defaultWorkflow.add_step(ControlFlowAnalysisStep())
        defaultWorkflow.add_step(StringAnalysisStep())
        defaultWorkflow.add_step(DataFlowAnalysisStep())
        
        # Add to workflows list
        self.workflows.append(defaultWorkflow)
        self.workflowsListModel.addElement(defaultWorkflow.name)
    
    def newWorkflow(self, event):
        # Prompt for workflow name and description
        name = JOptionPane.showInputDialog(self.frame, "Enter workflow name:")
        if not name:
            return
        
        description = JOptionPane.showInputDialog(self.frame, "Enter workflow description:")
        if not description:
            description = ""
        
        # Create new workflow
        newWorkflow = AnalysisWorkflow(name, description)
        self.workflows.append(newWorkflow)
        self.workflowsListModel.addElement(name)
        
        # Select new workflow
        self.workflowsList.setSelectedIndex(len(self.workflows) - 1)
    
    def deleteWorkflow(self, event):
        selectedIndex = self.workflowsList.getSelectedIndex()
        if selectedIndex >= 0:
            confirm = JOptionPane.showConfirmDialog(
                self.frame, 
                "Are you sure you want to delete this workflow?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )
            
            if confirm == JOptionPane.YES_OPTION:
                self.workflows.pop(selectedIndex)
                self.workflowsListModel.removeElementAt(selectedIndex)
                
                # Clear right panel if deleting current workflow
                if self.currentWorkflow == selectedIndex:
                    self.rightPanel.removeAll()
                    welcomePanel = JPanel(BorderLayout())
                    welcomeLabel = GLabel("Welcome to Analysis Workflow Automator")
                    welcomeLabel.setHorizontalAlignment(SwingConstants.CENTER)
                    welcomeLabel.setFont(welcomeLabel.getFont().deriveFont(16.0))
                    welcomePanel.add(welcomeLabel, BorderLayout.CENTER)
                    self.rightPanel.add(welcomePanel)
                    self.rightPanel.revalidate()
                    self.rightPanel.repaint()
    
    def onWorkflowSelection(self, event):
        selectedIndex = self.workflowsList.getSelectedIndex()
        if selectedIndex >= 0:
            self.currentWorkflow = selectedIndex
            workflow = self.workflows[selectedIndex]
            
            # Replace right panel with workflow editor
            self.rightPanel.removeAll()
            self.workflowEditorPanel = WorkflowEditorPanel(workflow, self)
            self.rightPanel.add(self.workflowEditorPanel)
            self.rightPanel.revalidate()
            self.rightPanel.repaint()
    
    def updateWorkflowList(self):
        # Update the workflow list display
        selectedIndex = self.workflowsList.getSelectedIndex()
        if selectedIndex >= 0:
            workflow = self.workflows[selectedIndex]
            self.workflowsListModel.setElementAt(workflow.name, selectedIndex)
    
    def saveWorkflow(self, event):
        selectedIndex = self.workflowsList.getSelectedIndex()
        if selectedIndex >= 0:
            workflow = self.workflows[selectedIndex]
            
            # Save workflow to file
            try:
                import java.io.FileWriter
                import java.io.IOException
                
                fileName = workflow.name.replace(" ", "_") + ".json"
                fileWriter = java.io.FileWriter(fileName)
                
                # Convert workflow to JSON
                import json
                workflow_json = json.dumps(workflow.to_dict(), indent=2)
                fileWriter.write(workflow_json)
                fileWriter.close()
                
                JOptionPane.showMessageDialog(self.frame, "Workflow saved to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                JOptionPane.showMessageDialog(self.frame, "Error saving workflow: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def loadWorkflow(self, event):
        try:
            import java.io.File
            import javax.swing.JFileChooser
            
            fileChooser = javax.swing.JFileChooser()
            fileChooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"))
            
            result = fileChooser.showOpenDialog(self.frame)
            if result == javax.swing.JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Read workflow from file
                import json
                with open(file.getPath(), 'r') as f:
                    workflow_data = json.load(f)
                
                workflow = AnalysisWorkflow.from_dict(workflow_data)
                self.workflows.append(workflow)
                self.workflowsListModel.addElement(workflow.name)
                
                JOptionPane.showMessageDialog(self.frame, "Workflow loaded successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error loading workflow: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def exportWorkflow(self, event):
        selectedIndex = self.workflowsList.getSelectedIndex()
        if selectedIndex >= 0:
            workflow = self.workflows[selectedIndex]
            
            try:
                import java.io.File
                import javax.swing.JFileChooser
                
                fileChooser = javax.swing.JFileChooser()
                fileChooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"))
                fileChooser.setSelectedFile(java.io.File(workflow.name.replace(" ", "_") + ".json"))
                
                result = fileChooser.showSaveDialog(self.frame)
                if result == javax.swing.JFileChooser.APPROVE_OPTION:
                    file = fileChooser.getSelectedFile()
                    
                    # Write workflow to file
                    import json
                    with open(file.getPath(), 'w') as f:
                        json.dump(workflow.to_dict(), f, indent=2)
                    
                    JOptionPane.showMessageDialog(self.frame, "Workflow exported to " + file.getPath(), "Success", JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                JOptionPane.showMessageDialog(self.frame, "Error exporting workflow: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def importWorkflow(self, event):
        try:
            import java.io.File
            import javax.swing.JFileChooser
            
            fileChooser = javax.swing.JFileChooser()
            fileChooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"))
            
            result = fileChooser.showOpenDialog(self.frame)
            if result == javax.swing.JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Read workflow from file
                import json
                with open(file.getPath(), 'r') as f:
                    workflow_data = json.load(f)
                
                workflow = AnalysisWorkflow.from_dict(workflow_data)
                self.workflows.append(workflow)
                self.workflowsListModel.addElement(workflow.name)
                
                JOptionPane.showMessageDialog(self.frame, "Workflow imported successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error importing workflow: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def executeWorkflow(self, event):
        selectedIndex = self.workflowsList.getSelectedIndex()
        if selectedIndex >= 0:
            workflow = self.workflows[selectedIndex]
            
            if not workflow.steps:
                JOptionPane.showMessageDialog(self.frame, "Workflow has no steps to execute", "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            # Execute workflow in a task
            from ghidra.util.task import TaskRunner
            
            class WorkflowExecutionTask(Task):
                def __init__(self, workflow, program, parent):
                    super(WorkflowExecutionTask, self).__init__("Executing Workflow", True, True, True)
                    self.workflow = workflow
                    self.program = program
                    self.parent = parent
                
                def run(self, monitor):
                    try:
                        success = self.workflow.execute(self.program, monitor)
                        
                        Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "Workflow executed successfully" if success else "Workflow execution failed", "Success" if success else "Error", JOptionPane.INFORMATION_MESSAGE if success else JOptionPane.ERROR_MESSAGE))
                    except CancelledException:
                        Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "Workflow execution cancelled", "Cancelled", JOptionPane.INFORMATION_MESSAGE))
                    except Exception as e:
                        Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "Error executing workflow: " + str(e), "Error", JOptionPane.ERROR_MESSAGE))
            
            task = WorkflowExecutionTask(workflow, currentProgram, self)
            TaskRunner.run(task)
    
    def showAbout(self, event):
        aboutText = "AnalysisWorkflowAutomator.py\n"
        aboutText += "Create customizable analysis workflows\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Create and edit custom analysis workflows\n"
        aboutText += "- Add and reorder analysis steps\n"
        aboutText += "- Save and load workflows\n"
        aboutText += "- Export and import workflows\n"
        aboutText += "- Execute workflows with progress monitoring"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About AnalysisWorkflowAutomator", JOptionPane.INFORMATION_MESSAGE)

# Run the script
AnalysisWorkflowAutomator().run()