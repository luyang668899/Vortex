# Ghidra script for batch analyzing multiple programs or parts of a program
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
import os
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout
from java.awt.event import ActionListener, MouseAdapter, MouseEvent
from javax.swing import (JFrame, JPanel, JScrollPane, JTree, JTable, JTextArea, JList, 
                         JTabbedPane, JComboBox, JCheckBox, JButton, JLabel, JTextField, 
                         JOptionPane, JMenu, JMenuBar, JMenuItem, JSplitPane, SwingConstants, 
                         DefaultListModel, FileChooser, FileNameExtensionFilter)
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

class BatchAnalysisTask:
    def __init__(self, name, description, files=None, addressRanges=None):
        self.name = name
        self.description = description
        self.files = files or []
        self.addressRanges = addressRanges or []
        self.status = "Pending"
        self.result = None
    
    def to_dict(self):
        return {
            'name': self.name,
            'description': self.description,
            'files': self.files,
            'addressRanges': [str(r) for r in self.addressRanges],
            'status': self.status
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            data['name'],
            data['description'],
            data.get('files', []),
            data.get('addressRanges', [])
        )
    
    def execute(self, monitor):
        monitor.setMessage("Executing batch task: " + self.name)
        monitor.initialize(len(self.files) + len(self.addressRanges))
        
        totalItems = len(self.files) + len(self.addressRanges)
        processedItems = 0
        
        # Process files
        for file in self.files:
            monitor.checkCanceled()
            monitor.setProgress(processedItems)
            monitor.setMessage("Processing file: " + os.path.basename(file))
            
            # In a real implementation, this would open and analyze the file
            self.processFile(file, monitor)
            processedItems += 1
        
        # Process address ranges
        for addrRange in self.addressRanges:
            monitor.checkCanceled()
            monitor.setProgress(processedItems)
            monitor.setMessage("Processing address range: " + str(addrRange))
            
            # In a real implementation, this would analyze the address range
            self.processAddressRange(addrRange, monitor)
            processedItems += 1
        
        self.status = "Completed"
        return True
    
    def processFile(self, file, monitor):
        # Base implementation - to be overridden
        monitor.setMessage("Processing file: " + file)
        # Simulate work
        import time
        time.sleep(1)
    
    def processAddressRange(self, addrRange, monitor):
        # Base implementation - to be overridden
        monitor.setMessage("Processing address range: " + str(addrRange))
        # Simulate work
        import time
        time.sleep(0.5)

class FunctionAnalysisTask(BatchAnalysisTask):
    def __init__(self, files=None, addressRanges=None):
        super(FunctionAnalysisTask, self).__init__(
            "Function Analysis",
            "Analyze functions in selected files or address ranges",
            files,
            addressRanges
        )
    
    def processFile(self, file, monitor):
        monitor.setMessage("Analyzing functions in file: " + file)
        import time
        time.sleep(1.5)
    
    def processAddressRange(self, addrRange, monitor):
        monitor.setMessage("Analyzing functions in range: " + str(addrRange))
        import time
        time.sleep(0.8)

class SecurityAnalysisTask(BatchAnalysisTask):
    def __init__(self, files=None, addressRanges=None):
        super(SecurityAnalysisTask, self).__init__(
            "Security Analysis",
            "Perform security analysis on selected files or address ranges",
            files,
            addressRanges
        )
    
    def processFile(self, file, monitor):
        monitor.setMessage("Performing security analysis on file: " + file)
        import time
        time.sleep(2)
    
    def processAddressRange(self, addrRange, monitor):
        monitor.setMessage("Performing security analysis on range: " + str(addrRange))
        import time
        time.sleep(1)

class BatchAnalyzer(GhidraScript):
    def __init__(self):
        super(BatchAnalyzer, self).__init__()
        self.frame = None
        self.tasks = []
        self.currentTask = None
    
    def run(self):
        try:
            # Create main frame
            self.frame = JFrame("Batch Analyzer")
            self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.frame.setSize(1000, 700)
            self.frame.setLocationRelativeTo(None)
            
            # Create menu bar
            menuBar = JMenuBar()
            fileMenu = JMenu("File")
            
            newTaskMenuItem = JMenuItem("New Task")
            newTaskMenuItem.addActionListener(self.newTask)
            fileMenu.add(newTaskMenuItem)
            
            saveTaskMenuItem = JMenuItem("Save Task")
            saveTaskMenuItem.addActionListener(self.saveTask)
            fileMenu.add(saveTaskMenuItem)
            
            loadTaskMenuItem = JMenuItem("Load Task")
            loadTaskMenuItem.addActionListener(self.loadTask)
            fileMenu.add(loadTaskMenuItem)
            
            exportResultsMenuItem = JMenuItem("Export Results")
            exportResultsMenuItem.addActionListener(self.exportResults)
            fileMenu.add(exportResultsMenuItem)
            
            menuBar.add(fileMenu)
            
            runMenu = JMenu("Run")
            executeTaskMenuItem = JMenuItem("Execute Task")
            executeTaskMenuItem.addActionListener(self.executeTask)
            runMenu.add(executeTaskMenuItem)
            
            executeAllMenuItem = JMenuItem("Execute All Tasks")
            executeAllMenuItem.addActionListener(self.executeAllTasks)
            runMenu.add(executeAllMenuItem)
            
            menuBar.add(runMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create left panel with tasks list
            leftPanel = JPanel(BorderLayout())
            leftPanel.setPreferredSize(Dimension(250, 700))
            
            tasksLabel = GLabel("Tasks:")
            leftPanel.add(tasksLabel, BorderLayout.NORTH)
            
            self.tasksListModel = DefaultListModel()
            self.tasksList = JList(self.tasksListModel)
            self.tasksList.addListSelectionListener(self.onTaskSelection)
            
            tasksScrollPane = JScrollPane(self.tasksList)
            leftPanel.add(tasksScrollPane, BorderLayout.CENTER)
            
            # Create task control buttons
            taskButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
            
            newButton = JButton("New")
            newButton.addActionListener(self.newTask)
            
            deleteButton = JButton("Delete")
            deleteButton.addActionListener(self.deleteTask)
            
            taskButtonsPanel.add(newButton)
            taskButtonsPanel.add(deleteButton)
            
            leftPanel.add(taskButtonsPanel, BorderLayout.SOUTH)
            
            # Create right panel with task editor
            self.rightPanel = JPanel(BorderLayout())
            
            # Create welcome panel
            welcomePanel = JPanel(BorderLayout())
            welcomeLabel = GLabel("Welcome to Batch Analyzer")
            welcomeLabel.setHorizontalAlignment(SwingConstants.CENTER)
            welcomeLabel.setFont(welcomeLabel.getFont().deriveFont(16.0))
            
            welcomeText = JTextArea()
            welcomeText.setEditable(False)
            welcomeText.setText("Create or select a batch task to begin editing.")
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
            
            # Create default task
            self.createDefaultTask()
            
        except Exception as e:
            self.statusBar.setText("Error: " + str(e))
            traceback.print_exc()
    
    def createDefaultTask(self):
        # Create a default batch task
        defaultTask = BatchAnalysisTask(
            "Default Batch Task",
            "A default batch task for demonstration",
            [],
            []
        )
        
        self.tasks.append(defaultTask)
        self.tasksListModel.addElement(defaultTask.name)
    
    def newTask(self, event):
        # Prompt for task details
        name = JOptionPane.showInputDialog(self.frame, "Enter task name:")
        if not name:
            return
        
        description = JOptionPane.showInputDialog(self.frame, "Enter task description:")
        if not description:
            description = ""
        
        # Prompt for task type
        taskType = JOptionPane.showInputDialog(
            self.frame,
            "Enter task type (Function Analysis/Security Analysis/Custom):",
            "Function Analysis"
        )
        
        # Create task based on type
        if taskType == "Function Analysis":
            task = FunctionAnalysisTask(name, description)
        elif taskType == "Security Analysis":
            task = SecurityAnalysisTask(name, description)
        else:
            task = BatchAnalysisTask(name, description)
        
        self.tasks.append(task)
        self.tasksListModel.addElement(task.name)
        
        # Select new task
        self.tasksList.setSelectedIndex(len(self.tasks) - 1)
    
    def deleteTask(self, event):
        selectedIndex = self.tasksList.getSelectedIndex()
        if selectedIndex >= 0:
            confirm = JOptionPane.showConfirmDialog(
                self.frame,
                "Are you sure you want to delete this task?",
                "Confirm Delete",
                JOptionPane.YES_NO_OPTION
            )
            
            if confirm == JOptionPane.YES_OPTION:
                self.tasks.pop(selectedIndex)
                self.tasksListModel.removeElementAt(selectedIndex)
                
                # Clear right panel if deleting current task
                if self.currentTask == selectedIndex:
                    self.rightPanel.removeAll()
                    welcomePanel = JPanel(BorderLayout())
                    welcomeLabel = GLabel("Welcome to Batch Analyzer")
                    welcomeLabel.setHorizontalAlignment(SwingConstants.CENTER)
                    welcomeLabel.setFont(welcomeLabel.getFont().deriveFont(16.0))
                    welcomePanel.add(welcomeLabel, BorderLayout.CENTER)
                    self.rightPanel.add(welcomePanel)
                    self.rightPanel.revalidate()
                    self.rightPanel.repaint()
    
    def onTaskSelection(self, event):
        selectedIndex = self.tasksList.getSelectedIndex()
        if selectedIndex >= 0:
            self.currentTask = selectedIndex
            task = self.tasks[selectedIndex]
            
            # Replace right panel with task editor
            self.rightPanel.removeAll()
            taskEditorPanel = self.createTaskEditorPanel(task)
            self.rightPanel.add(taskEditorPanel)
            self.rightPanel.revalidate()
            self.rightPanel.repaint()
    
    def createTaskEditorPanel(self, task):
        panel = JPanel(BorderLayout())
        
        # Create task info panel
        infoPanel = JPanel(GridLayout(2, 2, 5, 5))
        infoPanel.setBorder(javax.swing.border.TitledBorder("Task Information"))
        
        nameLabel = GLabel("Name:")
        nameField = GTextField(task.name)
        
        descLabel = GLabel("Description:")
        descField = GTextField(task.description)
        
        infoPanel.add(nameLabel)
        infoPanel.add(nameField)
        infoPanel.add(descLabel)
        infoPanel.add(descField)
        
        panel.add(infoPanel, BorderLayout.NORTH)
        
        # Create tabbed pane for files and address ranges
        tabbedPane = JTabbedPane()
        
        # Files tab
        filesPanel = JPanel(BorderLayout())
        
        filesListLabel = GLabel("Files:")
        filesPanel.add(filesListLabel, BorderLayout.NORTH)
        
        self.filesListModel = DefaultListModel()
        filesList = JList(self.filesListModel)
        
        # Add existing files
        for file in task.files:
            self.filesListModel.addElement(os.path.basename(file))
        
        filesScrollPane = JScrollPane(filesList)
        filesPanel.add(filesScrollPane, BorderLayout.CENTER)
        
        # File control buttons
        fileButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        addFileButton = JButton("Add Files")
        addFileButton.addActionListener(lambda e, t=task: self.addFiles(t))
        
        removeFileButton = JButton("Remove File")
        removeFileButton.addActionListener(lambda e, t=task, fl=filesList: self.removeFile(t, fl))
        
        fileButtonsPanel.add(addFileButton)
        fileButtonsPanel.add(removeFileButton)
        
        filesPanel.add(fileButtonsPanel, BorderLayout.SOUTH)
        
        tabbedPane.addTab("Files", filesPanel)
        
        # Address Ranges tab
        rangesPanel = JPanel(BorderLayout())
        
        rangesListLabel = GLabel("Address Ranges:")
        rangesPanel.add(rangesListLabel, BorderLayout.NORTH)
        
        self.rangesListModel = DefaultListModel()
        rangesList = JList(self.rangesListModel)
        
        # Add existing ranges
        for addrRange in task.addressRanges:
            self.rangesListModel.addElement(str(addrRange))
        
        rangesScrollPane = JScrollPane(rangesList)
        rangesPanel.add(rangesScrollPane, BorderLayout.CENTER)
        
        # Range control buttons
        rangeButtonsPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        addRangeButton = JButton("Add Range")
        addRangeButton.addActionListener(lambda e, t=task: self.addAddressRange(t))
        
        removeRangeButton = JButton("Remove Range")
        removeRangeButton.addActionListener(lambda e, t=task, rl=rangesList: self.removeAddressRange(t, rl))
        
        rangeButtonsPanel.add(addRangeButton)
        rangeButtonsPanel.add(removeRangeButton)
        
        rangesPanel.add(rangeButtonsPanel, BorderLayout.SOUTH)
        
        tabbedPane.addTab("Address Ranges", rangesPanel)
        
        panel.add(tabbedPane, BorderLayout.CENTER)
        
        # Create task status panel
        statusPanel = JPanel(FlowLayout(FlowLayout.LEFT))
        statusLabel = GLabel("Status:")
        statusValueLabel = GLabel(task.status)
        
        statusPanel.add(statusLabel)
        statusPanel.add(statusValueLabel)
        
        panel.add(statusPanel, BorderLayout.SOUTH)
        
        return panel
    
    def addFiles(self, task):
        # Open file chooser
        import java.io.File
        fileChooser = FileChooser()
        fileChooser.setMultiSelectionEnabled(True)
        fileChooser.setFileFilter(FileNameExtensionFilter("Executable Files", "exe", "dll", "elf", "bin"))
        
        result = fileChooser.showOpenDialog(self.frame)
        if result == FileChooser.APPROVE_OPTION:
            selectedFiles = fileChooser.getSelectedFiles()
            for file in selectedFiles:
                filePath = file.getAbsolutePath()
                task.files.append(filePath)
                self.filesListModel.addElement(os.path.basename(filePath))
    
    def removeFile(self, task, filesList):
        selectedIndex = filesList.getSelectedIndex()
        if selectedIndex >= 0:
            task.files.pop(selectedIndex)
            self.filesListModel.removeElementAt(selectedIndex)
    
    def addAddressRange(self, task):
        # Prompt for address range
        rangeStr = JOptionPane.showInputDialog(self.frame, "Enter address range (e.g., 0x1000-0x2000):")
        if rangeStr:
            task.addressRanges.append(rangeStr)
            self.rangesListModel.addElement(rangeStr)
    
    def removeAddressRange(self, task, rangesList):
        selectedIndex = rangesList.getSelectedIndex()
        if selectedIndex >= 0:
            task.addressRanges.pop(selectedIndex)
            self.rangesListModel.removeElementAt(selectedIndex)
    
    def saveTask(self, event):
        selectedIndex = self.tasksList.getSelectedIndex()
        if selectedIndex >= 0:
            task = self.tasks[selectedIndex]
            
            # Save task to file
            try:
                import json
                import java.io.FileWriter
                
                fileName = task.name.replace(" ", "_") + "_task.json"
                fileWriter = java.io.FileWriter(fileName)
                
                task_json = json.dumps(task.to_dict(), indent=2)
                fileWriter.write(task_json)
                fileWriter.close()
                
                JOptionPane.showMessageDialog(self.frame, "Task saved to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
            except Exception as e:
                JOptionPane.showMessageDialog(self.frame, "Error saving task: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def loadTask(self, event):
        try:
            import java.io.File
            import javax.swing.JFileChooser
            import json
            
            fileChooser = javax.swing.JFileChooser()
            fileChooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON Files", "json"))
            
            result = fileChooser.showOpenDialog(self.frame)
            if result == javax.swing.JFileChooser.APPROVE_OPTION:
                file = fileChooser.getSelectedFile()
                
                # Read task from file
                with open(file.getPath(), 'r') as f:
                    task_data = json.load(f)
                
                task = BatchAnalysisTask.from_dict(task_data)
                self.tasks.append(task)
                self.tasksListModel.addElement(task.name)
                
                JOptionPane.showMessageDialog(self.frame, "Task loaded successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error loading task: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def executeTask(self, event):
        selectedIndex = self.tasksList.getSelectedIndex()
        if selectedIndex >= 0:
            task = self.tasks[selectedIndex]
            
            if not task.files and not task.addressRanges:
                JOptionPane.showMessageDialog(self.frame, "Task has no files or address ranges to process", "Error", JOptionPane.ERROR_MESSAGE)
                return
            
            # Execute task in a task
            from ghidra.util.task import TaskRunner
            
            class BatchTaskExecutionTask(Task):
                def __init__(self, task, parent):
                    super(BatchTaskExecutionTask, self).__init__("Executing Batch Task", True, True, True)
                    self.task = task
                    self.parent = parent
                
                def run(self, monitor):
                    try:
                        success = self.task.execute(monitor)
                        
                        def on_success():
                            JOptionPane.showMessageDialog(self.parent.frame, "Task executed successfully", "Success", JOptionPane.INFORMATION_MESSAGE)
                            # Update task status
                            self.task.status = "Completed"
                            # Refresh task list
                            self.parent.tasksListModel.setElementAt(self.task.name + " (Completed)", selectedIndex)
                        
                        def on_failure():
                            JOptionPane.showMessageDialog(self.parent.frame, "Task execution failed", "Error", JOptionPane.ERROR_MESSAGE)
                            self.task.status = "Failed"
                            self.parent.tasksListModel.setElementAt(self.task.name + " (Failed)", selectedIndex)
                        
                        Swing.runLater(on_success if success else on_failure)
                    except CancelledException:
                        def on_cancelled():
                            JOptionPane.showMessageDialog(self.parent.frame, "Task execution cancelled", "Cancelled", JOptionPane.INFORMATION_MESSAGE)
                            self.task.status = "Cancelled"
                            self.parent.tasksListModel.setElementAt(self.task.name + " (Cancelled)", selectedIndex)
                        Swing.runLater(on_cancelled)
                    except Exception as e:
                        def on_error():
                            JOptionPane.showMessageDialog(self.parent.frame, "Error executing task: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
                            self.task.status = "Error"
                            self.parent.tasksListModel.setElementAt(self.task.name + " (Error)", selectedIndex)
                        Swing.runLater(on_error)
            
            executionTask = BatchTaskExecutionTask(task, self)
            TaskRunner.run(executionTask)
    
    def executeAllTasks(self, event):
        if not self.tasks:
            JOptionPane.showMessageDialog(self.frame, "No tasks to execute", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        # Execute all tasks in a task
        from ghidra.util.task import TaskRunner
        
        class ExecuteAllTasksTask(Task):
            def __init__(self, tasks, parent):
                super(ExecuteAllTasksTask, self).__init__("Executing All Tasks", True, True, True)
                self.tasks = tasks
                self.parent = parent
            
            def run(self, monitor):
                try:
                    monitor.initialize(len(self.tasks))
                    
                    for i, task in enumerate(self.tasks):
                        monitor.checkCanceled()
                        monitor.setProgress(i)
                        monitor.setMessage("Executing task " + str(i+1) + "/" + str(len(self.tasks)) + ": " + task.name)
                        
                        success = task.execute(monitor)
                        if not success:
                            Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "Task execution failed: " + task.name, "Error", JOptionPane.ERROR_MESSAGE))
                            task.status = "Failed"
                        else:
                            task.status = "Completed"
                    
                    Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "All tasks executed", "Success", JOptionPane.INFORMATION_MESSAGE))
                    
                    # Update task list
                    for i, task in enumerate(self.tasks):
                        self.parent.tasksListModel.setElementAt(task.name + " (" + task.status + ")", i)
                        
                except CancelledException:
                    Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "Execution cancelled", "Cancelled", JOptionPane.INFORMATION_MESSAGE))
                except Exception as e:
                    Swing.runLater(lambda: JOptionPane.showMessageDialog(self.parent.frame, "Error executing tasks: " + str(e), "Error", JOptionPane.ERROR_MESSAGE))
        
        executionTask = ExecuteAllTasksTask(self.tasks, self)
        TaskRunner.run(executionTask)
    
    def exportResults(self, event):
        if not self.tasks:
            JOptionPane.showMessageDialog(self.frame, "No tasks to export", "Error", JOptionPane.ERROR_MESSAGE)
            return
        
        try:
            import json
            import java.io.FileWriter
            
            # Create export data
            exportData = {
                'tasks': [task.to_dict() for task in self.tasks]
            }
            
            # Save to file
            fileName = "batch_analysis_results.json"
            fileWriter = java.io.FileWriter(fileName)
            fileWriter.write(json.dumps(exportData, indent=2))
            fileWriter.close()
            
            JOptionPane.showMessageDialog(self.frame, "Results exported to " + fileName, "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error exporting results: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def showAbout(self, event):
        aboutText = "BatchAnalyzer.py\n"
        aboutText += "Batch analysis tool for multiple programs or address ranges\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- Create and manage batch analysis tasks\n"
        aboutText += "- Add multiple files for analysis\n"
        aboutText += "- Specify address ranges for analysis\n"
        aboutText += "- Execute tasks in background\n"
        aboutText += "- Export results to JSON"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About BatchAnalyzer", JOptionPane.INFORMATION_MESSAGE)

# Run the script
BatchAnalyzer().run()