# Ghidra script for 3D memory layout visualization
# Author: Luyang
# Date: 2023-07-01

import sys
import traceback
from java.awt import BorderLayout, Color, Dimension, FlowLayout, GridLayout, Point, Graphics, Graphics2D, RenderingHints
from java.awt.event import ActionListener, MouseAdapter, MouseEvent, KeyAdapter, KeyEvent
from javax.swing import (JFrame, JPanel, JScrollPane, JTree, JTable, JTextArea, JList, 
                         JTabbedPane, JComboBox, JCheckBox, JButton, JLabel, JTextField, 
                         JOptionPane, JMenu, JMenuBar, JMenuItem, JSplitPane, SwingConstants)
from javax.swing.tree import DefaultMutableTreeNode, DefaultTreeModel, TreeSelectionModel
from javax.swing.table import DefaultTableModel
from javax.swing.event import TreeSelectionListener
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.address import AddressSetView, AddressRange, AddressSet
from ghidra.program.model.listing import Function, Variable, CodeUnit, CodeSection
from ghidra.program.model.symbol import Symbol, SymbolTable, SymbolType
from ghidra.program.model.mem import MemoryBlock
from docking.widgets.combobox import GComboBox
from docking.widgets.label import GLabel
from docking.widgets.textfield import GTextField
from ghidra.app.script import GhidraScript

class MemoryBlock3D:
    def __init__(self, block, x, y, z, width, height, depth):
        self.block = block
        self.x = x
        self.y = y
        self.z = z
        self.width = width
        self.height = height
        self.depth = depth
        self.color = self.getBlockColor()
    
    def getBlockColor(self):
        blockName = self.block.getName().lower()
        if "code" in blockName or ".text" in blockName:
            return Color.BLUE
        elif "data" in blockName or ".data" in blockName:
            return Color.GREEN
        elif "bss" in blockName or ".bss" in blockName:
            return Color.YELLOW
        elif "stack" in blockName:
            return Color.RED
        elif "heap" in blockName:
            return Color.ORANGE
        else:
            return Color.GRAY

class MemoryVisualizationPanel(JPanel):
    def __init__(self, memoryBlocks3D):
        super(MemoryVisualizationPanel, self).__init__()
        self.memoryBlocks3D = memoryBlocks3D
        self.rotationX = 30
        self.rotationY = 45
        self.scale = 1.0
        self.offsetX = 400
        self.offsetY = 300
        self.selectedBlock = None
        
        # Add mouse and keyboard listeners
        self.addMouseListener(self)
        self.addMouseMotionListener(self)
        self.addKeyListener(self)
        self.setFocusable(True)
    
    def paintComponent(self, g):
        super(MemoryVisualizationPanel, self).paintComponent(g)
        g2d = g.create()
        
        # Enable anti-aliasing
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        
        # Clear background
        g2d.setColor(Color.WHITE)
        g2d.fillRect(0, 0, self.getWidth(), self.getHeight())
        
        # Draw coordinate system
        self.drawCoordinateSystem(g2d)
        
        # Draw memory blocks
        for block3D in self.memoryBlocks3D:
            self.drawMemoryBlock(g2d, block3D)
        
        g2d.dispose()
    
    def drawCoordinateSystem(self, g2d):
        # Draw axes
        g2d.setColor(Color.LIGHT_GRAY)
        
        # X-axis
        g2d.drawLine(self.offsetX, self.offsetY, self.offsetX + 100, self.offsetY)
        g2d.drawString("X", self.offsetX + 105, self.offsetY + 5)
        
        # Y-axis
        g2d.drawLine(self.offsetX, self.offsetY, self.offsetX, self.offsetY - 100)
        g2d.drawString("Y", self.offsetX - 5, self.offsetY - 105)
        
        # Z-axis
        g2d.drawLine(self.offsetX, self.offsetY, self.offsetX + 70, self.offsetY + 70)
        g2d.drawString("Z", self.offsetX + 75, self.offsetY + 80)
    
    def drawMemoryBlock(self, g2d, block3D):
        # Calculate 2D coordinates from 3D
        x1, y1 = self.project3DTo2D(block3D.x, block3D.y, block3D.z)
        x2, y2 = self.project3DTo2D(block3D.x + block3D.width, block3D.y, block3D.z)
        x3, y3 = self.project3DTo2D(block3D.x + block3D.width, block3D.y + block3D.height, block3D.z)
        x4, y4 = self.project3DTo2D(block3D.x, block3D.y + block3D.height, block3D.z)
        
        x5, y5 = self.project3DTo2D(block3D.x, block3D.y, block3D.z + block3D.depth)
        x6, y6 = self.project3DTo2D(block3D.x + block3D.width, block3D.y, block3D.z + block3D.depth)
        x7, y7 = self.project3DTo2D(block3D.x + block3D.width, block3D.y + block3D.height, block3D.z + block3D.depth)
        x8, y8 = self.project3DTo2D(block3D.x, block3D.y + block3D.height, block3D.z + block3D.depth)
        
        # Draw faces
        # Back face
        g2d.setColor(self.adjustColor(block3D.color, 0.7))
        g2d.fillPolygon([x1, x2, x3, x4], [y1, y2, y3, y4], 4)
        g2d.setColor(Color.BLACK)
        g2d.drawPolygon([x1, x2, x3, x4], [y1, y2, y3, y4], 4)
        
        # Front face
        g2d.setColor(self.adjustColor(block3D.color, 1.0))
        g2d.fillPolygon([x5, x6, x7, x8], [y5, y6, y7, y8], 4)
        g2d.setColor(Color.BLACK)
        g2d.drawPolygon([x5, x6, x7, x8], [y5, y6, y7, y8], 4)
        
        # Left face
        g2d.setColor(self.adjustColor(block3D.color, 0.8))
        g2d.fillPolygon([x1, x4, x8, x5], [y1, y4, y8, y5], 4)
        g2d.setColor(Color.BLACK)
        g2d.drawPolygon([x1, x4, x8, x5], [y1, y4, y8, y5], 4)
        
        # Right face
        g2d.setColor(self.adjustColor(block3D.color, 0.9))
        g2d.fillPolygon([x2, x3, x7, x6], [y2, y3, y7, y6], 4)
        g2d.setColor(Color.BLACK)
        g2d.drawPolygon([x2, x3, x7, x6], [y2, y3, y7, y6], 4)
        
        # Top face
        g2d.setColor(self.adjustColor(block3D.color, 1.1))
        g2d.fillPolygon([x4, x3, x7, x8], [y4, y3, y7, y8], 4)
        g2d.setColor(Color.BLACK)
        g2d.drawPolygon([x4, x3, x7, x8], [y4, y3, y7, y8], 4)
        
        # Bottom face
        g2d.setColor(self.adjustColor(block3D.color, 0.6))
        g2d.fillPolygon([x1, x2, x6, x5], [y1, y2, y6, y5], 4)
        g2d.setColor(Color.BLACK)
        g2d.drawPolygon([x1, x2, x6, x5], [y1, y2, y6, y5], 4)
        
        # Draw block name
        g2d.setColor(Color.BLACK)
        centerX = (x1 + x2 + x3 + x4) / 4
        centerY = (y1 + y2 + y3 + y4) / 4
        g2d.drawString(block3D.block.getName(), int(centerX), int(centerY))
    
    def project3DTo2D(self, x, y, z):
        # Simple 3D to 2D projection
        # Apply rotation
        radiansX = math.radians(self.rotationX)
        radiansY = math.radians(self.rotationY)
        
        # Rotate around X-axis
        rotatedY = y * math.cos(radiansX) - z * math.sin(radiansX)
        rotatedZ = y * math.sin(radiansX) + z * math.cos(radiansX)
        
        # Rotate around Y-axis
        rotatedX = x * math.cos(radiansY) + rotatedZ * math.sin(radiansY)
        rotatedZ = -x * math.sin(radiansY) + rotatedZ * math.cos(radiansY)
        
        # Apply scale
        scaledX = rotatedX * self.scale
        scaledY = rotatedY * self.scale
        
        # Apply offset
        screenX = self.offsetX + int(scaledX)
        screenY = self.offsetY - int(scaledY)
        
        return screenX, screenY
    
    def adjustColor(self, color, factor):
        r = min(255, max(0, int(color.getRed() * factor)))
        g = min(255, max(0, int(color.getGreen() * factor)))
        b = min(255, max(0, int(color.getBlue() * factor)))
        return Color(r, g, b)
    
    def setRotation(self, rotationX, rotationY):
        self.rotationX = rotationX
        self.rotationY = rotationY
        self.repaint()
    
    def setScale(self, scale):
        self.scale = scale
        self.repaint()
    
    def setOffset(self, offsetX, offsetY):
        self.offsetX = offsetX
        self.offsetY = offsetY
        self.repaint()
    
    def getSelectedBlockAt(self, x, y):
        # Simple hit testing
        for block3D in self.memoryBlocks3D:
            # Check if click is within the projected bounds of any block
            # This is a simplified implementation
            blockX1, blockY1 = self.project3DTo2D(block3D.x, block3D.y, block3D.z)
            blockX2, blockY2 = self.project3DTo2D(block3D.x + block3D.width, block3D.y + block3D.height, block3D.z + block3D.depth)
            
            if min(blockX1, blockX2) <= x <= max(blockX1, blockX2) and \
               min(blockY1, blockY2) <= y <= max(blockY1, blockY2):
                return block3D
        return None

    # Mouse events
    def mousePressed(self, e):
        self.selectedBlock = self.getSelectedBlockAt(e.getX(), e.getY())
        self.repaint()
    
    def mouseReleased(self, e):
        pass
    
    def mouseDragged(self, e):
        pass
    
    def mouseMoved(self, e):
        pass
    
    # Keyboard events
    def keyPressed(self, e):
        if e.getKeyCode() == KeyEvent.VK_UP:
            self.rotationX -= 5
        elif e.getKeyCode() == KeyEvent.VK_DOWN:
            self.rotationX += 5
        elif e.getKeyCode() == KeyEvent.VK_LEFT:
            self.rotationY -= 5
        elif e.getKeyCode() == KeyEvent.VK_RIGHT:
            self.rotationY += 5
        elif e.getKeyCode() == KeyEvent.VK_PLUS or e.getKeyCode() == KeyEvent.VK_EQUALS:
            self.scale *= 1.1
        elif e.getKeyCode() == KeyEvent.VK_MINUS:
            self.scale *= 0.9
        
        self.repaint()
    
    def keyReleased(self, e):
        pass
    
    def keyTyped(self, e):
        pass

class _3DMemoryVisualizer(GhidraScript):
    def __init__(self):
        super(_3DMemoryVisualizer, self).__init__()
        self.frame = None
        self.memoryBlocks3D = []
        self.memoryVisualizationPanel = None
    
    def run(self):
        try:
            # Import math for 3D calculations
            global math
            import math
            
            # Get memory blocks
            memoryBlocks = currentProgram.getMemory().getBlocks()
            
            # Create 3D memory blocks
            self.create3DMemoryBlocks(memoryBlocks)
            
            # Create main frame
            self.frame = JFrame("3D Memory Visualizer")
            self.frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
            self.frame.setSize(1000, 800)
            self.frame.setLocationRelativeTo(None)
            
            # Create menu bar
            menuBar = JMenuBar()
            fileMenu = JMenu("File")
            exportMenuItem = JMenuItem("Export Visualization")
            exportMenuItem.addActionListener(self.exportVisualization)
            fileMenu.add(exportMenuItem)
            menuBar.add(fileMenu)
            
            viewMenu = JMenu("View")
            resetViewMenuItem = JMenuItem("Reset View")
            resetViewMenuItem.addActionListener(self.resetView)
            viewMenu.add(resetViewMenuItem)
            menuBar.add(viewMenu)
            
            helpMenu = JMenu("Help")
            aboutMenuItem = JMenuItem("About")
            aboutMenuItem.addActionListener(self.showAbout)
            helpMenu.add(aboutMenuItem)
            menuBar.add(helpMenu)
            
            self.frame.setJMenuBar(menuBar)
            
            # Create main panel
            mainPanel = JPanel(BorderLayout())
            
            # Create control panel
            controlPanel = JPanel(GridLayout(4, 2, 5, 5))
            controlPanel.setPreferredSize(Dimension(200, 300))
            
            # Rotation controls
            rotationXLabel = GLabel("Rotation X:")
            self.rotationXSlider = javax.swing.JSlider(0, 360, 30)
            self.rotationXSlider.addChangeListener(self.onRotationChange)
            
            rotationYLabel = GLabel("Rotation Y:")
            self.rotationYSlider = javax.swing.JSlider(0, 360, 45)
            self.rotationYSlider.addChangeListener(self.onRotationChange)
            
            # Scale control
            scaleLabel = GLabel("Scale:")
            self.scaleSlider = javax.swing.JSlider(1, 200, 100)
            self.scaleSlider.addChangeListener(self.onScaleChange)
            
            # Memory block list
            blockListLabel = GLabel("Memory Blocks:")
            self.blockListModel = javax.swing.DefaultListModel()
            self.blockList = JList(self.blockListModel)
            self.blockList.addListSelectionListener(self.onBlockSelection)
            
            for block3D in self.memoryBlocks3D:
                self.blockListModel.addElement(block3D.block.getName())
            
            blockListScrollPane = JScrollPane(self.blockList)
            
            controlPanel.add(rotationXLabel)
            controlPanel.add(self.rotationXSlider)
            controlPanel.add(rotationYLabel)
            controlPanel.add(self.rotationYSlider)
            controlPanel.add(scaleLabel)
            controlPanel.add(self.scaleSlider)
            controlPanel.add(blockListLabel)
            controlPanel.add(blockListScrollPane)
            
            # Create memory visualization panel
            self.memoryVisualizationPanel = MemoryVisualizationPanel(self.memoryBlocks3D)
            
            # Create split pane
            splitPane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, controlPanel, self.memoryVisualizationPanel)
            splitPane.setDividerLocation(200)
            
            mainPanel.add(splitPane, BorderLayout.CENTER)
            
            # Create status bar
            self.statusBar = GLabel("Use arrow keys to rotate, +/- to scale, click to select blocks")
            self.statusBar.setHorizontalAlignment(SwingConstants.LEFT)
            mainPanel.add(self.statusBar, BorderLayout.SOUTH)
            
            self.frame.add(mainPanel)
            self.frame.setVisible(True)
            
        except Exception as e:
            print("Error: " + str(e))
            traceback.print_exc()
    
    def create3DMemoryBlocks(self, memoryBlocks):
        # Create 3D representation of memory blocks
        # Simple layout algorithm
        x = 0
        y = 0
        z = 0
        blockSize = 50
        
        for block in memoryBlocks:
            # Calculate block dimensions based on size
            blockSizeMB = block.getSize() / (1024 * 1024.0)
            width = max(20, min(200, int(blockSizeMB * 2)))
            height = 50
            depth = 30
            
            # Create 3D block
            block3D = MemoryBlock3D(block, x, y, z, width, height, depth)
            self.memoryBlocks3D.append(block3D)
            
            # Update position for next block
            x += width + 10
            if x > 500:
                x = 0
                z += depth + 10
    
    def onRotationChange(self, event):
        if self.memoryVisualizationPanel:
            rotationX = self.rotationXSlider.getValue()
            rotationY = self.rotationYSlider.getValue()
            self.memoryVisualizationPanel.setRotation(rotationX, rotationY)
    
    def onScaleChange(self, event):
        if self.memoryVisualizationPanel:
            scale = self.scaleSlider.getValue() / 100.0
            self.memoryVisualizationPanel.setScale(scale)
    
    def onBlockSelection(self, event):
        selectedIndex = self.blockList.getSelectedIndex()
        if selectedIndex >= 0 and self.memoryVisualizationPanel:
            selectedBlock3D = self.memoryBlocks3D[selectedIndex]
            # Highlight selected block
            self.memoryVisualizationPanel.selectedBlock = selectedBlock3D
            self.memoryVisualizationPanel.repaint()
            # Show block details
            self.showBlockDetails(selectedBlock3D)
    
    def showBlockDetails(self, block3D):
        block = block3D.block
        details = "Memory Block Details:\n\n"
        details += "Name: " + block.getName() + "\n"
        details += "Start Address: " + str(block.getStart()) + "\n"
        details += "End Address: " + str(block.getEnd()) + "\n"
        details += "Size: " + str(block.getSize()) + " bytes\n"
        details += "Permissions: "
        details += "R" if block.isReadable() else "-"
        details += "W" if block.isWritable() else "-"
        details += "X" if block.isExecutable() else "-"
        details += "\n"
        details += "Initialized: " + str(block.isInitialized()) + "\n"
        
        JOptionPane.showMessageDialog(self.frame, details, "Memory Block Details", JOptionPane.INFORMATION_MESSAGE)
    
    def exportVisualization(self, event):
        try:
            # Simple export to image
            import java.io.File
            import javax.imageio.ImageIO
            
            # Create a buffered image
            image = self.memoryVisualizationPanel.createImage(800, 600)
            g = image.getGraphics()
            self.memoryVisualizationPanel.paint(g)
            g.dispose()
            
            # Save to file
            file = java.io.File("memory_visualization.png")
            ImageIO.write(image, "png", file)
            
            JOptionPane.showMessageDialog(self.frame, "Visualization exported to memory_visualization.png", "Success", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self.frame, "Error during export: " + str(e), "Error", JOptionPane.ERROR_MESSAGE)
    
    def resetView(self, event):
        if self.memoryVisualizationPanel:
            self.rotationXSlider.setValue(30)
            self.rotationYSlider.setValue(45)
            self.scaleSlider.setValue(100)
            self.memoryVisualizationPanel.setRotation(30, 45)
            self.memoryVisualizationPanel.setScale(1.0)
            self.memoryVisualizationPanel.setOffset(400, 300)
    
    def showAbout(self, event):
        aboutText = "3DMemoryVisualizer.py\n"
        aboutText += "3D memory layout visualization tool\n"
        aboutText += "Author: Luyang\n"
        aboutText += "Date: 2023-07-01\n"
        aboutText += "Version: 1.0\n\n"
        aboutText += "Features:\n"
        aboutText += "- 3D visualization of memory blocks\n"
        aboutText += "- Rotation and scaling controls\n"
        aboutText += "- Memory block details\n"
        aboutText += "- Export to image\n\n"
        aboutText += "Controls:\n"
        aboutText += "- Use arrow keys to rotate\n"
        aboutText += "- Use +/- to scale\n"
        aboutText += "- Click on blocks to view details"
        
        JOptionPane.showMessageDialog(self.frame, aboutText, "About 3DMemoryVisualizer", JOptionPane.INFORMATION_MESSAGE)

# Run the script
_3DMemoryVisualizer().run()