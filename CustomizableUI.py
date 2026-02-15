#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CustomizableUI.py

可完全自定义的用户界面布局工具，支持界面组件拖拽功能、布局保存与加载功能，以及不同分辨率下的适配性。

作者: Ghidra开发者
日期: 2023-10-01
版本: 1.0.0
"""

import os
import sys
import json
import threading
import time
from datetime import datetime

# Ghidra模块导入
try:
    from ghidra.util.task import Task, TaskMonitor
    from ghidra.app.script import GhidraScript
    from docking.widgets.dialogs import GenericDialog
    from docking.widgets.table import GTable
    from docking.widgets.checkbox.GCheckBox import GCheckBox
    from docking.widgets.textfield import GTextField
    from docking.widgets.combobox.GComboBox import GComboBox
    from docking.action import DockingAction
    from docking.action import MenuData
    from resources import ResourceManager
    from java.awt import BorderLayout
    from java.awt import GridBagLayout
    from java.awt import GridBagConstraints
    from java.awt import Insets
    from java.awt import Color
    from java.awt import Point
    from java.awt import Dimension
    from java.awt.event import ActionListener
    from java.awt.event import MouseAdapter
    from java.awt.event import MouseEvent
    from java.awt.event import MouseMotionAdapter
    from javax.swing import JButton
    from javax.swing import JLabel
    from javax.swing import JScrollPane
    from javax.swing import JPanel
    from javax.swing import JTabbedPane
    from javax.swing import JOptionPane
    from javax.swing import JFileChooser
    from javax.swing import JPopupMenu
    from javax.swing.table import DefaultTableModel
    from javax.swing.table import TableCellRenderer
    from javax.swing.table import TableCellEditor
    from javax.swing.event import TableModelEvent
    from javax.swing.event import TableModelListener
    from java.io import File
    from java.io import FileReader
    from java.io import FileWriter
    from java.io import IOException
    from java.util import ArrayList
    from java.util import List
    from java.util import Map
    from java.util import HashMap
    from java.util import LinkedHashMap
    from java.util import Collections
    from java.util import Comparator
    from java.util.prefs import Preferences
    from ghidra.framework.main import ToolManager
    from ghidra.framework.plugintool import PluginTool
    from docking.framework import Tool
    from docking.widgets.window import WindowPosition
    from docking.widgets.window import WindowPositionManager
    from docking.widgets.splitpanel import SplitPanel
    from docking.widgets.tabbedpane import GTabbedPane
    from docking.widgets.tree import GTree
    from docking.widgets.tree import GTreeCellRenderer
    from docking.widgets.list.GList import GList
    from docking.widgets.fieldpanel import FieldPanel
    from docking.widgets.label.GLabel import GLabel
    from docking.widgets.textarea.GTextArea import GTextArea
    from docking.widgets.button.GButton import GButton
    from docking.widgets.button.GToggleButton import GToggleButton
    from docking.widgets.button.GRadioButton import GRadioButton
    from docking.widgets.panel.GPanel import GPanel
    from docking.widgets.dialog.GDialog import GDialog
    from docking.widgets.dialog.GFileChooser import GFileChooser
    from docking.widgets.table.GTable import GTable
    from docking.widgets.table.GTableHeader import GTableHeader
    from docking.widgets.table.GTableCellRenderer import GTableCellRenderer
    from docking.widgets.table.GTableCellEditor import GTableCellEditor
    from docking.widgets.table.GTableSelectionModel import GTableSelectionModel
    from docking.widgets.table.GTableColumnModel import GTableColumnModel
    from docking.widgets.table.GTableSortingModel import GTableSortingModel
    from docking.widgets.table.GTableFilterModel import GTableFilterModel
    from docking.widgets.table.GTableDataModel import GTableDataModel
    from docking.widgets.table.GTableWidget import GTableWidget
    from docking.widgets.table.threaded.GThreadedTablePanel import GThreadedTablePanel
    from docking.widgets.table.threaded.GThreadedTableModel import GThreadedTableModel
    from docking.widgets.table.threaded.GThreadedTableWidget import GThreadedTableWidget
    from docking.widgets.table.constraint.ColumnTypeMapper import ColumnTypeMapper
    from docking.widgets.table.constraint.provider.ColumnConstraintProvider import ColumnConstraintProvider
    from docking.widgets.table.constraint.provider.ColumnConstraintProviderManager import ColumnConstraintProviderManager
except Exception as e:
    print(f"导入模块时出错: {e}")

class DraggableComponent(JPanel):
    """
    可拖拽的UI组件
    """
    def __init__(self, title, content_panel):
        """
        初始化可拖拽组件
        
        Args:
            title: 组件标题
            content_panel: 组件内容面板
        """
        super(DraggableComponent, self).__init__()
        self.title = title
        self.content_panel = content_panel
        self.is_dragging = False
        self.drag_offset = Point(0, 0)
        
        # 设置布局
        self.setLayout(BorderLayout())
        
        # 创建标题栏
        title_bar = JPanel()
        title_bar.setBackground(Color.LIGHT_GRAY)
        title_bar.setLayout(BorderLayout())
        
        # 添加标题
        title_label = GLabel(title)
        title_bar.add(title_label, BorderLayout.WEST)
        
        # 添加鼠标监听器用于拖拽
        class DragMouseAdapter(MouseAdapter):
            def __init__(self, parent):
                self.parent = parent
            
            def mousePressed(self, e):
                self.parent.drag_offset.setLocation(e.getX(), e.getY())
                self.parent.is_dragging = True
            
            def mouseReleased(self, e):
                self.parent.is_dragging = False
        
        class DragMouseMotionAdapter(MouseMotionAdapter):
            def __init__(self, parent):
                self.parent = parent
            
            def mouseDragged(self, e):
                if self.parent.is_dragging:
                    container = self.parent.getParent()
                    if container:
                        new_x = container.getX() + (e.getX() - self.parent.drag_offset.x)
                        new_y = container.getY() + (e.getY() - self.parent.drag_offset.y)
                        
                        # 确保组件不会被拖出容器边界
                        if new_x < 0:
                            new_x = 0
                        if new_y < 0:
                            new_y = 0
                        
                        container.setLocation(new_x, new_y)
                        container.revalidate()
                        container.repaint()
        
        title_bar.addMouseListener(DragMouseAdapter(self))
        title_bar.addMouseMotionListener(DragMouseMotionAdapter(self))
        
        # 添加标题栏和内容面板
        self.add(title_bar, BorderLayout.NORTH)
        self.add(content_panel, BorderLayout.CENTER)
        
        # 设置组件大小
        self.setPreferredSize(Dimension(300, 200))

class LayoutManager:
    """
    布局管理器，负责保存和加载布局配置
    """
    def __init__(self, tool):
        """
        初始化布局管理器
        
        Args:
            tool: Ghidra工具实例
        """
        self.tool = tool
        self.layouts = {}
        self.current_layout = "default"
        self.layouts_dir = os.path.join(os.path.expanduser("~"), ".ghidra", "layouts")
        
        # 创建布局保存目录
        if not os.path.exists(self.layouts_dir):
            os.makedirs(self.layouts_dir)
        
        # 加载默认布局
        self.load_default_layout()
    
    def save_layout(self, name):
        """
        保存当前布局
        
        Args:
            name: 布局名称
        """
        try:
            layout_data = {}
            
            # 获取所有组件的位置和大小
            components = self.tool.getComponents()
            for component in components:
                if hasattr(component, "title"):
                    component_data = {
                        "title": component.title,
                        "x": component.getX(),
                        "y": component.getY(),
                        "width": component.getWidth(),
                        "height": component.getHeight()
                    }
                    layout_data[component.title] = component_data
            
            # 保存到文件
            layout_file = os.path.join(self.layouts_dir, f"{name}.json")
            with open(layout_file, "w", encoding="utf-8") as f:
                json.dump(layout_data, f, indent=2, ensure_ascii=False)
            
            # 更新布局字典
            self.layouts[name] = layout_data
            self.current_layout = name
            
            return True
        except Exception as e:
            print(f"保存布局时出错: {e}")
            return False
    
    def load_layout(self, name):
        """
        加载指定布局
        
        Args:
            name: 布局名称
        """
        try:
            # 检查布局是否存在
            if name not in self.layouts:
                # 尝试从文件加载
                layout_file = os.path.join(self.layouts_dir, f"{name}.json")
                if not os.path.exists(layout_file):
                    return False
                
                with open(layout_file, "r", encoding="utf-8") as f:
                    layout_data = json.load(f)
                
                self.layouts[name] = layout_data
            else:
                layout_data = self.layouts[name]
            
            # 应用布局
            components = self.tool.getComponents()
            for component in components:
                if hasattr(component, "title") and component.title in layout_data:
                    component_data = layout_data[component.title]
                    component.setLocation(component_data["x"], component_data["y"])
                    component.setSize(component_data["width"], component_data["height"])
            
            self.current_layout = name
            self.tool.revalidate()
            self.tool.repaint()
            
            return True
        except Exception as e:
            print(f"加载布局时出错: {e}")
            return False
    
    def load_default_layout(self):
        """
        加载默认布局
        """
        default_layout = {
            "Function List": {"x": 10, "y": 10, "width": 300, "height": 400},
            "Symbol Tree": {"x": 320, "y": 10, "width": 250, "height": 400},
            "Disassembly": {"x": 10, "y": 420, "width": 800, "height": 400},
            "Decompiler": {"x": 820, "y": 420, "width": 800, "height": 400}
        }
        
        self.layouts["default"] = default_layout
        self.current_layout = "default"
    
    def get_available_layouts(self):
        """
        获取可用的布局列表
        
        Returns:
            布局名称列表
        """
        layouts = ["default"]
        
        # 扫描布局目录
        if os.path.exists(self.layouts_dir):
            for file in os.listdir(self.layouts_dir):
                if file.endswith(".json"):
                    layout_name = file[:-5]  # 移除.json后缀
                    if layout_name not in layouts:
                        layouts.append(layout_name)
        
        return layouts

class CustomizableUIScript(GhidraScript):
    """
    可自定义UI布局脚本
    """
    def __init__(self):
        """
        初始化脚本
        """
        super(CustomizableUIScript, self).__init__()
        self.layout_manager = None
    
    def run(self):
        """
        运行脚本
        """
        try:
            # 获取当前工具
            tool = self.state.getTool()
            if not tool:
                self.println("无法获取当前工具实例")
                return
            
            # 初始化布局管理器
            self.layout_manager = LayoutManager(tool)
            
            # 创建主对话框
            dialog = CustomizableUIDialog(tool, self.layout_manager)
            dialog.setVisible(True)
            
        except Exception as e:
            self.println(f"运行脚本时出错: {e}")

class CustomizableUIDialog(GDialog):
    """
    可自定义UI布局对话框
    """
    def __init__(self, tool, layout_manager):
        """
        初始化对话框
        
        Args:
            tool: Ghidra工具实例
            layout_manager: 布局管理器实例
        """
        super(CustomizableUIDialog, self).__init__(tool.getWindow(), "自定义UI布局", True)
        self.tool = tool
        self.layout_manager = layout_manager
        
        # 设置对话框大小
        self.setSize(600, 400)
        
        # 创建主面板
        main_panel = GPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建布局管理面板
        layout_panel = self.create_layout_panel()
        main_panel.add(layout_panel, BorderLayout.CENTER)
        
        # 创建按钮面板
        button_panel = self.create_button_panel()
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        # 设置内容面板
        self.setContent(main_panel)
        
        # 居中显示
        self.setLocationRelativeTo(tool.getWindow())
    
    def create_layout_panel(self):
        """
        创建布局管理面板
        
        Returns:
            布局管理面板
        """
        panel = GPanel()
        panel.setLayout(GridBagLayout())
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # 布局列表
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0.3
        panel.add(GLabel("可用布局:"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 0
        gbc.weightx = 0.7
        self.layout_list = GComboBox()
        self.update_layout_list()
        panel.add(self.layout_list, gbc)
        
        # 布局名称输入
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.weightx = 0.3
        panel.add(GLabel("新布局名称:"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 1
        gbc.weightx = 0.7
        self.layout_name_field = GTextField(20)
        panel.add(self.layout_name_field, gbc)
        
        # 布局操作按钮
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        
        button_panel = JPanel()
        
        def on_load_layout(e):
            selected_layout = str(self.layout_list.getSelectedItem())
            if selected_layout:
                success = self.layout_manager.load_layout(selected_layout)
                if success:
                    JOptionPane.showMessageDialog(self, f"成功加载布局: {selected_layout}", "成功", JOptionPane.INFORMATION_MESSAGE)
                else:
                    JOptionPane.showMessageDialog(self, f"加载布局失败: {selected_layout}", "错误", JOptionPane.ERROR_MESSAGE)
        
        load_button = GButton("加载布局")
        load_button.addActionListener(on_load_layout)
        button_panel.add(load_button)
        
        def on_save_layout(e):
            layout_name = self.layout_name_field.getText().strip()
            if not layout_name:
                JOptionPane.showMessageDialog(self, "请输入布局名称", "错误", JOptionPane.ERROR_MESSAGE)
                return
            
            success = self.layout_manager.save_layout(layout_name)
            if success:
                JOptionPane.showMessageDialog(self, f"成功保存布局: {layout_name}", "成功", JOptionPane.INFORMATION_MESSAGE)
                self.update_layout_list()
            else:
                JOptionPane.showMessageDialog(self, f"保存布局失败: {layout_name}", "错误", JOptionPane.ERROR_MESSAGE)
        
        save_button = GButton("保存布局")
        save_button.addActionListener(on_save_layout)
        button_panel.add(save_button)
        
        def on_delete_layout(e):
            selected_layout = str(self.layout_list.getSelectedItem())
            if selected_layout == "default":
                JOptionPane.showMessageDialog(self, "默认布局不能删除", "错误", JOptionPane.ERROR_MESSAGE)
                return
            
            if selected_layout:
                # 确认删除
                option = JOptionPane.showConfirmDialog(self, f"确定要删除布局 '{selected_layout}' 吗?", "确认删除", JOptionPane.YES_NO_OPTION)
                if option == JOptionPane.YES_OPTION:
                    # 删除布局文件
                    layout_file = os.path.join(self.layout_manager.layouts_dir, f"{selected_layout}.json")
                    if os.path.exists(layout_file):
                        os.remove(layout_file)
                    
                    # 从布局字典中移除
                    if selected_layout in self.layout_manager.layouts:
                        del self.layout_manager.layouts[selected_layout]
                    
                    # 重新加载布局列表
                    self.update_layout_list()
                    JOptionPane.showMessageDialog(self, f"成功删除布局: {selected_layout}", "成功", JOptionPane.INFORMATION_MESSAGE)
        
        delete_button = GButton("删除布局")
        delete_button.addActionListener(on_delete_layout)
        button_panel.add(delete_button)
        
        panel.add(button_panel, gbc)
        
        return panel
    
    def create_button_panel(self):
        """
        创建按钮面板
        
        Returns:
            按钮面板
        """
        panel = JPanel()
        
        def on_close(e):
            self.dispose()
        
        close_button = GButton("关闭")
        close_button.addActionListener(on_close)
        panel.add(close_button)
        
        return panel
    
    def update_layout_list(self):
        """
        更新布局列表
        """
        # 清空列表
        self.layout_list.removeAllItems()
        
        # 添加可用布局
        layouts = self.layout_manager.get_available_layouts()
        for layout in layouts:
            self.layout_list.addItem(layout)
        
        # 选择当前布局
        current_layout = self.layout_manager.current_layout
        if current_layout:
            for i in range(self.layout_list.getItemCount()):
                if self.layout_list.getItemAt(i) == current_layout:
                    self.layout_list.setSelectedIndex(i)
                    break

class ComponentPalette(GPanel):
    """
    组件调色板，用于添加新的UI组件
    """
    def __init__(self, tool):
        """
        初始化组件调色板
        
        Args:
            tool: Ghidra工具实例
        """
        super(ComponentPalette, self).__init__()
        self.tool = tool
        
        # 设置布局
        self.setLayout(BorderLayout())
        
        # 添加标题
        title_label = GLabel("组件调色板")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        self.add(title_label, BorderLayout.NORTH)
        
        # 创建组件列表
        component_list = JPanel()
        component_list.setLayout(GridBagLayout())
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        
        # 添加常用组件按钮
        components = [
            ("函数列表", self.add_function_list),
            ("符号树", self.add_symbol_tree),
            ("反汇编视图", self.add_disassembly_view),
            ("反编译视图", self.add_decompiler_view),
            ("内存视图", self.add_memory_view),
            ("寄存器视图", self.add_register_view),
            ("导入表", self.add_imports_view),
            ("导出表", self.add_exports_view)
        ]
        
        for i, (name, callback) in enumerate(components):
            gbc.gridx = 0
            gbc.gridy = i
            def on_click(e):
                callback()
            
            button = GButton(name)
            button.addActionListener(on_click)
            component_list.add(button, gbc)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(component_list)
        self.add(scroll_pane, BorderLayout.CENTER)
        
        # 设置大小
        self.setPreferredSize(Dimension(200, 400))
    
    def add_function_list(self):
        """
        添加函数列表组件
        """
        # 这里实现添加函数列表的逻辑
        pass
    
    def add_symbol_tree(self):
        """
        添加符号树组件
        """
        # 这里实现添加符号树的逻辑
        pass
    
    def add_disassembly_view(self):
        """
        添加反汇编视图组件
        """
        # 这里实现添加反汇编视图的逻辑
        pass
    
    def add_decompiler_view(self):
        """
        添加反编译视图组件
        """
        # 这里实现添加反编译视图的逻辑
        pass
    
    def add_memory_view(self):
        """
        添加内存视图组件
        """
        # 这里实现添加内存视图的逻辑
        pass
    
    def add_register_view(self):
        """
        添加寄存器视图组件
        """
        # 这里实现添加寄存器视图的逻辑
        pass
    
    def add_imports_view(self):
        """
        添加导入表组件
        """
        # 这里实现添加导入表的逻辑
        pass
    
    def add_exports_view(self):
        """
        添加导出表组件
        """
        # 这里实现添加导出表的逻辑
        pass

# 主入口
if __name__ == "__main__":
    script = CustomizableUIScript()
    script.run()
