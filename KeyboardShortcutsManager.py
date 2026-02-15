#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KeyboardShortcutsManager.py

自定义键盘快捷键管理工具，支持快捷键配置、冲突检测和导出导入功能。

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
    from java.awt.event import KeyEvent
    from java.awt.event import KeyAdapter
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

class ShortcutManager:
    """
    快捷键管理器，负责管理和配置键盘快捷键
    """
    def __init__(self, tool):
        """
        初始化快捷键管理器
        
        Args:
            tool: Ghidra工具实例
        """
        self.tool = tool
        self.shortcuts = {}
        self.default_shortcuts = {}
        self.shortcuts_dir = os.path.join(os.path.expanduser("~"), ".ghidra", "shortcuts")
        
        # 创建快捷键保存目录
        if not os.path.exists(self.shortcuts_dir):
            os.makedirs(self.shortcuts_dir)
        
        # 加载默认快捷键
        self.load_default_shortcuts()
        
        # 加载用户自定义快捷键
        self.load_user_shortcuts()
    
    def load_default_shortcuts(self):
        """
        加载默认快捷键配置
        """
        # 默认快捷键配置
        self.default_shortcuts = {
            # 常用操作
            "复制": "Ctrl+C",
            "粘贴": "Ctrl+V",
            "剪切": "Ctrl+X",
            "撤销": "Ctrl+Z",
            "重做": "Ctrl+Y",
            "查找": "Ctrl+F",
            "替换": "Ctrl+H",
            "全选": "Ctrl+A",
            
            # 视图操作
            "切换反汇编/反编译视图": "Ctrl+D",
            "放大": "Ctrl++",
            "缩小": "Ctrl+-",
            "重置缩放": "Ctrl+0",
            "刷新视图": "F5",
            
            # 分析操作
            "启动分析": "Ctrl+Shift+A",
            "函数图": "F12",
            "交叉引用": "Ctrl+X",
            "重命名": "L",
            "注释": ";",
            "设置类型": "Y",
            
            # 导航操作
            "上一个位置": "Alt+Left",
            "下一个位置": "Alt+Right",
            "转到地址": "G",
            "转到函数": "Ctrl+G",
            "转到主函数": "Ctrl+Shift+G",
            
            # 工具操作
            "打开文件": "Ctrl+O",
            "保存项目": "Ctrl+S",
            "关闭文件": "Ctrl+W",
            "退出": "Ctrl+Q"
        }
        
        # 初始化当前快捷键为默认快捷键
        self.shortcuts.update(self.default_shortcuts)
    
    def load_user_shortcuts(self):
        """
        加载用户自定义快捷键
        """
        try:
            shortcuts_file = os.path.join(self.shortcuts_dir, "shortcuts.json")
            if os.path.exists(shortcuts_file):
                with open(shortcuts_file, "r", encoding="utf-8") as f:
                    user_shortcuts = json.load(f)
                
                # 更新快捷键
                self.shortcuts.update(user_shortcuts)
        except Exception as e:
            print(f"加载用户快捷键时出错: {e}")
    
    def save_shortcuts(self):
        """
        保存用户自定义快捷键
        """
        try:
            # 只保存与默认快捷键不同的配置
            user_shortcuts = {}
            for action, shortcut in self.shortcuts.items():
                if action not in self.default_shortcuts or shortcut != self.default_shortcuts[action]:
                    user_shortcuts[action] = shortcut
            
            # 保存到文件
            shortcuts_file = os.path.join(self.shortcuts_dir, "shortcuts.json")
            with open(shortcuts_file, "w", encoding="utf-8") as f:
                json.dump(user_shortcuts, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print(f"保存快捷键时出错: {e}")
            return False
    
    def reset_to_defaults(self):
        """
        重置所有快捷键为默认值
        """
        self.shortcuts.clear()
        self.shortcuts.update(self.default_shortcuts)
        return self.save_shortcuts()
    
    def set_shortcut(self, action, shortcut):
        """
        设置快捷键
        
        Args:
            action: 操作名称
            shortcut: 快捷键字符串
        """
        self.shortcuts[action] = shortcut
    
    def get_shortcut(self, action):
        """
        获取操作的快捷键
        
        Args:
            action: 操作名称
        
        Returns:
            快捷键字符串
        """
        return self.shortcuts.get(action, "")
    
    def get_all_shortcuts(self):
        """
        获取所有快捷键
        
        Returns:
            快捷键字典
        """
        return self.shortcuts.copy()
    
    def check_conflicts(self, new_shortcut, exclude_action=None):
        """
        检查快捷键冲突
        
        Args:
            new_shortcut: 新快捷键
            exclude_action: 排除的操作（通常是当前正在编辑的操作）
        
        Returns:
            冲突的操作列表
        """
        conflicts = []
        for action, shortcut in self.shortcuts.items():
            if action != exclude_action and shortcut == new_shortcut:
                conflicts.append(action)
        return conflicts
    
    def import_shortcuts(self, file_path):
        """
        导入快捷键配置
        
        Args:
            file_path: 配置文件路径
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                imported_shortcuts = json.load(f)
            
            # 更新快捷键
            self.shortcuts.update(imported_shortcuts)
            
            # 保存更新后的配置
            return self.save_shortcuts()
        except Exception as e:
            print(f"导入快捷键时出错: {e}")
            return False
    
    def export_shortcuts(self, file_path):
        """
        导出快捷键配置
        
        Args:
            file_path: 导出文件路径
        """
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(self.shortcuts, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"导出快捷键时出错: {e}")
            return False

class ShortcutTableModel(DefaultTableModel):
    """
    快捷键表格模型
    """
    def __init__(self, shortcuts):
        """
        初始化表格模型
        
        Args:
            shortcuts: 快捷键字典
        """
        super(ShortcutTableModel, self).__init__()
        
        # 设置列名
        self.setColumnIdentifiers(["操作", "当前快捷键", "默认快捷键"])
        
        # 添加数据行
        for action, shortcut in shortcuts.items():
            default_shortcut = ""
            # 这里需要获取默认快捷键，暂时留空
            self.addRow([action, shortcut, default_shortcut])
    
    def isCellEditable(self, row, column):
        """
        只允许编辑快捷键列
        
        Args:
            row: 行索引
            column: 列索引
        
        Returns:
            是否可编辑
        """
        return column == 1  # 只允许编辑当前快捷键列

class ShortcutEditorPanel(GPanel):
    """
    快捷键编辑器面板
    """
    def __init__(self, shortcut_manager):
        """
        初始化快捷键编辑器面板
        
        Args:
            shortcut_manager: 快捷键管理器实例
        """
        super(ShortcutEditorPanel, self).__init__()
        self.shortcut_manager = shortcut_manager
        self.current_action = None
        
        # 设置布局
        self.setLayout(BorderLayout())
        
        # 添加标题
        title_label = GLabel("快捷键编辑器")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        self.add(title_label, BorderLayout.NORTH)
        
        # 创建编辑器内容
        editor_content = JPanel()
        editor_content.setLayout(GridBagLayout())
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # 操作名称
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.weightx = 0.3
        editor_content.add(GLabel("操作:"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 0
        gbc.weightx = 0.7
        self.action_label = GLabel("")
        editor_content.add(self.action_label, gbc)
        
        # 当前快捷键
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.weightx = 0.3
        editor_content.add(GLabel("当前快捷键:"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 1
        gbc.weightx = 0.7
        self.current_shortcut_label = GLabel("")
        editor_content.add(self.current_shortcut_label, gbc)
        
        # 新快捷键
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.weightx = 0.3
        editor_content.add(GLabel("新快捷键:"), gbc)
        
        gbc.gridx = 1
        gbc.gridy = 2
        gbc.weightx = 0.7
        self.new_shortcut_field = GTextField(20)
        self.new_shortcut_field.setEditable(False)
        
        class ShortcutKeyAdapter(KeyAdapter):
            def __init__(self, parent):
                self.parent = parent
            
            def keyPressed(self, e):
                self.parent.capture_shortcut(e)
        
        self.new_shortcut_field.addKeyListener(ShortcutKeyAdapter(self))
        editor_content.add(self.new_shortcut_field, gbc)
        
        # 提示信息
        gbc.gridx = 0
        gbc.gridy = 3
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        tip_label = GLabel("提示: 按下要设置的快捷键组合，按Esc取消")
        tip_label.setForeground(Color.GRAY)
        editor_content.add(tip_label, gbc)
        
        # 按钮
        gbc.gridx = 0
        gbc.gridy = 4
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        
        button_panel = JPanel()
        
        def on_apply(e):
            self.apply_shortcut()
        
        apply_button = GButton("应用")
        apply_button.addActionListener(on_apply)
        button_panel.add(apply_button)
        
        def on_cancel(e):
            self.reset_editor()
        
        cancel_button = GButton("取消")
        cancel_button.addActionListener(on_cancel)
        button_panel.add(cancel_button)
        
        def on_reset(e):
            self.reset_to_default()
        
        reset_button = GButton("重置为默认")
        reset_button.addActionListener(on_reset)
        button_panel.add(reset_button)
        
        editor_content.add(button_panel, gbc)
        
        self.add(editor_content, BorderLayout.CENTER)
    
    def set_action(self, action):
        """
        设置当前编辑的操作
        
        Args:
            action: 操作名称
        """
        self.current_action = action
        self.action_label.setText(action)
        
        # 获取当前快捷键
        current_shortcut = self.shortcut_manager.get_shortcut(action)
        self.current_shortcut_label.setText(current_shortcut)
        
        # 清空新快捷键输入框
        self.new_shortcut_field.setText("")
    
    def capture_shortcut(self, e):
        """
        捕获用户按下的快捷键
        
        Args:
            e: 键盘事件
        """
        # 取消事件，避免触发其他操作
        e.consume()
        
        # 检查是否按下了Esc键
        if e.getKeyCode() == KeyEvent.VK_ESCAPE:
            self.new_shortcut_field.setText("")
            return
        
        # 构建快捷键字符串
        modifiers = []
        
        if e.isControlDown():
            modifiers.append("Ctrl")
        if e.isAltDown():
            modifiers.append("Alt")
        if e.isShiftDown():
            modifiers.append("Shift")
        if e.isMetaDown():
            modifiers.append("Meta")
        
        # 获取按键名称
        key_name = KeyEvent.getKeyText(e.getKeyCode())
        
        # 构建完整的快捷键字符串
        if modifiers:
            shortcut = "+".join(modifiers) + "+" + key_name
        else:
            shortcut = key_name
        
        # 更新输入框
        self.new_shortcut_field.setText(shortcut)
    
    def apply_shortcut(self):
        """
        应用新的快捷键
        """
        if not self.current_action:
            return
        
        new_shortcut = self.new_shortcut_field.getText().strip()
        if not new_shortcut:
            JOptionPane.showMessageDialog(self, "请输入有效的快捷键", "错误", JOptionPane.ERROR_MESSAGE)
            return
        
        # 检查冲突
        conflicts = self.shortcut_manager.check_conflicts(new_shortcut, self.current_action)
        if conflicts:
            conflict_str = ", ".join(conflicts)
            option = JOptionPane.showConfirmDialog(
                self, 
                f"快捷键 '{new_shortcut}' 与以下操作冲突: {conflict_str}\n是否继续?", 
                "快捷键冲突", 
                JOptionPane.YES_NO_OPTION
            )
            if option != JOptionPane.YES_OPTION:
                return
        
        # 设置新快捷键
        self.shortcut_manager.set_shortcut(self.current_action, new_shortcut)
        
        # 更新当前快捷键显示
        self.current_shortcut_label.setText(new_shortcut)
        
        # 保存配置
        self.shortcut_manager.save_shortcuts()
        
        JOptionPane.showMessageDialog(self, "快捷键设置成功", "成功", JOptionPane.INFORMATION_MESSAGE)
    
    def reset_editor(self):
        """
        重置编辑器
        """
        self.current_action = None
        self.action_label.setText("")
        self.current_shortcut_label.setText("")
        self.new_shortcut_field.setText("")
    
    def reset_to_default(self):
        """
        重置为默认快捷键
        """
        if not self.current_action:
            return
        
        # 获取默认快捷键
        default_shortcut = self.shortcut_manager.default_shortcuts.get(self.current_action, "")
        
        # 检查冲突
        conflicts = self.shortcut_manager.check_conflicts(default_shortcut, self.current_action)
        if conflicts:
            conflict_str = ", ".join(conflicts)
            option = JOptionPane.showConfirmDialog(
                self, 
                f"默认快捷键 '{default_shortcut}' 与以下操作冲突: {conflict_str}\n是否继续?", 
                "快捷键冲突", 
                JOptionPane.YES_NO_OPTION
            )
            if option != JOptionPane.YES_OPTION:
                return
        
        # 设置默认快捷键
        self.shortcut_manager.set_shortcut(self.current_action, default_shortcut)
        
        # 更新显示
        self.current_shortcut_label.setText(default_shortcut)
        self.new_shortcut_field.setText("")
        
        # 保存配置
        self.shortcut_manager.save_shortcuts()
        
        JOptionPane.showMessageDialog(self, "已重置为默认快捷键", "成功", JOptionPane.INFORMATION_MESSAGE)

class KeyboardShortcutsManagerDialog(GDialog):
    """
    键盘快捷键管理对话框
    """
    def __init__(self, tool, shortcut_manager):
        """
        初始化键盘快捷键管理对话框
        
        Args:
            tool: Ghidra工具实例
            shortcut_manager: 快捷键管理器实例
        """
        super(KeyboardShortcutsManagerDialog, self).__init__(tool.getWindow(), "键盘快捷键管理", True)
        self.tool = tool
        self.shortcut_manager = shortcut_manager
        
        # 设置对话框大小
        self.setSize(800, 600)
        
        # 创建主面板
        main_panel = GPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建标签页
        tabbed_pane = GTabbedPane()
        
        # 添加快捷键列表标签页
        self.shortcut_list_panel = self.create_shortcut_list_panel()
        tabbed_pane.addTab("快捷键列表", self.shortcut_list_panel)
        
        # 添加快捷键编辑器标签页
        self.shortcut_editor = ShortcutEditorPanel(shortcut_manager)
        tabbed_pane.addTab("快捷键编辑", self.shortcut_editor)
        
        # 添加导入/导出标签页
        self.import_export_panel = self.create_import_export_panel()
        tabbed_pane.addTab("导入/导出", self.import_export_panel)
        
        main_panel.add(tabbed_pane, BorderLayout.CENTER)
        
        # 创建按钮面板
        button_panel = self.create_button_panel()
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        # 设置内容面板
        self.setContent(main_panel)
        
        # 居中显示
        self.setLocationRelativeTo(tool.getWindow())
    
    def create_shortcut_list_panel(self):
        """
        创建快捷键列表面板
        
        Returns:
            快捷键列表面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 添加搜索框
        search_panel = JPanel()
        search_panel.setLayout(BorderLayout())
        
        search_label = GLabel("搜索:")
        search_panel.add(search_label, BorderLayout.WEST)
        
        self.search_field = GTextField(20)
        search_panel.add(self.search_field, BorderLayout.CENTER)
        
        panel.add(search_panel, BorderLayout.NORTH)
        
        # 创建快捷键表格
        shortcuts = self.shortcut_manager.get_all_shortcuts()
        
        # 创建表格模型
        data = []
        for action, shortcut in sorted(shortcuts.items()):
            default_shortcut = self.shortcut_manager.default_shortcuts.get(action, "")
            data.append([action, shortcut, default_shortcut])
        
        column_names = ["操作", "当前快捷键", "默认快捷键"]
        
        # 创建表格
        self.shortcut_table = GTable(data, column_names)
        
        class ShortcutListSelectionListener(ListSelectionListener):
            def __init__(self, parent):
                self.parent = parent
            
            def valueChanged(self, e):
                if not e.getValueIsAdjusting():
                    selected_row = self.parent.shortcut_table.getSelectedRow()
                    if selected_row >= 0:
                        action = str(self.parent.shortcut_table.getValueAt(selected_row, 0))
                        self.parent.shortcut_editor.set_action(action)
        
        self.shortcut_table.getSelectionModel().addListSelectionListener(ShortcutListSelectionListener(self))
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.shortcut_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_import_export_panel(self):
        """
        创建导入/导出面板
        
        Returns:
            导入/导出面板
        """
        panel = GPanel()
        panel.setLayout(GridBagLayout())
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        
        # 导入按钮
        gbc.gridx = 0
        gbc.gridy = 0
        def on_import(e):
            self.import_shortcuts()
        
        import_button = GButton("导入快捷键配置")
        import_button.addActionListener(on_import)
        panel.add(import_button, gbc)
        
        # 导出按钮
        gbc.gridx = 0
        gbc.gridy = 1
        
        def on_export(e):
            self.export_shortcuts()
        
        export_button = GButton("导出快捷键配置")
        export_button.addActionListener(on_export)
        panel.add(export_button, gbc)
        
        # 重置为默认按钮
        gbc.gridx = 0
        gbc.gridy = 2
        
        def on_reset_all(e):
            self.reset_all_shortcuts()
        
        reset_button = GButton("重置所有快捷键为默认值")
        reset_button.addActionListener(on_reset_all)
        panel.add(reset_button, gbc)
        
        return panel
    
    def create_button_panel(self):
        """
        创建按钮面板
        
        Returns:
            按钮面板
        """
        panel = JPanel()
        
        def on_ok(e):
            self.dispose()
        
        ok_button = GButton("确定")
        ok_button.addActionListener(on_ok)
        panel.add(ok_button)
        
        return panel
    
    def import_shortcuts(self):
        """
        导入快捷键配置
        """
        class JSONFileFilter(FileFilter):
            def accept(self, f):
                return f.isDirectory() or f.getName().endswith(".json")
            
            def getDescription(self):
                return "JSON文件 (*.json)"
        
        file_chooser = GFileChooser()
        file_chooser.setDialogTitle("选择快捷键配置文件")
        file_chooser.setFileFilter(JSONFileFilter())
        
        result = file_chooser.showOpenDialog(self)
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            
            success = self.shortcut_manager.import_shortcuts(file_path)
            if success:
                JOptionPane.showMessageDialog(self, "成功导入快捷键配置", "成功", JOptionPane.INFORMATION_MESSAGE)
                # 刷新表格
                self.refresh_shortcut_table()
            else:
                JOptionPane.showMessageDialog(self, "导入快捷键配置失败", "错误", JOptionPane.ERROR_MESSAGE)
    
    def export_shortcuts(self):
        """
        导出快捷键配置
        """
        class JSONFileFilter(FileFilter):
            def accept(self, f):
                return f.isDirectory() or f.getName().endswith(".json")
            
            def getDescription(self):
                return "JSON文件 (*.json)"
        
        file_chooser = GFileChooser()
        file_chooser.setDialogTitle("保存快捷键配置文件")
        file_chooser.setFileFilter(JSONFileFilter())
        
        # 设置默认文件名
        default_file = File(file_chooser.getCurrentDirectory(), "shortcuts.json")
        file_chooser.setSelectedFile(default_file)
        
        result = file_chooser.showSaveDialog(self)
        if result == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            file_path = selected_file.getAbsolutePath()
            
            # 确保文件扩展名为.json
            if not file_path.endswith(".json"):
                file_path += ".json"
            
            success = self.shortcut_manager.export_shortcuts(file_path)
            if success:
                JOptionPane.showMessageDialog(self, f"成功导出快捷键配置到: {file_path}", "成功", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self, "导出快捷键配置失败", "错误", JOptionPane.ERROR_MESSAGE)
    
    def reset_all_shortcuts(self):
        """
        重置所有快捷键为默认值
        """
        option = JOptionPane.showConfirmDialog(
            self, 
            "确定要重置所有快捷键为默认值吗?", 
            "确认重置", 
            JOptionPane.YES_NO_OPTION
        )
        
        if option == JOptionPane.YES_OPTION:
            success = self.shortcut_manager.reset_to_defaults()
            if success:
                JOptionPane.showMessageDialog(self, "已重置所有快捷键为默认值", "成功", JOptionPane.INFORMATION_MESSAGE)
                # 刷新表格
                self.refresh_shortcut_table()
                # 重置编辑器
                self.shortcut_editor.reset_editor()
            else:
                JOptionPane.showMessageDialog(self, "重置快捷键失败", "错误", JOptionPane.ERROR_MESSAGE)
    
    def refresh_shortcut_table(self):
        """
        刷新快捷键表格
        """
        # 清除现有数据
        self.shortcut_table.setModel(DefaultTableModel([], ["操作", "当前快捷键", "默认快捷键"]))
        
        # 添加新数据
        shortcuts = self.shortcut_manager.get_all_shortcuts()
        model = self.shortcut_table.getModel()
        
        for action, shortcut in sorted(shortcuts.items()):
            default_shortcut = self.shortcut_manager.default_shortcuts.get(action, "")
            model.addRow([action, shortcut, default_shortcut])

class KeyboardShortcutsManagerScript(GhidraScript):
    """
    键盘快捷键管理脚本
    """
    def __init__(self):
        """
        初始化脚本
        """
        super(KeyboardShortcutsManagerScript, self).__init__()
        self.shortcut_manager = None
    
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
            
            # 初始化快捷键管理器
            self.shortcut_manager = ShortcutManager(tool)
            
            # 创建主对话框
            dialog = KeyboardShortcutsManagerDialog(tool, self.shortcut_manager)
            dialog.setVisible(True)
            
        except Exception as e:
            self.println(f"运行脚本时出错: {e}")

# 主入口
if __name__ == "__main__":
    script = KeyboardShortcutsManagerScript()
    script.run()
