#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PluginManager.py

管理和加载自定义插件的工具，支持插件的发现、加载、启用/禁用、配置管理等功能。

作者: Ghidra开发者
日期: 2023-10-01
版本: 1.0.0
"""

import os
import sys
import importlib
import importlib.util
import json
import threading
import time
from datetime import datetime

# Ghidra模块导入
try:
    from ghidra.framework.model import ToolPlugin
    from ghidra.framework.plugintool import PluginTool
    from ghidra.util.task import Task, TaskMonitor
    from ghidra.app.script import GhidraScript
    from docking.widgets.dialogs import GenericDialog
    from docking.widgets.table import GTable
    from docking.widgets.table import TableColumnDescriptor
    from docking.widgets.table import TableSortingContext
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
    from java.awt.event import ActionListener
    from java.awt.event import MouseAdapter
    from java.awt.event import MouseEvent
    from javax.swing import JButton
    from javax.swing import JLabel
    from javax.swing import JScrollPane
    from javax.swing import JPanel
    from javax.swing import JMenuBar
    from javax.swing import JMenu
    from javax.swing import JMenuItem
    from javax.swing import JOptionPane
    from javax.swing.table import DefaultTableModel
    from javax.swing.table import TableCellRenderer
    from javax.swing.table import TableCellEditor
    from javax.swing.event import TableModelEvent
    from javax.swing.event import TableModelListener
    from java.io import File
    from java.io import FileReader
    from java.io import FileWriter
    from java.io import IOException
    from java.net import URL
    from java.net import URLClassLoader
except ImportError as e:
    print(f"导入Ghidra模块失败: {e}")
    sys.exit(1)

class PluginInfo:
    """插件信息类"""
    def __init__(self, name, path, description="", author="", version="1.0", enabled=True, loaded=False, error=None):
        self.name = name
        self.path = path
        self.description = description
        self.author = author
        self.version = version
        self.enabled = enabled
        self.loaded = loaded
        self.error = error
        self.last_loaded = None
        self.instance = None

    def to_dict(self):
        """转换为字典格式"""
        return {
            "name": self.name,
            "path": self.path,
            "description": self.description,
            "author": self.author,
            "version": self.version,
            "enabled": self.enabled
        }

    @staticmethod
    def from_dict(data):
        """从字典创建PluginInfo对象"""
        return PluginInfo(
            name=data.get("name", ""),
            path=data.get("path", ""),
            description=data.get("description", ""),
            author=data.get("author", ""),
            version=data.get("version", "1.0"),
            enabled=data.get("enabled", True)
        )

class PluginManagerTableModel(DefaultTableModel):
    """插件管理表格模型"""
    def __init__(self, plugin_infos):
        column_names = ["启用", "名称", "描述", "作者", "版本", "状态", "路径"]
        data = []
        for info in plugin_infos:
            status = "已加载" if info.loaded else ("错误" if info.error else "未加载")
            data.append([info.enabled, info.name, info.description, info.author, info.version, status, info.path])
        super(PluginManagerTableModel, self).__init__(data, column_names)
        self.plugin_infos = plugin_infos

    def isCellEditable(self, row, column):
        """只有第一列（启用）是可编辑的"""
        return column == 0

    def getColumnClass(self, columnIndex):
        """返回列的类型"""
        if columnIndex == 0:
            return bool
        return str

    def setValueAt(self, value, row, column):
        """设置单元格值"""
        if column == 0:
            self.plugin_infos[row].enabled = value
            self.dataVector.elementAt(row).setElementAt(value, column)
            self.fireTableCellUpdated(row, column)

class PluginManager(GhidraScript):
    """插件管理工具"""

    def __init__(self):
        super(PluginManager, self).__init__()
        self.plugin_infos = []
        self.plugin_paths = []
        self.config_file = os.path.join(os.path.expanduser("~"), ".ghidra", "plugin_manager_config.json")
        self.init_plugin_paths()

    def init_plugin_paths(self):
        """初始化插件路径"""
        # 默认插件路径
        default_paths = [
            os.path.join(os.path.expanduser("~"), ".ghidra", "plugins"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "plugins")
        ]
        
        for path in default_paths:
            if os.path.exists(path) and path not in self.plugin_paths:
                self.plugin_paths.append(path)

    def run(self):
        """运行脚本"""
        try:
            self.load_config()
            self.discover_plugins()
            self.show_dialog()
        except Exception as e:
            self.log_error(f"运行插件管理器时出错: {e}")

    def discover_plugins(self):
        """发现插件"""
        discovered_plugins = []
        
        # 遍历插件路径
        for plugin_path in self.plugin_paths:
            if not os.path.exists(plugin_path):
                continue
            
            for root, dirs, files in os.walk(plugin_path):
                for file in files:
                    if file.endswith(".py"):
                        plugin_file = os.path.join(root, file)
                        plugin_info = self.analyze_plugin(plugin_file)
                        if plugin_info:
                            # 检查是否已存在
                            existing = next((p for p in self.plugin_infos if p.path == plugin_info.path), None)
                            if existing:
                                # 更新现有插件信息
                                existing.name = plugin_info.name
                                existing.description = plugin_info.description
                                existing.author = plugin_info.author
                                existing.version = plugin_info.version
                                discovered_plugins.append(existing)
                            else:
                                discovered_plugins.append(plugin_info)
        
        # 添加配置中的插件（可能不在当前路径中）
        for existing_info in self.plugin_infos:
            if not any(p.path == existing_info.path for p in discovered_plugins):
                discovered_plugins.append(existing_info)
        
        self.plugin_infos = discovered_plugins

    def analyze_plugin(self, plugin_file):
        """分析插件文件，提取插件信息"""
        try:
            with open(plugin_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 提取插件信息
            name = os.path.basename(plugin_file)[:-3]  # 移除.py扩展名
            description = ""
            author = ""
            version = "1.0"
            
            # 简单的信息提取
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('# description:'):
                    description = line.split(':', 1)[1].strip()
                elif line.startswith('# author:'):
                    author = line.split(':', 1)[1].strip()
                elif line.startswith('# version:'):
                    version = line.split(':', 1)[1].strip()
            
            return PluginInfo(name, plugin_file, description, author, version)
        except Exception as e:
            self.log_error(f"分析插件 {plugin_file} 时出错: {e}")
            return None

    def load_config(self):
        """加载配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 加载插件信息
                if "plugins" in config:
                    self.plugin_infos = [PluginInfo.from_dict(plugin_data) for plugin_data in config["plugins"]]
                
                # 加载插件路径
                if "plugin_paths" in config:
                    for path in config["plugin_paths"]:
                        if os.path.exists(path) and path not in self.plugin_paths:
                            self.plugin_paths.append(path)
        except Exception as e:
            self.log_error(f"加载配置时出错: {e}")

    def save_config(self):
        """保存配置"""
        try:
            config = {
                "plugins": [info.to_dict() for info in self.plugin_infos],
                "plugin_paths": self.plugin_paths
            }
            
            # 确保配置目录存在
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log_error(f"保存配置时出错: {e}")

    def load_plugin(self, plugin_info):
        """加载插件"""
        try:
            if not plugin_info.enabled:
                return False
            
            # 添加插件目录到Python路径
            plugin_dir = os.path.dirname(plugin_info.path)
            if plugin_dir not in sys.path:
                sys.path.insert(0, plugin_dir)
            
            # 导入插件模块
            module_name = os.path.basename(plugin_info.path)[:-3]
            spec = importlib.util.spec_from_file_location(module_name, plugin_info.path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # 查找插件类
            plugin_class = None
            for name, obj in module.__dict__.items():
                if hasattr(obj, '__class__') and hasattr(obj, 'run'):
                    plugin_class = obj
                    break
            
            if plugin_class:
                plugin_info.instance = plugin_class
                plugin_info.loaded = True
                plugin_info.error = None
                plugin_info.last_loaded = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return True
            else:
                plugin_info.error = "未找到可执行的插件类"
                plugin_info.loaded = False
                return False
        except Exception as e:
            plugin_info.error = str(e)
            plugin_info.loaded = False
            self.log_error(f"加载插件 {plugin_info.name} 时出错: {e}")
            return False

    def unload_plugin(self, plugin_info):
        """卸载插件"""
        try:
            plugin_info.instance = None
            plugin_info.loaded = False
            plugin_info.last_loaded = None
            return True
        except Exception as e:
            self.log_error(f"卸载插件 {plugin_info.name} 时出错: {e}")
            return False

    def reload_plugin(self, plugin_info):
        """重新加载插件"""
        self.unload_plugin(plugin_info)
        return self.load_plugin(plugin_info)

    def run_plugin(self, plugin_info):
        """运行插件"""
        try:
            if not plugin_info.loaded:
                if not self.load_plugin(plugin_info):
                    return False
            
            if plugin_info.instance:
                # 在新线程中运行插件
                def run_plugin_thread():
                    try:
                        plugin_info.instance.run()
                    except Exception as e:
                        self.log_error(f"运行插件 {plugin_info.name} 时出错: {e}")
                
                thread = threading.Thread(target=run_plugin_thread)
                thread.daemon = True
                thread.start()
                return True
            return False
        except Exception as e:
            self.log_error(f"运行插件 {plugin_info.name} 时出错: {e}")
            return False

    def add_plugin_path(self, path):
        """添加插件路径"""
        if os.path.exists(path) and path not in self.plugin_paths:
            self.plugin_paths.append(path)
            return True
        return False

    def remove_plugin_path(self, path):
        """移除插件路径"""
        if path in self.plugin_paths:
            self.plugin_paths.remove(path)
            return True
        return False

    def show_dialog(self):
        """显示对话框"""
        dialog = PluginManagerDialog(self)
        dialog.setVisible(True)

    def log_error(self, message):
        """记录错误"""
        print(f"[ERROR] {message}")
        if hasattr(self, "println"):
            self.println(f"[ERROR] {message}")

class PluginManagerDialog(GenericDialog):
    """插件管理器对话框"""

    def __init__(self, plugin_manager):
        super(PluginManagerDialog, self).__init__("插件管理器")
        self.plugin_manager = plugin_manager
        self.table_model = PluginManagerTableModel(plugin_manager.plugin_infos)
        self.init_components()

    def init_components(self):
        """初始化组件"""
        main_panel = JPanel(BorderLayout())
        
        # 创建表格
        self.table = GTable(self.table_model)
        self.table.setFillsViewportHeight(True)
        self.table.setAutoCreateRowSorter(True)
        
        # 添加表格到滚动面板
        table_scroll = JScrollPane(self.table)
        main_panel.add(table_scroll, BorderLayout.CENTER)
        
        # 创建按钮面板
        button_panel = JPanel()
        
        # 加载按钮
        load_button = JButton("加载选中插件")
        load_button.addActionListener(self.create_action_listener(self.load_selected_plugins))
        button_panel.add(load_button)
        
        # 卸载按钮
        unload_button = JButton("卸载选中插件")
        unload_button.addActionListener(self.create_action_listener(self.unload_selected_plugins))
        button_panel.add(unload_button)
        
        # 重新加载按钮
        reload_button = JButton("重新加载选中插件")
        reload_button.addActionListener(self.create_action_listener(self.reload_selected_plugins))
        button_panel.add(reload_button)
        
        # 运行按钮
        run_button = JButton("运行选中插件")
        run_button.addActionListener(self.create_action_listener(self.run_selected_plugins))
        button_panel.add(run_button)
        
        # 刷新按钮
        refresh_button = JButton("刷新插件列表")
        refresh_button.addActionListener(self.create_action_listener(self.refresh_plugins))
        button_panel.add(refresh_button)
        
        # 插件路径按钮
        path_button = JButton("管理插件路径")
        path_button.addActionListener(self.create_action_listener(self.manage_plugin_paths))
        button_panel.add(path_button)
        
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        # 设置对话框内容
        self.setContent(main_panel)
        self.setPreferredSize(800, 600)

    def create_action_listener(self, func):
        """创建ActionListener"""
        class ActionListenerImpl(ActionListener):
            def actionPerformed(self, event):
                func()
        return ActionListenerImpl()

    def load_selected_plugins(self):
        """加载选中的插件"""
        selected_rows = self.table.getSelectedRows()
        for row in selected_rows:
            model_row = self.table.convertRowIndexToModel(row)
            plugin_info = self.plugin_manager.plugin_infos[model_row]
            if plugin_info.enabled:
                self.plugin_manager.load_plugin(plugin_info)
        self.refresh_table()

    def unload_selected_plugins(self):
        """卸载选中的插件"""
        selected_rows = self.table.getSelectedRows()
        for row in selected_rows:
            model_row = self.table.convertRowIndexToModel(row)
            plugin_info = self.plugin_manager.plugin_infos[model_row]
            self.plugin_manager.unload_plugin(plugin_info)
        self.refresh_table()

    def reload_selected_plugins(self):
        """重新加载选中的插件"""
        selected_rows = self.table.getSelectedRows()
        for row in selected_rows:
            model_row = self.table.convertRowIndexToModel(row)
            plugin_info = self.plugin_manager.plugin_infos[model_row]
            if plugin_info.enabled:
                self.plugin_manager.reload_plugin(plugin_info)
        self.refresh_table()

    def run_selected_plugins(self):
        """运行选中的插件"""
        selected_rows = self.table.getSelectedRows()
        for row in selected_rows:
            model_row = self.table.convertRowIndexToModel(row)
            plugin_info = self.plugin_manager.plugin_infos[model_row]
            self.plugin_manager.run_plugin(plugin_info)

    def refresh_plugins(self):
        """刷新插件列表"""
        self.plugin_manager.discover_plugins()
        self.refresh_table()

    def manage_plugin_paths(self):
        """管理插件路径"""
        dialog = PluginPathDialog(self.plugin_manager)
        dialog.setVisible(True)
        if dialog.wasConfirmed():
            self.refresh_plugins()

    def refresh_table(self):
        """刷新表格"""
        self.table_model = PluginManagerTableModel(self.plugin_manager.plugin_infos)
        self.table.setModel(self.table_model)
        self.table.revalidate()
        self.table.repaint()

    def close(self):
        """关闭对话框"""
        self.plugin_manager.save_config()
        super(PluginManagerDialog, self).close()

class PluginPathDialog(GenericDialog):
    """插件路径管理对话框"""

    def __init__(self, plugin_manager):
        super(PluginPathDialog, self).__init__("管理插件路径")
        self.plugin_manager = plugin_manager
        self.path_field = GTextField(40)
        self.path_list = []
        self.init_components()

    def init_components(self):
        """初始化组件"""
        main_panel = JPanel(BorderLayout())
        
        # 路径列表
        list_panel = JPanel()
        list_panel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(5, 5, 5, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        
        for i, path in enumerate(self.plugin_manager.plugin_paths):
            gbc.gridx = 0
            gbc.gridy = i
            gbc.weightx = 1.0
            label = JLabel(path)
            list_panel.add(label, gbc)
            
            gbc.gridx = 1
            gbc.weightx = 0.0
            remove_button = JButton("移除")
            remove_button.addActionListener(self.create_remove_listener(path))
            list_panel.add(remove_button, gbc)
        
        # 添加路径面板
        add_panel = JPanel()
        add_panel.add(JLabel("添加新路径:"))
        add_panel.add(self.path_field)
        add_button = JButton("添加")
        add_button.addActionListener(self.create_action_listener(self.add_path))
        add_panel.add(add_button)
        
        # 组装面板
        scroll_pane = JScrollPane(list_panel)
        main_panel.add(scroll_pane, BorderLayout.CENTER)
        main_panel.add(add_panel, BorderLayout.SOUTH)
        
        # 设置对话框内容
        self.setContent(main_panel)
        self.setPreferredSize(600, 400)

    def create_action_listener(self, func):
        """创建ActionListener"""
        class ActionListenerImpl(ActionListener):
            def actionPerformed(self, event):
                func()
        return ActionListenerImpl()

    def create_remove_listener(self, path):
        """创建移除路径的监听器"""
        class ActionListenerImpl(ActionListener):
            def actionPerformed(self, event):
                self.plugin_manager.remove_plugin_path(path)
                self.init_components()
                self.pack()
        return ActionListenerImpl()

    def add_path(self):
        """添加路径"""
        path = self.path_field.getText().strip()
        if path and os.path.exists(path):
            if self.plugin_manager.add_plugin_path(path):
                self.path_field.setText("")
                self.init_components()
                self.pack()
            else:
                JOptionPane.showMessageDialog(self, "路径已存在或无效", "错误", JOptionPane.ERROR_MESSAGE)
        else:
            JOptionPane.showMessageDialog(self, "请输入有效的路径", "错误", JOptionPane.ERROR_MESSAGE)

    def confirm(self):
        """确认"""
        self.plugin_manager.save_config()
        super(PluginPathDialog, self).confirm()

class PluginManagerAction(DockingAction):
    """插件管理器动作"""

    def __init__(self):
        super(PluginManagerAction, self).__init__("PluginManager", "PluginManager")
        self.setMenuData(MenuData(["Tools", "Plugin Manager"], None, "PluginManager"))
        self.setEnabled(True)

    def actionPerformed(self, action_context):
        """执行动作"""
        plugin_manager = PluginManager()
        plugin_manager.run()

# 主函数
if __name__ == "__main__":
    script = PluginManager()
    script.run()