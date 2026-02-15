#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ScriptRunner.py

管理和运行自定义脚本序列的工具，支持脚本序列的创建、执行、监控和配置管理。

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
    from javax.swing import JFileChooser
    from javax.swing.table import DefaultTableModel
    from javax.swing.table import TableCellRenderer
    from javax.swing.table import TableCellEditor
    from javax.swing.event import TableModelEvent
    from javax.swing.event import TableModelListener
    from java.io import File
    from java.io import FileReader
    from java.io import FileWriter
    from java.io import IOException
    from java.nio.file import Files
    from java.nio.file import Paths
    from java.util import ArrayList
    from java.util import List
    from java.util import Map
    from java.util import HashMap
except ImportError as e:
    print(f"导入Ghidra模块失败: {e}")
    sys.exit(1)

class ScriptInfo:
    """脚本信息类"""
    def __init__(self, name, path, arguments="", enabled=True, description=""):
        self.name = name
        self.path = path
        self.arguments = arguments
        self.enabled = enabled
        self.description = description
        self.status = "未运行"
        self.start_time = None
        self.end_time = None
        self.output = []

    def to_dict(self):
        """转换为字典格式"""
        return {
            "name": self.name,
            "path": self.path,
            "arguments": self.arguments,
            "enabled": self.enabled,
            "description": self.description
        }

    @staticmethod
    def from_dict(data):
        """从字典创建ScriptInfo对象"""
        return ScriptInfo(
            name=data.get("name", ""),
            path=data.get("path", ""),
            arguments=data.get("arguments", ""),
            enabled=data.get("enabled", True),
            description=data.get("description", "")
        )

class ScriptSequence:
    """脚本序列类"""
    def __init__(self, name, scripts=None, description=""):
        self.name = name
        self.scripts = scripts or []
        self.description = description
        self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.last_run = None
        self.status = "就绪"

    def to_dict(self):
        """转换为字典格式"""
        return {
            "name": self.name,
            "scripts": [script.to_dict() for script in self.scripts],
            "description": self.description,
            "created_at": self.created_at,
            "last_run": self.last_run
        }

    @staticmethod
    def from_dict(data):
        """从字典创建ScriptSequence对象"""
        sequence = ScriptSequence(
            name=data.get("name", ""),
            description=data.get("description", "")
        )
        sequence.scripts = [ScriptInfo.from_dict(script_data) for script_data in data.get("scripts", [])]
        sequence.created_at = data.get("created_at", sequence.created_at)
        sequence.last_run = data.get("last_run")
        return sequence

class ScriptRunnerTableModel(DefaultTableModel):
    """脚本运行表格模型"""
    def __init__(self, script_infos):
        column_names = ["启用", "名称", "描述", "参数", "状态", "路径"]
        data = []
        for info in script_infos:
            data.append([info.enabled, info.name, info.description, info.arguments, info.status, info.path])
        super(ScriptRunnerTableModel, self).__init__(data, column_names)
        self.script_infos = script_infos

    def isCellEditable(self, row, column):
        """只有前四列是可编辑的"""
        return column in [0, 1, 2, 3]

    def getColumnClass(self, columnIndex):
        """返回列的类型"""
        if columnIndex == 0:
            return bool
        return str

    def setValueAt(self, value, row, column):
        """设置单元格值"""
        if column == 0:
            self.script_infos[row].enabled = value
        elif column == 1:
            self.script_infos[row].name = value
        elif column == 2:
            self.script_infos[row].description = value
        elif column == 3:
            self.script_infos[row].arguments = value
        self.dataVector.elementAt(row).setElementAt(value, column)
        self.fireTableCellUpdated(row, column)

class ScriptRunner(GhidraScript):
    """脚本运行工具"""

    def __init__(self):
        super(ScriptRunner, self).__init__()
        self.script_sequences = []
        self.current_sequence = None
        self.config_file = os.path.join(os.path.expanduser("~"), ".ghidra", "script_runner_config.json")
        self.script_paths = [
            os.path.join(os.path.expanduser("~"), ".ghidra", "scripts"),
            os.path.join(os.path.dirname(os.path.abspath(__file__)))
        ]

    def run(self):
        """运行脚本"""
        try:
            self.load_config()
            if not self.script_sequences:
                # 创建默认序列
                default_sequence = ScriptSequence("默认序列")
                self.script_sequences.append(default_sequence)
                self.current_sequence = default_sequence
            else:
                self.current_sequence = self.script_sequences[0]
            self.show_dialog()
        except Exception as e:
            self.log_error(f"运行脚本运行器时出错: {e}")

    def load_config(self):
        """加载配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 加载脚本序列
                if "sequences" in config:
                    self.script_sequences = [ScriptSequence.from_dict(seq_data) for seq_data in config["sequences"]]
                
                # 加载脚本路径
                if "script_paths" in config:
                    for path in config["script_paths"]:
                        if os.path.exists(path) and path not in self.script_paths:
                            self.script_paths.append(path)
        except Exception as e:
            self.log_error(f"加载配置时出错: {e}")

    def save_config(self):
        """保存配置"""
        try:
            config = {
                "sequences": [seq.to_dict() for seq in self.script_sequences],
                "script_paths": self.script_paths
            }
            
            # 确保配置目录存在
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log_error(f"保存配置时出错: {e}")

    def discover_scripts(self):
        """发现脚本"""
        discovered_scripts = []
        
        # 遍历脚本路径
        for script_path in self.script_paths:
            if not os.path.exists(script_path):
                continue
            
            for root, dirs, files in os.walk(script_path):
                for file in files:
                    if file.endswith(".py"):
                        script_file = os.path.join(root, file)
                        script_info = self.analyze_script(script_file)
                        if script_info:
                            discovered_scripts.append(script_info)
        
        return discovered_scripts

    def analyze_script(self, script_file):
        """分析脚本文件，提取脚本信息"""
        try:
            with open(script_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # 提取脚本信息
            name = os.path.basename(script_file)[:-3]  # 移除.py扩展名
            description = ""
            
            # 简单的信息提取
            for line in content.split('\n'):
                line = line.strip()
                if line.startswith('# description:'):
                    description = line.split(':', 1)[1].strip()
                elif line.startswith('"""') or line.startswith("'''"):
                    # 尝试提取文档字符串
                    doc_start = line
                    doc_lines = [line[3:]]
                    for next_line in content.split('\n')[content.split('\n').index(line) + 1:]:
                        if next_line.strip().endswith('"""') or next_line.strip().endswith("'''"):
                            doc_lines.append(next_line.strip()[:-3])
                            break
                        doc_lines.append(next_line)
                    description = ' '.join(doc_lines).strip()[:200]  # 限制描述长度
                    break
            
            return ScriptInfo(name, script_file, description=description)
        except Exception as e:
            self.log_error(f"分析脚本 {script_file} 时出错: {e}")
            return None

    def run_script(self, script_info, monitor=None):
        """运行单个脚本"""
        try:
            if not script_info.enabled:
                script_info.status = "已跳过"
                return True
            
            script_info.status = "运行中"
            script_info.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            script_info.output = []
            
            # 保存原始标准输出
            original_stdout = sys.stdout
            
            # 重定向标准输出
            class OutputCapture:
                def __init__(self):
                    self.output = []
                def write(self, text):
                    self.output.append(text)
                    original_stdout.write(text)
                def flush(self):
                    original_stdout.flush()
            
            output_capture = OutputCapture()
            sys.stdout = output_capture
            
            try:
                # 添加脚本目录到Python路径
                script_dir = os.path.dirname(script_info.path)
                if script_dir not in sys.path:
                    sys.path.insert(0, script_dir)
                
                # 导入脚本模块
                module_name = os.path.basename(script_info.path)[:-3]
                spec = importlib.util.spec_from_file_location(module_name, script_info.path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # 查找脚本类
                script_class = None
                for name, obj in module.__dict__.items():
                    if hasattr(obj, '__class__') and hasattr(obj, 'run'):
                        script_class = obj
                        break
                
                if script_class:
                    # 运行脚本
                    if hasattr(script_class, 'run'):
                        script_class.run()
                    script_info.status = "成功"
                else:
                    script_info.status = "失败"
                    script_info.output.append("未找到可执行的脚本类")
            except Exception as e:
                script_info.status = "失败"
                script_info.output.append(str(e))
                self.log_error(f"运行脚本 {script_info.name} 时出错: {e}")
            finally:
                # 恢复标准输出
                sys.stdout = original_stdout
                script_info.output.extend(output_capture.output)
                script_info.end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            return script_info.status == "成功"
        except Exception as e:
            script_info.status = "失败"
            script_info.output.append(str(e))
            self.log_error(f"运行脚本 {script_info.name} 时出错: {e}")
            return False

    def run_sequence(self, sequence, monitor=None):
        """运行脚本序列"""
        try:
            sequence.status = "运行中"
            sequence.last_run = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            success_count = 0
            total_count = 0
            
            for i, script_info in enumerate(sequence.scripts):
                if monitor and monitor.isCancelled():
                    sequence.status = "已取消"
                    return False
                
                if monitor:
                    monitor.setMessage(f"运行脚本 {i+1}/{len(sequence.scripts)}: {script_info.name}")
                    monitor.setProgress((i + 1) * 100 / len(sequence.scripts))
                
                total_count += 1
                if self.run_script(script_info, monitor):
                    success_count += 1
                
                # 短暂暂停，让UI有机会更新
                time.sleep(0.1)
            
            if success_count == total_count:
                sequence.status = "全部成功"
            else:
                sequence.status = f"部分成功 ({success_count}/{total_count})"
            
            return success_count > 0
        except Exception as e:
            sequence.status = "失败"
            self.log_error(f"运行脚本序列 {sequence.name} 时出错: {e}")
            return False

    def add_script_to_sequence(self, script_info):
        """添加脚本到当前序列"""
        if self.current_sequence:
            # 检查是否已存在
            if not any(s.path == script_info.path for s in self.current_sequence.scripts):
                self.current_sequence.scripts.append(script_info)
                return True
        return False

    def remove_script_from_sequence(self, script_info):
        """从当前序列中移除脚本"""
        if self.current_sequence:
            if script_info in self.current_sequence.scripts:
                self.current_sequence.scripts.remove(script_info)
                return True
        return False

    def move_script_up(self, script_info):
        """上移脚本"""
        if self.current_sequence:
            index = self.current_sequence.scripts.index(script_info)
            if index > 0:
                self.current_sequence.scripts[index], self.current_sequence.scripts[index-1] = \
                    self.current_sequence.scripts[index-1], self.current_sequence.scripts[index]
                return True
        return False

    def move_script_down(self, script_info):
        """下移脚本"""
        if self.current_sequence:
            index = self.current_sequence.scripts.index(script_info)
            if index < len(self.current_sequence.scripts) - 1:
                self.current_sequence.scripts[index], self.current_sequence.scripts[index+1] = \
                    self.current_sequence.scripts[index+1], self.current_sequence.scripts[index]
                return True
        return False

    def create_new_sequence(self, name, description=""):
        """创建新序列"""
        new_sequence = ScriptSequence(name, description=description)
        self.script_sequences.append(new_sequence)
        self.current_sequence = new_sequence
        return new_sequence

    def delete_sequence(self, sequence):
        """删除序列"""
        if sequence in self.script_sequences:
            self.script_sequences.remove(sequence)
            if self.current_sequence == sequence:
                self.current_sequence = self.script_sequences[0] if self.script_sequences else None
            return True
        return False

    def export_sequence(self, sequence, file_path):
        """导出序列"""
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(sequence.to_dict(), f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            self.log_error(f"导出序列时出错: {e}")
            return False

    def import_sequence(self, file_path):
        """导入序列"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            sequence = ScriptSequence.from_dict(data)
            # 检查名称是否冲突
            existing_names = [s.name for s in self.script_sequences]
            if sequence.name in existing_names:
                i = 1
                while f"{sequence.name}_{i}" in existing_names:
                    i += 1
                sequence.name = f"{sequence.name}_{i}"
            self.script_sequences.append(sequence)
            return sequence
        except Exception as e:
            self.log_error(f"导入序列时出错: {e}")
            return None

    def show_dialog(self):
        """显示对话框"""
        dialog = ScriptRunnerDialog(self)
        dialog.setVisible(True)

    def log_error(self, message):
        """记录错误"""
        print(f"[ERROR] {message}")
        if hasattr(self, "println"):
            self.println(f"[ERROR] {message}")

class ScriptRunnerDialog(GenericDialog):
    """脚本运行对话框"""

    def __init__(self, script_runner):
        super(ScriptRunnerDialog, self).__init__("脚本运行器")
        self.script_runner = script_runner
        self.table_model = None
        self.sequence_combo = None
        self.init_components()

    def init_components(self):
        """初始化组件"""
        main_panel = JPanel(BorderLayout())
        
        # 顶部面板 - 序列选择和控制
        top_panel = JPanel()
        
        # 序列选择
        top_panel.add(JLabel("脚本序列:"))
        self.sequence_combo = GComboBox([s.name for s in self.script_runner.script_sequences])
        if self.script_runner.current_sequence:
            self.sequence_combo.setSelectedItem(self.script_runner.current_sequence.name)
        self.sequence_combo.addActionListener(self.create_action_listener(self.sequence_selected))
        top_panel.add(self.sequence_combo)
        
        # 新建序列按钮
        new_sequence_button = JButton("新建序列")
        new_sequence_button.addActionListener(self.create_action_listener(self.new_sequence))
        top_panel.add(new_sequence_button)
        
        # 删除序列按钮
        delete_sequence_button = JButton("删除序列")
        delete_sequence_button.addActionListener(self.create_action_listener(self.delete_sequence))
        top_panel.add(delete_sequence_button)
        
        # 导出序列按钮
        export_sequence_button = JButton("导出序列")
        export_sequence_button.addActionListener(self.create_action_listener(self.export_sequence))
        top_panel.add(export_sequence_button)
        
        # 导入序列按钮
        import_sequence_button = JButton("导入序列")
        import_sequence_button.addActionListener(self.create_action_listener(self.import_sequence))
        top_panel.add(import_sequence_button)
        
        main_panel.add(top_panel, BorderLayout.NORTH)
        
        # 中间面板 - 脚本列表
        if self.script_runner.current_sequence:
            self.table_model = ScriptRunnerTableModel(self.script_runner.current_sequence.scripts)
        else:
            self.table_model = ScriptRunnerTableModel([])
        
        self.table = GTable(self.table_model)
        self.table.setFillsViewportHeight(True)
        self.table.setAutoCreateRowSorter(True)
        
        # 添加表格到滚动面板
        table_scroll = JScrollPane(self.table)
        main_panel.add(table_scroll, BorderLayout.CENTER)
        
        # 底部面板 - 按钮
        button_panel = JPanel()
        
        # 添加脚本按钮
        add_script_button = JButton("添加脚本")
        add_script_button.addActionListener(self.create_action_listener(self.add_script))
        button_panel.add(add_script_button)
        
        # 移除脚本按钮
        remove_script_button = JButton("移除脚本")
        remove_script_button.addActionListener(self.create_action_listener(self.remove_script))
        button_panel.add(remove_script_button)
        
        # 上移按钮
        move_up_button = JButton("上移")
        move_up_button.addActionListener(self.create_action_listener(self.move_script_up))
        button_panel.add(move_up_button)
        
        # 下移按钮
        move_down_button = JButton("下移")
        move_down_button.addActionListener(self.create_action_listener(self.move_script_down))
        button_panel.add(move_down_button)
        
        # 运行序列按钮
        run_sequence_button = JButton("运行序列")
        run_sequence_button.addActionListener(self.create_action_listener(self.run_sequence))
        button_panel.add(run_sequence_button)
        
        # 刷新按钮
        refresh_button = JButton("刷新")
        refresh_button.addActionListener(self.create_action_listener(self.refresh_table))
        button_panel.add(refresh_button)
        
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        # 设置对话框内容
        self.setContent(main_panel)
        self.setPreferredSize(900, 600)

    def create_action_listener(self, func):
        """创建ActionListener"""
        class ActionListenerImpl(ActionListener):
            def actionPerformed(self, event):
                func()
        return ActionListenerImpl()

    def sequence_selected(self):
        """选择序列"""
        selected_name = self.sequence_combo.getSelectedItem()
        for sequence in self.script_runner.script_sequences:
            if sequence.name == selected_name:
                self.script_runner.current_sequence = sequence
                self.refresh_table()
                break

    def new_sequence(self):
        """新建序列"""
        name = JOptionPane.showInputDialog(self, "输入序列名称:")
        if name:
            description = JOptionPane.showInputDialog(self, "输入序列描述:")
            self.script_runner.create_new_sequence(name, description or "")
            self.update_sequence_combo()
            self.sequence_combo.setSelectedItem(name)
            self.refresh_table()

    def delete_sequence(self):
        """删除序列"""
        if len(self.script_runner.script_sequences) <= 1:
            JOptionPane.showMessageDialog(self, "至少需要保留一个序列", "错误", JOptionPane.ERROR_MESSAGE)
            return
        
        selected_name = self.sequence_combo.getSelectedItem()
        confirm = JOptionPane.showConfirmDialog(self, f"确定要删除序列 {selected_name} 吗?", "确认", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            for sequence in self.script_runner.script_sequences:
                if sequence.name == selected_name:
                    self.script_runner.delete_sequence(sequence)
                    self.update_sequence_combo()
                    self.refresh_table()
                    break

    def export_sequence(self):
        """导出序列"""
        if not self.script_runner.current_sequence:
            return
        
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("导出脚本序列")
        file_chooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON文件", "json"))
        file_chooser.setSelectedFile(File(self.script_runner.current_sequence.name + ".json"))
        
        if file_chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".json"):
                file_path += ".json"
            if self.script_runner.export_sequence(self.script_runner.current_sequence, file_path):
                JOptionPane.showMessageDialog(self, "序列导出成功", "成功", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self, "序列导出失败", "错误", JOptionPane.ERROR_MESSAGE)

    def import_sequence(self):
        """导入序列"""
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("导入脚本序列")
        file_chooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON文件", "json"))
        
        if file_chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            sequence = self.script_runner.import_sequence(file_path)
            if sequence:
                self.update_sequence_combo()
                self.sequence_combo.setSelectedItem(sequence.name)
                self.refresh_table()
                JOptionPane.showMessageDialog(self, "序列导入成功", "成功", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self, "序列导入失败", "错误", JOptionPane.ERROR_MESSAGE)

    def add_script(self):
        """添加脚本"""
        # 发现可用脚本
        available_scripts = self.script_runner.discover_scripts()
        
        # 过滤掉已在当前序列中的脚本
        current_paths = [s.path for s in self.script_runner.current_sequence.scripts]
        available_scripts = [s for s in available_scripts if s.path not in current_paths]
        
        if not available_scripts:
            JOptionPane.showMessageDialog(self, "没有可用的脚本", "提示", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # 创建脚本选择对话框
        dialog = ScriptSelectionDialog(available_scripts)
        dialog.setVisible(True)
        if dialog.wasConfirmed():
            selected_scripts = dialog.get_selected_scripts()
            for script in selected_scripts:
                self.script_runner.add_script_to_sequence(script)
            self.refresh_table()

    def remove_script(self):
        """移除脚本"""
        selected_rows = self.table.getSelectedRows()
        if not selected_rows:
            JOptionPane.showMessageDialog(self, "请选择要移除的脚本", "提示", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # 按索引降序排列，避免移除时索引变化
        selected_rows.sort(reverse=True)
        for row in selected_rows:
            model_row = self.table.convertRowIndexToModel(row)
            script_info = self.script_runner.current_sequence.scripts[model_row]
            self.script_runner.remove_script_from_sequence(script_info)
        
        self.refresh_table()

    def move_script_up(self):
        """上移脚本"""
        selected_rows = self.table.getSelectedRows()
        if len(selected_rows) != 1:
            JOptionPane.showMessageDialog(self, "请选择一个脚本", "提示", JOptionPane.INFORMATION_MESSAGE)
            return
        
        model_row = self.table.convertRowIndexToModel(selected_rows[0])
        script_info = self.script_runner.current_sequence.scripts[model_row]
        if self.script_runner.move_script_up(script_info):
            self.refresh_table()

    def move_script_down(self):
        """下移脚本"""
        selected_rows = self.table.getSelectedRows()
        if len(selected_rows) != 1:
            JOptionPane.showMessageDialog(self, "请选择一个脚本", "提示", JOptionPane.INFORMATION_MESSAGE)
            return
        
        model_row = self.table.convertRowIndexToModel(selected_rows[0])
        script_info = self.script_runner.current_sequence.scripts[model_row]
        if self.script_runner.move_script_down(script_info):
            self.refresh_table()

    def run_sequence(self):
        """运行序列"""
        if not self.script_runner.current_sequence or not self.script_runner.current_sequence.scripts:
            JOptionPane.showMessageDialog(self, "序列中没有脚本", "提示", JOptionPane.INFORMATION_MESSAGE)
            return
        
        # 创建运行任务
        class RunSequenceTask(Task):
            def __init__(self, script_runner, sequence):
                super(RunSequenceTask, self).__init__("运行脚本序列", True, False, False)
                self.script_runner = script_runner
                self.sequence = sequence
            def run(self, monitor):
                self.script_runner.run_sequence(self.sequence, monitor)
        
        task = RunSequenceTask(self.script_runner, self.script_runner.current_sequence)
        self.script_runner.monitor.execute(task)
        
        # 等待任务完成并刷新表格
        while task.isRunning():
            time.sleep(0.1)
        self.refresh_table()

    def refresh_table(self):
        """刷新表格"""
        if self.script_runner.current_sequence:
            self.table_model = ScriptRunnerTableModel(self.script_runner.current_sequence.scripts)
            self.table.setModel(self.table_model)
            self.table.revalidate()
            self.table.repaint()

    def update_sequence_combo(self):
        """更新序列下拉框"""
        self.sequence_combo.removeAllItems()
        for sequence in self.script_runner.script_sequences:
            self.sequence_combo.addItem(sequence.name)

    def create_action_listener(self, func):
        """创建ActionListener"""
        class ActionListenerImpl(ActionListener):
            def actionPerformed(self, event):
                func()
        return ActionListenerImpl()

    def close(self):
        """关闭对话框"""
        self.script_runner.save_config()
        super(ScriptRunnerDialog, self).close()

class ScriptSelectionDialog(GenericDialog):
    """脚本选择对话框"""

    def __init__(self, available_scripts):
        super(ScriptSelectionDialog, self).__init__("选择脚本")
        self.available_scripts = available_scripts
        self.selected_scripts = []
        self.checkboxes = []
        self.init_components()

    def init_components(self):
        """初始化组件"""
        main_panel = JPanel(BorderLayout())
        
        # 脚本列表
        list_panel = JPanel()
        list_panel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(2, 5, 2, 5)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        
        for i, script in enumerate(self.available_scripts):
            gbc.gridx = 0
            gbc.gridy = i
            gbc.weightx = 0.0
            checkbox = GCheckBox()
            self.checkboxes.append(checkbox)
            list_panel.add(checkbox, gbc)
            
            gbc.gridx = 1
            gbc.weightx = 1.0
            label = JLabel(f"{script.name} - {script.description}")
            list_panel.add(label, gbc)
        
        scroll_pane = JScrollPane(list_panel)
        main_panel.add(scroll_pane, BorderLayout.CENTER)
        
        # 设置对话框内容
        self.setContent(main_panel)
        self.setPreferredSize(600, 400)

    def confirm(self):
        """确认选择"""
        self.selected_scripts = []
        for i, checkbox in enumerate(self.checkboxes):
            if checkbox.isSelected():
                self.selected_scripts.append(self.available_scripts[i])
        super(ScriptSelectionDialog, self).confirm()

    def get_selected_scripts(self):
        """获取选中的脚本"""
        return self.selected_scripts

class ScriptRunnerAction(DockingAction):
    """脚本运行器动作"""

    def __init__(self):
        super(ScriptRunnerAction, self).__init__("ScriptRunner", "ScriptRunner")
        self.setMenuData(MenuData(["Tools", "Script Runner"], None, "ScriptRunner"))
        self.setEnabled(True)

    def actionPerformed(self, action_context):
        """执行动作"""
        script_runner = ScriptRunner()
        script_runner.run()

# 导入模块
import importlib
import importlib.util

# 主函数
if __name__ == "__main__":
    script = ScriptRunner()
    script.run()