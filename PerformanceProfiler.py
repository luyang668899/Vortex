#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PerformanceProfiler.py

分析程序性能瓶颈，实现执行时间分析和性能数据可视化。

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
import statistics

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
    # 导入Ghidra的程序和函数相关类
    from ghidra.program.model.listing import Function
    from ghidra.program.model.listing import FunctionIterator
    from ghidra.program.model.listing import Program
    from ghidra.program.model.listing import Listing
    from ghidra.program.model.address import Address
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.address import AddressSetView
    from ghidra.program.model.lang import Register
    from ghidra.program.model.lang import RegisterValue
    from ghidra.program.model.mem import Memory
    from ghidra.program.model.mem import MemoryAccessException
    from ghidra.program.model.symbol import Symbol
    from ghidra.program.model.symbol import SymbolIterator
    from ghidra.program.model.symbol import SymbolTable
    from ghidra.program.model.block import CodeBlock
    from ghidra.program.model.block import CodeBlockIterator
    from ghidra.program.model.block import CodeBlockModel
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import TaskMonitorAdapter
    from ghidra.util.exception import CancelledException
except Exception as e:
    print(f"导入模块时出错: {e}")

class PerformanceData:
    """
    性能数据类，用于存储和分析性能相关数据
    """
    def __init__(self):
        """
        初始化性能数据
        """
        self.function_times = {}
        self.block_times = {}
        self.instruction_counts = {}
        self.called_functions = {}
        self.execution_trace = []
    
    def add_function_time(self, function_name, execution_time):
        """
        添加函数执行时间
        
        Args:
            function_name: 函数名称
            execution_time: 执行时间（毫秒）
        """
        if function_name not in self.function_times:
            self.function_times[function_name] = []
        self.function_times[function_name].append(execution_time)
    
    def add_block_time(self, block_address, execution_time):
        """
        添加代码块执行时间
        
        Args:
            block_address: 代码块地址
            execution_time: 执行时间（毫秒）
        """
        if block_address not in self.block_times:
            self.block_times[block_address] = []
        self.block_times[block_address].append(execution_time)
    
    def add_instruction_count(self, function_name, count):
        """
        添加指令执行次数
        
        Args:
            function_name: 函数名称
            count: 指令执行次数
        """
        self.instruction_counts[function_name] = count
    
    def add_called_function(self, caller, callee):
        """
        添加函数调用关系
        
        Args:
            caller: 调用者函数
            callee: 被调用函数
        """
        if caller not in self.called_functions:
            self.called_functions[caller] = set()
        self.called_functions[caller].add(callee)
    
    def add_execution_trace(self, instruction):
        """
        添加执行轨迹
        
        Args:
            instruction: 执行的指令
        """
        self.execution_trace.append(instruction)
    
    def get_function_stats(self):
        """
        获取函数统计信息
        
        Returns:
            函数统计信息字典
        """
        stats = {}
        for function_name, times in self.function_times.items():
            if times:
                stats[function_name] = {
                    "count": len(times),
                    "min": min(times),
                    "max": max(times),
                    "average": statistics.mean(times),
                    "total": sum(times)
                }
        return stats
    
    def get_block_stats(self):
        """
        获取代码块统计信息
        
        Returns:
            代码块统计信息字典
        """
        stats = {}
        for block_address, times in self.block_times.items():
            if times:
                stats[block_address] = {
                    "count": len(times),
                    "min": min(times),
                    "max": max(times),
                    "average": statistics.mean(times),
                    "total": sum(times)
                }
        return stats
    
    def get_hottest_functions(self, top_n=10):
        """
        获取执行时间最长的函数
        
        Args:
            top_n: 返回前N个函数
        
        Returns:
            执行时间最长的函数列表
        """
        stats = self.get_function_stats()
        sorted_functions = sorted(stats.items(), key=lambda x: x[1]["total"], reverse=True)
        return sorted_functions[:top_n]
    
    def get_most_called_functions(self, top_n=10):
        """
        获取调用次数最多的函数
        
        Args:
            top_n: 返回前N个函数
        
        Returns:
            调用次数最多的函数列表
        """
        stats = self.get_function_stats()
        sorted_functions = sorted(stats.items(), key=lambda x: x[1]["count"], reverse=True)
        return sorted_functions[:top_n]
    
    def save_to_file(self, file_path):
        """
        保存性能数据到文件
        
        Args:
            file_path: 文件路径
        """
        try:
            data = {
                "function_times": self.function_times,
                "block_times": {str(k): v for k, v in self.block_times.items()},
                "instruction_counts": self.instruction_counts,
                "called_functions": {k: list(v) for k, v in self.called_functions.items()},
                "execution_trace": self.execution_trace
            }
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print(f"保存性能数据时出错: {e}")
            return False
    
    def load_from_file(self, file_path):
        """
        从文件加载性能数据
        
        Args:
            file_path: 文件路径
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self.function_times = data.get("function_times", {})
            self.block_times = {eval(k): v for k, v in data.get("block_times", {}).items()}
            self.instruction_counts = data.get("instruction_counts", {})
            self.called_functions = {k: set(v) for k, v in data.get("called_functions", {}).items()}
            self.execution_trace = data.get("execution_trace", [])
            
            return True
        except Exception as e:
            print(f"加载性能数据时出错: {e}")
            return False

class PerformanceProfiler:
    """
    性能分析器，用于分析程序性能瓶颈
    """
    def __init__(self, program):
        """
        初始化性能分析器
        
        Args:
            program: Ghidra程序实例
        """
        self.program = program
        self.performance_data = PerformanceData()
        self.is_profiling = False
        self.start_time = 0
        self.function_calls = {}
    
    def start_profiling(self):
        """
        开始性能分析
        """
        self.is_profiling = True
        self.start_time = time.time()
        self.function_calls = {}
        self.performance_data = PerformanceData()
        print("性能分析已启动")
    
    def stop_profiling(self):
        """
        停止性能分析
        """
        self.is_profiling = False
        elapsed_time = time.time() - self.start_time
        print(f"性能分析已停止，总耗时: {elapsed_time:.2f}秒")
    
    def analyze_function_performance(self):
        """
        分析函数性能
        
        Returns:
            函数性能分析结果
        """
        try:
            listing = self.program.getListing()
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            results = []
            
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                # 计算函数大小
                if body is not None:
                    size = body.getNumAddresses()
                else:
                    size = 0
                
                # 计算基本块数量
                block_count = 0
                block_model = BasicBlockModel(self.program)
                block_iterator = block_model.getCodeBlocksContaining(body, TaskMonitorAdapter.DUMMY_MONITOR)
                while block_iterator.hasNext():
                    block_count += 1
                    block_iterator.next()
                
                # 计算调用次数（模拟数据，实际需要运行时收集）
                call_count = self.function_calls.get(function_name, 0)
                
                # 计算执行时间（模拟数据，实际需要运行时收集）
                execution_time = size * 0.01  # 模拟执行时间
                
                results.append({
                    "name": function_name,
                    "address": function.getEntryPoint(),
                    "size": size,
                    "block_count": block_count,
                    "call_count": call_count,
                    "execution_time": execution_time
                })
            
            # 按执行时间排序
            results.sort(key=lambda x: x["execution_time"], reverse=True)
            
            return results
        except Exception as e:
            print(f"分析函数性能时出错: {e}")
            return []
    
    def analyze_block_performance(self):
        """
        分析代码块性能
        
        Returns:
            代码块性能分析结果
        """
        try:
            listing = self.program.getListing()
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            results = []
            
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                if body is not None:
                    # 获取基本块
                    block_model = BasicBlockModel(self.program)
                    block_iterator = block_model.getCodeBlocksContaining(body, TaskMonitorAdapter.DUMMY_MONITOR)
                    
                    while block_iterator.hasNext():
                        block = block_iterator.next()
                        block_address = block.getStart()
                        block_size = block.getNumAddresses()
                        
                        # 计算执行时间（模拟数据）
                        execution_time = block_size * 0.005  # 模拟执行时间
                        
                        results.append({
                            "function": function_name,
                            "address": block_address,
                            "size": block_size,
                            "execution_time": execution_time
                        })
            
            # 按执行时间排序
            results.sort(key=lambda x: x["execution_time"], reverse=True)
            
            return results
        except Exception as e:
            print(f"分析代码块性能时出错: {e}")
            return []
    
    def identify_bottlenecks(self, threshold=0.1):
        """
        识别性能瓶颈
        
        Args:
            threshold: 瓶颈阈值（占总执行时间的比例）
        
        Returns:
            瓶颈函数列表
        """
        try:
            function_performance = self.analyze_function_performance()
            
            if not function_performance:
                return []
            
            # 计算总执行时间
            total_time = sum(item["execution_time"] for item in function_performance)
            
            # 识别瓶颈
            bottlenecks = []
            for item in function_performance:
                if item["execution_time"] / total_time >= threshold:
                    bottlenecks.append(item)
            
            return bottlenecks
        except Exception as e:
            print(f"识别性能瓶颈时出错: {e}")
            return []
    
    def generate_performance_report(self):
        """
        生成性能分析报告
        
        Returns:
            性能分析报告
        """
        try:
            # 分析函数性能
            function_performance = self.analyze_function_performance()
            
            # 分析代码块性能
            block_performance = self.analyze_block_performance()
            
            # 识别瓶颈
            bottlenecks = self.identify_bottlenecks()
            
            # 生成报告
            report = {
                "total_functions": len(function_performance),
                "total_blocks": len(block_performance),
                "bottlenecks": bottlenecks,
                "top_functions_by_time": function_performance[:10],
                "top_blocks_by_time": block_performance[:10]
            }
            
            return report
        except Exception as e:
            print(f"生成性能分析报告时出错: {e}")
            return {}

class PerformanceVisualizer:
    """
    性能数据可视化器
    """
    def __init__(self, performance_data):
        """
        初始化性能可视化器
        
        Args:
            performance_data: 性能数据
        """
        self.performance_data = performance_data
    
    def create_performance_chart(self, parent):
        """
        创建性能图表
        
        Args:
            parent: 父组件
        
        Returns:
            性能图表面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建图表标题
        title_label = GLabel("性能分析图表")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        panel.add(title_label, BorderLayout.NORTH)
        
        # 创建图表内容（这里使用简单的文本表示，实际可以使用更复杂的图表库）
        chart_content = GTextArea()
        chart_content.setEditable(False)
        
        # 添加性能数据
        function_stats = self.performance_data.get_function_stats()
        if function_stats:
            chart_content.append("=== 函数性能统计 ===\n")
            for function_name, stats in sorted(function_stats.items(), key=lambda x: x[1]["total"], reverse=True)[:10]:
                chart_content.append(f"{function_name}:\n")
                chart_content.append(f"  调用次数: {stats['count']}\n")
                chart_content.append(f"  最小时间: {stats['min']:.4f}ms\n")
                chart_content.append(f"  最大时间: {stats['max']:.4f}ms\n")
                chart_content.append(f"  平均时间: {stats['average']:.4f}ms\n")
                chart_content.append(f"  总时间: {stats['total']:.4f}ms\n\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(chart_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_call_graph(self, parent):
        """
        创建调用图
        
        Args:
            parent: 父组件
        
        Returns:
            调用图面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建图表标题
        title_label = GLabel("函数调用图")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        panel.add(title_label, BorderLayout.NORTH)
        
        # 创建调用图内容
        graph_content = GTextArea()
        graph_content.setEditable(False)
        
        # 添加调用关系
        called_functions = self.performance_data.called_functions
        if called_functions:
            graph_content.append("=== 函数调用关系 ===\n")
            for caller, callees in called_functions.items():
                graph_content.append(f"{caller} ->\n")
                for callee in callees:
                    graph_content.append(f"  - {callee}\n")
                graph_content.append("\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(graph_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel

class PerformanceProfilerDialog(GDialog):
    """
    性能分析对话框
    """
    def __init__(self, tool, program):
        """
        初始化性能分析对话框
        
        Args:
            tool: Ghidra工具实例
            program: Ghidra程序实例
        """
        super(PerformanceProfilerDialog, self).__init__(tool.getWindow(), "性能分析器", True)
        self.tool = tool
        self.program = program
        self.profiler = PerformanceProfiler(program)
        self.performance_data = PerformanceData()
        
        # 设置对话框大小
        self.setSize(900, 700)
        
        # 创建主面板
        main_panel = GPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建标签页
        tabbed_pane = GTabbedPane()
        
        # 添加控制标签页
        self.control_panel = self.create_control_panel()
        tabbed_pane.addTab("控制", self.control_panel)
        
        # 添加函数分析标签页
        self.function_analysis_panel = self.create_function_analysis_panel()
        tabbed_pane.addTab("函数分析", self.function_analysis_panel)
        
        # 添加代码块分析标签页
        self.block_analysis_panel = self.create_block_analysis_panel()
        tabbed_pane.addTab("代码块分析", self.block_analysis_panel)
        
        # 添加可视化标签页
        self.visualization_panel = self.create_visualization_panel()
        tabbed_pane.addTab("可视化", self.visualization_panel)
        
        # 添加报告标签页
        self.report_panel = self.create_report_panel()
        tabbed_pane.addTab("报告", self.report_panel)
        
        main_panel.add(tabbed_pane, BorderLayout.CENTER)
        
        # 设置内容面板
        self.setContent(main_panel)
        
        # 居中显示
        self.setLocationRelativeTo(tool.getWindow())
    
    def create_control_panel(self):
        """
        创建控制面板
        
        Returns:
            控制面板
        """
        panel = GPanel()
        panel.setLayout(GridBagLayout())
        
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        
        # 开始分析按钮
        gbc.gridx = 0
        gbc.gridy = 0
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        def on_start(e):
            self.profiler.start_profiling()
            JOptionPane.showMessageDialog(self, "性能分析已启动", "信息", JOptionPane.INFORMATION_MESSAGE)
        
        self.start_button = GButton("开始性能分析")
        self.start_button.addActionListener(on_start)
        panel.add(self.start_button, gbc)
        
        # 停止分析按钮
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 2
        gbc.weightx = 1.0
        def on_stop(e):
            self.profiler.stop_profiling()
            JOptionPane.showMessageDialog(self, "性能分析已停止", "信息", JOptionPane.INFORMATION_MESSAGE)
            # 刷新分析结果
            self.refresh_analysis_results()
        
        self.stop_button = GButton("停止性能分析")
        self.stop_button.addActionListener(on_stop)
        panel.add(self.stop_button, gbc)
        
        # 保存数据按钮
        gbc.gridx = 0
        gbc.gridy = 2
        gbc.gridwidth = 1
        gbc.weightx = 0.5
        class JSONFileFilter(FileFilter):
            def accept(self, f):
                return f.isDirectory() or f.getName().endswith(".json")
            
            def getDescription(self):
                return "JSON文件 (*.json)"
        
        def on_save(e):
            file_chooser = GFileChooser()
            file_chooser.setDialogTitle("保存性能数据")
            file_chooser.setFileFilter(JSONFileFilter())
            
            result = file_chooser.showSaveDialog(self)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                # 确保文件扩展名为.json
                if not file_path.endswith(".json"):
                    file_path += ".json"
                
                success = self.performance_data.save_to_file(file_path)
                if success:
                    JOptionPane.showMessageDialog(self, f"成功保存性能数据到: {file_path}", "成功", JOptionPane.INFORMATION_MESSAGE)
                else:
                    JOptionPane.showMessageDialog(self, "保存性能数据失败", "错误", JOptionPane.ERROR_MESSAGE)
        
        save_button = GButton("保存性能数据")
        save_button.addActionListener(on_save)
        panel.add(save_button, gbc)
        
        # 加载数据按钮
        gbc.gridx = 1
        gbc.gridy = 2
        gbc.gridwidth = 1
        gbc.weightx = 0.5
        def on_load(e):
            file_chooser = GFileChooser()
            file_chooser.setDialogTitle("加载性能数据")
            file_chooser.setFileFilter(JSONFileFilter())
            
            result = file_chooser.showOpenDialog(self)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                success = self.performance_data.load_from_file(file_path)
                if success:
                    JOptionPane.showMessageDialog(self, f"成功加载性能数据从: {file_path}", "成功", JOptionPane.INFORMATION_MESSAGE)
                    # 刷新分析结果
                    self.refresh_analysis_results()
                else:
                    JOptionPane.showMessageDialog(self, "加载性能数据失败", "错误", JOptionPane.ERROR_MESSAGE)
        
        load_button = GButton("加载性能数据")
        load_button.addActionListener(on_load)
        panel.add(load_button, gbc)
        
        return panel
    
    def create_function_analysis_panel(self):
        """
        创建函数分析面板
        
        Returns:
            函数分析面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建分析按钮
        def on_analyze_functions(e):
            self.analyze_functions()
        
        analyze_button = GButton("分析函数性能")
        analyze_button.addActionListener(on_analyze_functions)
        panel.add(analyze_button, BorderLayout.NORTH)
        
        # 创建函数表格
        column_names = ["函数名", "地址", "大小", "基本块数", "调用次数", "执行时间(ms)"]
        self.function_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.function_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_block_analysis_panel(self):
        """
        创建代码块分析面板
        
        Returns:
            代码块分析面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建分析按钮
        def on_analyze_blocks(e):
            self.analyze_blocks()
        
        analyze_button = GButton("分析代码块性能")
        analyze_button.addActionListener(on_analyze_blocks)
        panel.add(analyze_button, BorderLayout.NORTH)
        
        # 创建代码块表格
        column_names = ["函数名", "地址", "大小", "执行时间(ms)"]
        self.block_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.block_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_visualization_panel(self):
        """
        创建可视化面板
        
        Returns:
            可视化面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建可视化按钮
        def on_generate_visualization(e):
            self.generate_visualization()
        
        visualize_button = GButton("生成可视化")
        visualize_button.addActionListener(on_generate_visualization)
        panel.add(visualize_button, BorderLayout.NORTH)
        
        # 创建可视化内容面板
        self.visualization_content = GPanel()
        self.visualization_content.setLayout(BorderLayout())
        
        # 添加默认提示
        default_label = GLabel("点击 '生成可视化' 按钮查看性能数据可视化")
        default_label.setHorizontalAlignment(JLabel.CENTER)
        self.visualization_content.add(default_label, BorderLayout.CENTER)
        
        panel.add(self.visualization_content, BorderLayout.CENTER)
        
        return panel
    
    def create_report_panel(self):
        """
        创建报告面板
        
        Returns:
            报告面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建生成报告按钮
        def on_generate_report(e):
            self.generate_report()
        
        generate_button = GButton("生成报告")
        generate_button.addActionListener(on_generate_report)
        panel.add(generate_button, BorderLayout.NORTH)
        
        # 创建报告内容
        self.report_text = GTextArea()
        self.report_text.setEditable(False)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.report_text)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def analyze_functions(self):
        """
        分析函数性能
        """
        try:
            results = self.profiler.analyze_function_performance()
            
            # 更新表格
            model = DefaultTableModel([], ["函数名", "地址", "大小", "基本块数", "调用次数", "执行时间(ms)"])
            for result in results[:50]:  # 只显示前50个函数
                model.addRow([
                    result["name"],
                    result["address"],
                    result["size"],
                    result["block_count"],
                    result["call_count"],
                    f"{result['execution_time']:.4f}"
                ])
            
            self.function_table.setModel(model)
            
            JOptionPane.showMessageDialog(self, f"成功分析了 {len(results)} 个函数", "成功", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self, f"分析函数性能时出错: {e}", "错误", JOptionPane.ERROR_MESSAGE)
    
    def analyze_blocks(self):
        """
        分析代码块性能
        """
        try:
            results = self.profiler.analyze_block_performance()
            
            # 更新表格
            model = DefaultTableModel([], ["函数名", "地址", "大小", "执行时间(ms)"])
            for result in results[:100]:  # 只显示前100个代码块
                model.addRow([
                    result["function"],
                    result["address"],
                    result["size"],
                    f"{result['execution_time']:.4f}"
                ])
            
            self.block_table.setModel(model)
            
            JOptionPane.showMessageDialog(self, f"成功分析了 {len(results)} 个代码块", "成功", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self, f"分析代码块性能时出错: {e}", "错误", JOptionPane.ERROR_MESSAGE)
    
    def generate_visualization(self):
        """
        生成可视化
        """
        try:
            # 清除现有内容
            self.visualization_content.removeAll()
            
            # 创建可视化器
            visualizer = PerformanceVisualizer(self.performance_data)
            
            # 创建性能图表
            chart_panel = visualizer.create_performance_chart(self)
            
            # 添加到内容面板
            self.visualization_content.add(chart_panel, BorderLayout.CENTER)
            
            # 刷新面板
            self.visualization_content.revalidate()
            self.visualization_content.repaint()
            
        except Exception as e:
            JOptionPane.showMessageDialog(self, f"生成可视化时出错: {e}", "错误", JOptionPane.ERROR_MESSAGE)
    
    def generate_report(self):
        """
        生成性能分析报告
        """
        try:
            report = self.profiler.generate_performance_report()
            
            # 清空现有内容
            self.report_text.setText("")
            
            # 添加报告内容
            self.report_text.append("=== 性能分析报告 ===\n\n")
            self.report_text.append(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            self.report_text.append(f"程序: {self.program.getName()}\n")
            self.report_text.append(f"总函数数: {report.get('total_functions', 0)}\n")
            self.report_text.append(f"总代码块数: {report.get('total_blocks', 0)}\n\n")
            
            # 添加瓶颈分析
            bottlenecks = report.get('bottlenecks', [])
            if bottlenecks:
                self.report_text.append("=== 性能瓶颈 ===\n")
                for bottleneck in bottlenecks:
                    self.report_text.append(f"函数: {bottleneck['name']}\n")
                    self.report_text.append(f"  地址: {bottleneck['address']}\n")
                    self.report_text.append(f"  大小: {bottleneck['size']} bytes\n")
                    self.report_text.append(f"  基本块数: {bottleneck['block_count']}\n")
                    self.report_text.append(f"  执行时间: {bottleneck['execution_time']:.4f}ms\n\n")
            
            # 添加top函数
            top_functions = report.get('top_functions_by_time', [])
            if top_functions:
                self.report_text.append("=== 执行时间最长的函数 ===\n")
                for i, function in enumerate(top_functions[:10], 1):
                    self.report_text.append(f"{i}. {function['name']}: {function['execution_time']:.4f}ms\n")
                self.report_text.append("\n")
            
            # 添加优化建议
            self.report_text.append("=== 优化建议 ===\n")
            if bottlenecks:
                for bottleneck in bottlenecks:
                    self.report_text.append(f"- 考虑优化函数 '{bottleneck['name']}'，其执行时间较长\n")
            self.report_text.append("- 检查频繁调用的函数，考虑缓存或内联优化\n")
            self.report_text.append("- 分析热点代码块，寻找算法优化机会\n")
            self.report_text.append("- 考虑使用更高效的数据结构和算法\n")
            
        except Exception as e:
            JOptionPane.showMessageDialog(self, f"生成报告时出错: {e}", "错误", JOptionPane.ERROR_MESSAGE)
    
    def refresh_analysis_results(self):
        """
        刷新分析结果
        """
        # 重新分析函数性能
        self.analyze_functions()
        
        # 重新分析代码块性能
        self.analyze_blocks()
        
        # 重新生成可视化
        self.generate_visualization()
        
        # 重新生成报告
        self.generate_report()

class PerformanceProfilerScript(GhidraScript):
    """
    性能分析脚本
    """
    def __init__(self):
        """
        初始化脚本
        """
        super(PerformanceProfilerScript, self).__init__()
    
    def run(self):
        """
        运行脚本
        """
        try:
            # 获取当前程序
            program = self.currentProgram
            if not program:
                self.println("没有打开的程序")
                return
            
            # 获取当前工具
            tool = self.state.getTool()
            if not tool:
                self.println("无法获取当前工具实例")
                return
            
            # 创建性能分析对话框
            dialog = PerformanceProfilerDialog(tool, program)
            dialog.setVisible(True)
            
        except Exception as e:
            self.println(f"运行脚本时出错: {e}")

# 主入口
if __name__ == "__main__":
    script = PerformanceProfilerScript()
    script.run()
