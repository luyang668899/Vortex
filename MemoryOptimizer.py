#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MemoryOptimizer.py

分析内存使用模式并提供优化建议，识别内存泄漏。

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
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.pcode import PcodeOpAST
    from ghidra.program.model.pcode import HighFunction
    from ghidra.program.model.pcode import HighParam
    from ghidra.program.model.pcode import HighLocal
    from ghidra.program.model.data import DataType
    from ghidra.program.model.data import DataTypeManager
    from ghidra.program.model.data import Structure
    from ghidra.program.model.data import Union
    from ghidra.program.model.data import Array
    from ghidra.program.model.data import Pointer
    from ghidra.program.model.data import StringDataType
    from ghidra.program.model.data import IntegerDataType
    from ghidra.program.model.data import BooleanDataType
    from ghidra.program.model.data import FloatDataType
    from ghidra.program.model.data import DoubleDataType
except Exception as e:
    print(f"导入模块时出错: {e}")

class MemoryAnalysisResult:
    """
    内存分析结果类
    """
    def __init__(self):
        """
        初始化内存分析结果
        """
        self.memory_allocations = []
        self.memory_frees = []
        self.potential_leaks = []
        self.memory_hotspots = []
        self.optimization_suggestions = []
    
    def add_memory_allocation(self, address, size, function, context):
        """
        添加内存分配记录
        
        Args:
            address: 分配地址
            size: 分配大小
            function: 函数名
            context: 上下文信息
        """
        self.memory_allocations.append({
            "address": address,
            "size": size,
            "function": function,
            "context": context
        })
    
    def add_memory_free(self, address, function, context):
        """
        添加内存释放记录
        
        Args:
            address: 释放地址
            function: 函数名
            context: 上下文信息
        """
        self.memory_frees.append({
            "address": address,
            "function": function,
            "context": context
        })
    
    def add_potential_leak(self, address, size, function, reason):
        """
        添加潜在内存泄漏
        
        Args:
            address: 泄漏地址
            size: 泄漏大小
            function: 函数名
            reason: 泄漏原因
        """
        self.potential_leaks.append({
            "address": address,
            "size": size,
            "function": function,
            "reason": reason
        })
    
    def add_memory_hotspot(self, function, allocation_count, total_size):
        """
        添加内存使用热点
        
        Args:
            function: 函数名
            allocation_count: 分配次数
            total_size: 总分配大小
        """
        self.memory_hotspots.append({
            "function": function,
            "allocation_count": allocation_count,
            "total_size": total_size
        })
    
    def add_optimization_suggestion(self, function, suggestion, severity):
        """
        添加优化建议
        
        Args:
            function: 函数名
            suggestion: 建议内容
            severity: 严重程度 (low, medium, high)
        """
        self.optimization_suggestions.append({
            "function": function,
            "suggestion": suggestion,
            "severity": severity
        })
    
    def get_total_allocations(self):
        """
        获取总内存分配次数
        
        Returns:
            总分配次数
        """
        return len(self.memory_allocations)
    
    def get_total_frees(self):
        """
        获取总内存释放次数
        
        Returns:
            总释放次数
        """
        return len(self.memory_frees)
    
    def get_total_leaks(self):
        """
        获取潜在内存泄漏数量
        
        Returns:
            潜在内存泄漏数量
        """
        return len(self.potential_leaks)
    
    def get_top_hotspots(self, n=10):
        """
        获取内存使用热点前N名
        
        Args:
            n: 返回数量
        
        Returns:
            内存使用热点列表
        """
        sorted_hotspots = sorted(self.memory_hotspots, key=lambda x: x["total_size"], reverse=True)
        return sorted_hotspots[:n]
    
    def get_optimization_suggestions(self, severity=None):
        """
        获取优化建议
        
        Args:
            severity: 严重程度过滤
        
        Returns:
            优化建议列表
        """
        if severity:
            return [s for s in self.optimization_suggestions if s["severity"] == severity]
        return self.optimization_suggestions
    
    def save_to_file(self, file_path):
        """
        保存分析结果到文件
        
        Args:
            file_path: 文件路径
        """
        try:
            data = {
                "memory_allocations": self.memory_allocations,
                "memory_frees": self.memory_frees,
                "potential_leaks": self.potential_leaks,
                "memory_hotspots": self.memory_hotspots,
                "optimization_suggestions": self.optimization_suggestions
            }
            
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            print(f"保存分析结果时出错: {e}")
            return False
    
    def load_from_file(self, file_path):
        """
        从文件加载分析结果
        
        Args:
            file_path: 文件路径
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self.memory_allocations = data.get("memory_allocations", [])
            self.memory_frees = data.get("memory_frees", [])
            self.potential_leaks = data.get("potential_leaks", [])
            self.memory_hotspots = data.get("memory_hotspots", [])
            self.optimization_suggestions = data.get("optimization_suggestions", [])
            
            return True
        except Exception as e:
            print(f"加载分析结果时出错: {e}")
            return False

class MemoryAnalyzer:
    """
    内存分析器
    """
    def __init__(self, program):
        """
        初始化内存分析器
        
        Args:
            program: Ghidra程序实例
        """
        self.program = program
        self.result = MemoryAnalysisResult()
    
    def analyze_memory_usage(self):
        """
        分析内存使用情况
        
        Returns:
            内存分析结果
        """
        try:
            # 分析内存分配和释放
            self._analyze_memory_operations()
            
            # 检测内存泄漏
            self._detect_memory_leaks()
            
            # 分析内存热点
            self._analyze_memory_hotspots()
            
            # 生成优化建议
            self._generate_optimization_suggestions()
            
            return self.result
        except Exception as e:
            print(f"分析内存使用时出错: {e}")
            return self.result
    
    def _analyze_memory_operations(self):
        """
        分析内存分配和释放操作
        """
        try:
            listing = self.program.getListing()
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            # 常见的内存分配函数
            allocation_functions = {
                "malloc": 1,      # size参数位置
                "calloc": 2,      # count, size参数位置
                "realloc": 2,     # ptr, size参数位置
                "new": 0,         # C++ new操作符
                "operator new": 1  # C++ operator new
            }
            
            # 常见的内存释放函数
            free_functions = {
                "free": 1,         # ptr参数位置
                "delete": 0,       # C++ delete操作符
                "operator delete": 1  # C++ operator delete
            }
            
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                if body is None:
                    continue
                
                # 分析函数中的内存操作
                try:
                    # 获取函数的Pcode
                    high_function = HighFunction.getHighFunction(function)
                    if high_function:
                        # 遍历Pcode操作
                        for block in high_function.getBasicBlocks():
                            for pcode_op in block.getIterator():
                                # 检查是否是函数调用
                                if pcode_op.getOpcode() == PcodeOp.CALL:
                                    # 获取调用目标
                                    target = pcode_op.getInput(0)
                                    if target.isConstant():
                                        target_addr = target.getAddress()
                                        # 获取目标函数名
                                        target_function = function_manager.getFunctionContaining(target_addr)
                                        if target_function:
                                            called_function_name = target_function.getName()
                                            
                                            # 检查是否是内存分配函数
                                            if called_function_name in allocation_functions:
                                                # 尝试获取分配大小
                                                size_param_index = allocation_functions[called_function_name]
                                                if size_param_index > 0 and pcode_op.getNumInputs() > size_param_index:
                                                    size_input = pcode_op.getInput(size_param_index)
                                                    # 简化处理，实际需要更复杂的分析
                                                    size = 0
                                                    if size_input.isConstant():
                                                        size = size_input.getOffset()
                                                    
                                                    self.result.add_memory_allocation(
                                                        pcode_op.getAddress(),
                                                        size,
                                                        function_name,
                                                        f"调用 {called_function_name}"
                                                    )
                                            
                                            # 检查是否是内存释放函数
                                            if called_function_name in free_functions:
                                                self.result.add_memory_free(
                                                    pcode_op.getAddress(),
                                                    function_name,
                                                    f"调用 {called_function_name}"
                                                )
                except Exception as e:
                    # 忽略单个函数分析错误
                    pass
        except Exception as e:
            print(f"分析内存操作时出错: {e}")
    
    def _detect_memory_leaks(self):
        """
        检测潜在的内存泄漏
        """
        try:
            # 简单的泄漏检测逻辑
            # 实际需要更复杂的数据流分析
            
            # 统计每个函数的分配和释放次数
            function_allocations = {}
            function_frees = {}
            
            for alloc in self.result.memory_allocations:
                function = alloc["function"]
                if function not in function_allocations:
                    function_allocations[function] = 0
                function_allocations[function] += 1
            
            for free in self.result.memory_frees:
                function = free["function"]
                if function not in function_frees:
                    function_frees[function] = 0
                function_frees[function] += 1
            
            # 检查分配次数大于释放次数的函数
            for function, alloc_count in function_allocations.items():
                free_count = function_frees.get(function, 0)
                if alloc_count > free_count:
                    # 模拟泄漏检测结果
                    self.result.add_potential_leak(
                        "0x0",  # 模拟地址
                        0,       # 模拟大小
                        function,
                        f"分配次数({alloc_count})大于释放次数({free_count})"
                    )
        except Exception as e:
            print(f"检测内存泄漏时出错: {e}")
    
    def _analyze_memory_hotspots(self):
        """
        分析内存使用热点
        """
        try:
            # 统计每个函数的内存分配情况
            function_memory = {}
            
            for alloc in self.result.memory_allocations:
                function = alloc["function"]
                size = alloc["size"]
                
                if function not in function_memory:
                    function_memory[function] = {
                        "allocation_count": 0,
                        "total_size": 0
                    }
                
                function_memory[function]["allocation_count"] += 1
                function_memory[function]["total_size"] += size
            
            # 添加内存热点
            for function, stats in function_memory.items():
                if stats["total_size"] > 0:
                    self.result.add_memory_hotspot(
                        function,
                        stats["allocation_count"],
                        stats["total_size"]
                    )
        except Exception as e:
            print(f"分析内存热点时出错: {e}")
    
    def _generate_optimization_suggestions(self):
        """
        生成内存优化建议
        """
        try:
            # 基于内存热点生成建议
            hotspots = self.result.get_top_hotspots(10)
            for hotspot in hotspots:
                if hotspot["total_size"] > 1024 * 1024:  # 大于1MB
                    self.result.add_optimization_suggestion(
                        hotspot["function"],
                        f"函数内存分配较大 ({hotspot['total_size']} bytes)，考虑使用内存池或缓存",
                        "high"
                    )
                elif hotspot["allocation_count"] > 100:
                    self.result.add_optimization_suggestion(
                        hotspot["function"],
                        f"函数内存分配次数较多 ({hotspot['allocation_count']} 次)，考虑减少分配次数",
                        "medium"
                    )
            
            # 基于泄漏检测生成建议
            for leak in self.result.potential_leaks:
                self.result.add_optimization_suggestion(
                    leak["function"],
                    f"潜在内存泄漏: {leak['reason']}",
                    "high"
                )
            
            # 通用建议
            self.result.add_optimization_suggestion(
                "全局",
                "考虑使用智能指针或RAII模式管理内存",
                "medium"
            )
            
            self.result.add_optimization_suggestion(
                "全局",
                "对于频繁分配的小对象，考虑使用对象池",
                "medium"
            )
            
            self.result.add_optimization_suggestion(
                "全局",
                "检查是否有不必要的大内存分配",
                "low"
            )
        except Exception as e:
            print(f"生成优化建议时出错: {e}")

class MemoryVisualizer:
    """
    内存使用可视化器
    """
    def __init__(self, analysis_result):
        """
        初始化内存可视化器
        
        Args:
            analysis_result: 内存分析结果
        """
        self.analysis_result = analysis_result
    
    def create_memory_usage_chart(self, parent):
        """
        创建内存使用图表
        
        Args:
            parent: 父组件
        
        Returns:
            内存使用图表面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建图表标题
        title_label = GLabel("内存使用分析")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        panel.add(title_label, BorderLayout.NORTH)
        
        # 创建图表内容
        chart_content = GTextArea()
        chart_content.setEditable(False)
        
        # 添加内存分配统计
        total_allocations = len(self.analysis_result.memory_allocations)
        total_frees = len(self.analysis_result.memory_frees)
        total_leaks = len(self.analysis_result.potential_leaks)
        
        chart_content.append("=== 内存操作统计 ===\n")
        chart_content.append(f"总内存分配次数: {total_allocations}\n")
        chart_content.append(f"总内存释放次数: {total_frees}\n")
        chart_content.append(f"潜在内存泄漏数: {total_leaks}\n\n")
        
        # 添加内存热点
        hotspots = self.analysis_result.get_top_hotspots(10)
        if hotspots:
            chart_content.append("=== 内存使用热点 ===\n")
            for i, hotspot in enumerate(hotspots, 1):
                chart_content.append(f"{i}. {hotspot['function']}:\n")
                chart_content.append(f"  分配次数: {hotspot['allocation_count']}\n")
                chart_content.append(f"  总分配大小: {hotspot['total_size']} bytes\n\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(chart_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_leak_analysis_chart(self, parent):
        """
        创建内存泄漏分析图表
        
        Args:
            parent: 父组件
        
        Returns:
            内存泄漏分析图表面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建图表标题
        title_label = GLabel("内存泄漏分析")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        panel.add(title_label, BorderLayout.NORTH)
        
        # 创建图表内容
        chart_content = GTextArea()
        chart_content.setEditable(False)
        
        # 添加内存泄漏信息
        leaks = self.analysis_result.potential_leaks
        if leaks:
            chart_content.append("=== 潜在内存泄漏 ===\n")
            for i, leak in enumerate(leaks, 1):
                chart_content.append(f"{i}. 函数: {leak['function']}\n")
                chart_content.append(f"   地址: {leak['address']}\n")
                chart_content.append(f"   大小: {leak['size']} bytes\n")
                chart_content.append(f"   原因: {leak['reason']}\n\n")
        else:
            chart_content.append("未检测到潜在内存泄漏\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(chart_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_optimization_suggestions_chart(self, parent):
        """
        创建优化建议图表
        
        Args:
            parent: 父组件
        
        Returns:
            优化建议图表面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建图表标题
        title_label = GLabel("内存优化建议")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        panel.add(title_label, BorderLayout.NORTH)
        
        # 创建图表内容
        chart_content = GTextArea()
        chart_content.setEditable(False)
        
        # 添加优化建议
        suggestions = self.analysis_result.get_optimization_suggestions()
        if suggestions:
            # 按严重程度分组
            high_suggestions = [s for s in suggestions if s["severity"] == "high"]
            medium_suggestions = [s for s in suggestions if s["severity"] == "medium"]
            low_suggestions = [s for s in suggestions if s["severity"] == "low"]
            
            if high_suggestions:
                chart_content.append("=== 高优先级建议 ===\n")
                for suggestion in high_suggestions:
                    chart_content.append(f"函数: {suggestion['function']}\n")
                    chart_content.append(f"  建议: {suggestion['suggestion']}\n\n")
            
            if medium_suggestions:
                chart_content.append("=== 中优先级建议 ===\n")
                for suggestion in medium_suggestions:
                    chart_content.append(f"函数: {suggestion['function']}\n")
                    chart_content.append(f"  建议: {suggestion['suggestion']}\n\n")
            
            if low_suggestions:
                chart_content.append("=== 低优先级建议 ===\n")
                for suggestion in low_suggestions:
                    chart_content.append(f"函数: {suggestion['function']}\n")
                    chart_content.append(f"  建议: {suggestion['suggestion']}\n\n")
        else:
            chart_content.append("没有优化建议\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(chart_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel

class MemoryOptimizerDialog(GDialog):
    """
    内存优化对话框
    """
    def __init__(self, tool, program):
        """
        初始化内存优化对话框
        
        Args:
            tool: Ghidra工具实例
            program: Ghidra程序实例
        """
        super(MemoryOptimizerDialog, self).__init__(tool.getWindow(), "内存优化器", True)
        self.tool = tool
        self.program = program
        self.analyzer = MemoryAnalyzer(program)
        self.analysis_result = MemoryAnalysisResult()
        
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
        
        # 添加内存使用标签页
        self.memory_usage_panel = self.create_memory_usage_panel()
        tabbed_pane.addTab("内存使用", self.memory_usage_panel)
        
        # 添加泄漏分析标签页
        self.leak_analysis_panel = self.create_leak_analysis_panel()
        tabbed_pane.addTab("泄漏分析", self.leak_analysis_panel)
        
        # 添加优化建议标签页
        self.optimization_panel = self.create_optimization_panel()
        tabbed_pane.addTab("优化建议", self.optimization_panel)
        
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
        self.analyze_button = GButton("开始内存分析")
        self.analyze_button.addActionListener(lambda e: self.analyze_memory())
        panel.add(self.analyze_button, gbc)
        
        # 保存结果按钮
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 1
        gbc.weightx = 0.5
        class JSONFileFilter(FileFilter):
            def accept(self, f):
                return f.isDirectory() or f.getName().endswith(".json")
            
            def getDescription(self):
                return "JSON文件 (*.json)"
        
        def on_save(e):
            file_chooser = GFileChooser()
            file_chooser.setDialogTitle("保存分析结果")
            file_chooser.setFileFilter(JSONFileFilter())
            
            result = file_chooser.showSaveDialog(self)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                # 确保文件扩展名为.json
                if not file_path.endswith(".json"):
                    file_path += ".json"
                
                success = self.analysis_result.save_to_file(file_path)
                if success:
                    JOptionPane.showMessageDialog(self, f"成功保存分析结果到: {file_path}", "成功", JOptionPane.INFORMATION_MESSAGE)
                else:
                    JOptionPane.showMessageDialog(self, "保存分析结果失败", "错误", JOptionPane.ERROR_MESSAGE)
        
        save_button = GButton("保存分析结果")
        save_button.addActionListener(on_save)
        panel.add(save_button, gbc)
        
        # 加载结果按钮
        gbc.gridx = 1
        gbc.gridy = 1
        gbc.gridwidth = 1
        gbc.weightx = 0.5
        def on_load(e):
            file_chooser = GFileChooser()
            file_chooser.setDialogTitle("加载分析结果")
            file_chooser.setFileFilter(JSONFileFilter())
            
            result = file_chooser.showOpenDialog(self)
            if result == JFileChooser.APPROVE_OPTION:
                selected_file = file_chooser.getSelectedFile()
                file_path = selected_file.getAbsolutePath()
                
                success = self.analysis_result.load_from_file(file_path)
                if success:
                    JOptionPane.showMessageDialog(self, f"成功加载分析结果从: {file_path}", "成功", JOptionPane.INFORMATION_MESSAGE)
                    # 刷新面板
                    self.refresh_panels()
                else:
                    JOptionPane.showMessageDialog(self, "加载分析结果失败", "错误", JOptionPane.ERROR_MESSAGE)
        
        load_button = GButton("加载分析结果")
        load_button.addActionListener(on_load)
        panel.add(load_button, gbc)
        
        return panel
    
    def create_memory_usage_panel(self):
        """
        创建内存使用面板
        
        Returns:
            内存使用面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建内存使用表格
        column_names = ["地址", "大小", "函数", "上下文"]
        self.memory_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.memory_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_leak_analysis_panel(self):
        """
        创建泄漏分析面板
        
        Returns:
            泄漏分析面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建泄漏分析表格
        column_names = ["地址", "大小", "函数", "原因"]
        self.leak_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.leak_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_optimization_panel(self):
        """
        创建优化建议面板
        
        Returns:
            优化建议面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建优化建议表格
        column_names = ["函数", "建议", "严重程度"]
        self.optimization_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.optimization_table)
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
        
        # 创建可视化内容面板
        self.visualization_content = GPanel()
        self.visualization_content.setLayout(BorderLayout())
        
        # 添加默认提示
        default_label = GLabel("点击 '开始内存分析' 按钮查看内存使用可视化")
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
        
        # 创建报告内容
        self.report_text = GTextArea()
        self.report_text.setEditable(False)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.report_text)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def analyze_memory(self):
        """
        分析内存使用
        """
        try:
            # 显示分析进度
            JOptionPane.showMessageDialog(self, "开始内存分析，请稍候...", "信息", JOptionPane.INFORMATION_MESSAGE)
            
            # 执行内存分析
            self.analysis_result = self.analyzer.analyze_memory_usage()
            
            # 刷新面板
            self.refresh_panels()
            
            JOptionPane.showMessageDialog(self, "内存分析完成", "成功", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self, f"分析内存使用时出错: {e}", "错误", JOptionPane.ERROR_MESSAGE)
    
    def refresh_panels(self):
        """
        刷新所有面板
        """
        # 刷新内存使用面板
        self.refresh_memory_usage_panel()
        
        # 刷新泄漏分析面板
        self.refresh_leak_analysis_panel()
        
        # 刷新优化建议面板
        self.refresh_optimization_panel()
        
        # 刷新可视化面板
        self.refresh_visualization_panel()
        
        # 刷新报告面板
        self.refresh_report_panel()
    
    def refresh_memory_usage_panel(self):
        """
        刷新内存使用面板
        """
        # 更新内存使用表格
        model = DefaultTableModel([], ["地址", "大小", "函数", "上下文"])
        for alloc in self.analysis_result.memory_allocations[:100]:  # 只显示前100条
            model.addRow([
                alloc["address"],
                alloc["size"],
                alloc["function"],
                alloc["context"]
            ])
        
        self.memory_table.setModel(model)
    
    def refresh_leak_analysis_panel(self):
        """
        刷新泄漏分析面板
        """
        # 更新泄漏分析表格
        model = DefaultTableModel([], ["地址", "大小", "函数", "原因"])
        for leak in self.analysis_result.potential_leaks:
            model.addRow([
                leak["address"],
                leak["size"],
                leak["function"],
                leak["reason"]
            ])
        
        self.leak_table.setModel(model)
    
    def refresh_optimization_panel(self):
        """
        刷新优化建议面板
        """
        # 更新优化建议表格
        model = DefaultTableModel([], ["函数", "建议", "严重程度"])
        for suggestion in self.analysis_result.optimization_suggestions:
            model.addRow([
                suggestion["function"],
                suggestion["suggestion"],
                suggestion["severity"]
            ])
        
        self.optimization_table.setModel(model)
    
    def refresh_visualization_panel(self):
        """
        刷新可视化面板
        """
        # 清除现有内容
        self.visualization_content.removeAll()
        
        # 创建可视化器
        visualizer = MemoryVisualizer(self.analysis_result)
        
        # 创建内存使用图表
        chart_panel = visualizer.create_memory_usage_chart(self)
        
        # 添加到内容面板
        self.visualization_content.add(chart_panel, BorderLayout.CENTER)
        
        # 刷新面板
        self.visualization_content.revalidate()
        self.visualization_content.repaint()
    
    def refresh_report_panel(self):
        """
        刷新报告面板
        """
        # 清空现有内容
        self.report_text.setText("")
        
        # 添加报告内容
        self.report_text.append("=== 内存分析报告 ===\n\n")
        self.report_text.append(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.report_text.append(f"程序: {self.program.getName()}\n\n")
        
        # 添加内存操作统计
        self.report_text.append("=== 内存操作统计 ===\n")
        self.report_text.append(f"总内存分配次数: {len(self.analysis_result.memory_allocations)}\n")
        self.report_text.append(f"总内存释放次数: {len(self.analysis_result.memory_frees)}\n")
        self.report_text.append(f"潜在内存泄漏数: {len(self.analysis_result.potential_leaks)}\n\n")
        
        # 添加内存泄漏分析
        leaks = self.analysis_result.potential_leaks
        if leaks:
            self.report_text.append("=== 内存泄漏分析 ===\n")
            for leak in leaks:
                self.report_text.append(f"函数: {leak['function']}\n")
                self.report_text.append(f"  原因: {leak['reason']}\n\n")
        
        # 添加内存热点分析
        hotspots = self.analysis_result.get_top_hotspots(10)
        if hotspots:
            self.report_text.append("=== 内存热点分析 ===\n")
            for i, hotspot in enumerate(hotspots, 1):
                self.report_text.append(f"{i}. {hotspot['function']}:\n")
                self.report_text.append(f"  分配次数: {hotspot['allocation_count']}\n")
                self.report_text.append(f"  总分配大小: {hotspot['total_size']} bytes\n\n")
        
        # 添加优化建议
        suggestions = self.analysis_result.get_optimization_suggestions()
        if suggestions:
            self.report_text.append("=== 优化建议 ===\n")
            for suggestion in suggestions:
                self.report_text.append(f"[{suggestion['severity'].upper()}] {suggestion['function']}:\n")
                self.report_text.append(f"  {suggestion['suggestion']}\n\n")

class MemoryOptimizerScript(GhidraScript):
    """
    内存优化脚本
    """
    def __init__(self):
        """
        初始化脚本
        """
        super(MemoryOptimizerScript, self).__init__()
    
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
            
            # 创建内存优化对话框
            dialog = MemoryOptimizerDialog(tool, program)
            dialog.setVisible(True)
            
        except Exception as e:
            self.println(f"运行脚本时出错: {e}")

# 主入口
if __name__ == "__main__":
    script = MemoryOptimizerScript()
    script.run()
