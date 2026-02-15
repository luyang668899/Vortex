#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CodeSizeOptimizer.py

分析代码大小并提供减小代码体积的建议，识别冗余代码。

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

class CodeSizeAnalysisResult:
    """
    代码大小分析结果类
    """
    def __init__(self):
        """
        初始化代码大小分析结果
        """
        self.function_sizes = {}
        self.unused_functions = []
        self.reduntant_code = []
        self.code_complexity = {}
        self.optimization_suggestions = []
        self.total_code_size = 0
    
    def add_function_size(self, function_name, size, address):
        """
        添加函数大小信息
        
        Args:
            function_name: 函数名
            size: 函数大小
            address: 函数地址
        """
        self.function_sizes[function_name] = {
            "size": size,
            "address": address
        }
        self.total_code_size += size
    
    def add_unused_function(self, function_name, size, address):
        """
        添加未使用的函数
        
        Args:
            function_name: 函数名
            size: 函数大小
            address: 函数地址
        """
        self.unused_functions.append({
            "name": function_name,
            "size": size,
            "address": address
        })
    
    def add_reduntant_code(self, function_name, address, reason, estimated_savings):
        """
        添加冗余代码
        
        Args:
            function_name: 函数名
            address: 代码地址
            reason: 冗余原因
            estimated_savings: 估计节省大小
        """
        self.reduntant_code.append({
            "function": function_name,
            "address": address,
            "reason": reason,
            "estimated_savings": estimated_savings
        })
    
    def add_code_complexity(self, function_name, complexity, size):
        """
        添加代码复杂度信息
        
        Args:
            function_name: 函数名
            complexity: 复杂度值
            size: 函数大小
        """
        self.code_complexity[function_name] = {
            "complexity": complexity,
            "size": size
        }
    
    def add_optimization_suggestion(self, function_name, suggestion, estimated_savings, severity):
        """
        添加优化建议
        
        Args:
            function_name: 函数名
            suggestion: 建议内容
            estimated_savings: 估计节省大小
            severity: 严重程度 (low, medium, high)
        """
        self.optimization_suggestions.append({
            "function": function_name,
            "suggestion": suggestion,
            "estimated_savings": estimated_savings,
            "severity": severity
        })
    
    def get_largest_functions(self, n=10):
        """
        获取最大的N个函数
        
        Args:
            n: 返回数量
        
        Returns:
            最大的N个函数列表
        """
        sorted_functions = sorted(
            self.function_sizes.items(),
            key=lambda x: x[1]["size"],
            reverse=True
        )
        return sorted_functions[:n]
    
    def get_unused_functions(self):
        """
        获取未使用的函数
        
        Returns:
            未使用的函数列表
        """
        return sorted(self.unused_functions, key=lambda x: x["size"], reverse=True)
    
    def get_reduntant_code(self):
        """
        获取冗余代码
        
        Returns:
            冗余代码列表
        """
        return sorted(self.reduntant_code, key=lambda x: x["estimated_savings"], reverse=True)
    
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
    
    def get_total_unused_size(self):
        """
        获取未使用函数的总大小
        
        Returns:
            未使用函数的总大小
        """
        return sum(f["size"] for f in self.unused_functions)
    
    def get_total_reduntant_size(self):
        """
        获取冗余代码的总大小
        
        Returns:
            冗余代码的总大小
        """
        return sum(r["estimated_savings"] for r in self.reduntant_code)
    
    def get_total_estimated_savings(self):
        """
        获取总估计节省大小
        
        Returns:
            总估计节省大小
        """
        return self.get_total_unused_size() + self.get_total_reduntant_size()
    
    def save_to_file(self, file_path):
        """
        保存分析结果到文件
        
        Args:
            file_path: 文件路径
        """
        try:
            data = {
                "function_sizes": self.function_sizes,
                "unused_functions": self.unused_functions,
                "reduntant_code": self.reduntant_code,
                "code_complexity": self.code_complexity,
                "optimization_suggestions": self.optimization_suggestions,
                "total_code_size": self.total_code_size
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
            
            self.function_sizes = data.get("function_sizes", {})
            self.unused_functions = data.get("unused_functions", [])
            self.reduntant_code = data.get("reduntant_code", [])
            self.code_complexity = data.get("code_complexity", {})
            self.optimization_suggestions = data.get("optimization_suggestions", [])
            self.total_code_size = data.get("total_code_size", 0)
            
            return True
        except Exception as e:
            print(f"加载分析结果时出错: {e}")
            return False

class CodeSizeAnalyzer:
    """
    代码大小分析器
    """
    def __init__(self, program):
        """
        初始化代码大小分析器
        
        Args:
            program: Ghidra程序实例
        """
        self.program = program
        self.result = CodeSizeAnalysisResult()
    
    def analyze_code_size(self):
        """
        分析代码大小
        
        Returns:
            代码大小分析结果
        """
        try:
            # 分析函数大小
            self._analyze_function_sizes()
            
            # 检测未使用的函数
            self._detect_unused_functions()
            
            # 检测冗余代码
            self._detect_reduntant_code()
            
            # 分析代码复杂度
            self._analyze_code_complexity()
            
            # 生成优化建议
            self._generate_optimization_suggestions()
            
            return self.result
        except Exception as e:
            print(f"分析代码大小时出错: {e}")
            return self.result
    
    def _analyze_function_sizes(self):
        """
        分析函数大小
        """
        try:
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                if body is not None:
                    size = body.getNumAddresses()
                    address = function.getEntryPoint()
                    self.result.add_function_size(function_name, size, address)
        except Exception as e:
            print(f"分析函数大小时出错: {e}")
    
    def _detect_unused_functions(self):
        """
        检测未使用的函数
        """
        try:
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            symbol_table = self.program.getSymbolTable()
            
            # 收集所有函数引用
            function_references = set()
            symbols = symbol_table.getAllSymbols()
            
            for symbol in symbols:
                if symbol.isExternal():  # 外部符号可能是导入的函数
                    continue
                
                # 检查符号是否被引用
                references = symbol_table.getReferencesTo(symbol.getAddress())
                for ref in references:
                    # 获取引用所在的函数
                    ref_function = function_manager.getFunctionContaining(ref.getFromAddress())
                    if ref_function:
                        function_references.add(ref_function.getName())
            
            # 检测未使用的函数
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                if body is not None:
                    size = body.getNumAddresses()
                    address = function.getEntryPoint()
                    
                    # 检查函数是否被引用
                    if function_name not in function_references:
                        # 检查函数是否是入口点或可能被动态调用
                        if not function.isThunk() and not function.isExternal():
                            self.result.add_unused_function(function_name, size, address)
        except Exception as e:
            print(f"检测未使用函数时出错: {e}")
    
    def _detect_reduntant_code(self):
        """
        检测冗余代码
        """
        try:
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                if body is None:
                    continue
                
                # 简单的冗余代码检测
                # 1. 检测重复的基本块
                block_model = BasicBlockModel(self.program)
                block_iterator = block_model.getCodeBlocksContaining(body, TaskMonitorAdapter.DUMMY_MONITOR)
                
                # 收集基本块内容哈希
                block_hashes = {}
                while block_iterator.hasNext():
                    block = block_iterator.next()
                    block_start = block.getStart()
                    block_end = block.getEnd()
                    
                    # 计算基本块内容哈希（简化处理）
                    block_size = block.getNumAddresses()
                    if block_size > 0:
                        # 这里使用地址和大小作为简单哈希，实际应该分析指令内容
                        block_key = f"{block_start}_{block_size}"
                        if block_key not in block_hashes:
                            block_hashes[block_key] = []
                        block_hashes[block_key].append(block_start)
                
                # 检测重复的基本块
                for block_key, addresses in block_hashes.items():
                    if len(addresses) > 1:
                        # 计算估计节省大小
                        # 假设每个重复块只保留一个
                        block_size = int(block_key.split("_")[1])
                        estimated_savings = block_size * (len(addresses) - 1)
                        
                        for address in addresses[1:]:  # 跳过第一个，标记其余为冗余
                            self.result.add_reduntant_code(
                                function_name,
                                address,
                                f"重复的基本块",
                                estimated_savings
                            )
                            break  # 每个重复组只添加一个建议
        except Exception as e:
            print(f"检测冗余代码时出错: {e}")
    
    def _analyze_code_complexity(self):
        """
        分析代码复杂度
        """
        try:
            function_manager = self.program.getFunctionManager()
            functions = function_manager.getFunctions(True)
            
            for function in functions:
                if function is None:
                    continue
                
                function_name = function.getName()
                body = function.getBody()
                
                if body is None:
                    continue
                
                size = body.getNumAddresses()
                
                # 计算简单的复杂度度量
                # 基于基本块数量的复杂度
                block_count = 0
                block_model = BasicBlockModel(self.program)
                block_iterator = block_model.getCodeBlocksContaining(body, TaskMonitorAdapter.DUMMY_MONITOR)
                
                while block_iterator.hasNext():
                    block_count += 1
                    block_iterator.next()
                
                # 简单的复杂度计算: 基本块数量
                complexity = block_count
                self.result.add_code_complexity(function_name, complexity, size)
        except Exception as e:
            print(f"分析代码复杂度时出错: {e}")
    
    def _generate_optimization_suggestions(self):
        """
        生成优化建议
        """
        try:
            # 基于函数大小生成建议
            largest_functions = self.result.get_largest_functions(20)
            for function_name, info in largest_functions:
                size = info["size"]
                
                if size > 1024:  # 大于1KB
                    self.result.add_optimization_suggestion(
                        function_name,
                        f"函数较大 ({size} bytes)，考虑拆分为多个小函数",
                        size // 2,  # 估计节省一半大小
                        "high"
                    )
                elif size > 512:  # 大于512 bytes
                    self.result.add_optimization_suggestion(
                        function_name,
                        f"函数中等大小 ({size} bytes)，考虑优化算法",
                        size // 4,  # 估计节省四分之一大小
                        "medium"
                    )
            
            # 基于未使用的函数生成建议
            for unused_function in self.result.unused_functions:
                function_name = unused_function["name"]
                size = unused_function["size"]
                
                self.result.add_optimization_suggestion(
                    function_name,
                    "函数未被使用，可以删除",
                    size,
                    "high"
                )
            
            # 基于冗余代码生成建议
            for redundant in self.result.reduntant_code:
                function_name = redundant["function"]
                reason = redundant["reason"]
                savings = redundant["estimated_savings"]
                
                self.result.add_optimization_suggestion(
                    function_name,
                    f"{reason}，可以优化",
                    savings,
                    "medium"
                )
            
            # 基于代码复杂度生成建议
            for function_name, info in self.result.code_complexity.items():
                complexity = info["complexity"]
                size = info["size"]
                
                if complexity > 20:  # 复杂度较高
                    self.result.add_optimization_suggestion(
                        function_name,
                        f"代码复杂度较高 ({complexity})，考虑重构",
                        size // 5,  # 估计节省五分之一大小
                        "medium"
                    )
            
            # 通用建议
            self.result.add_optimization_suggestion(
                "全局",
                "考虑使用更紧凑的数据类型",
                0,  # 无法估计具体节省
                "low"
            )
            
            self.result.add_optimization_suggestion(
                "全局",
                "移除未使用的变量和常量",
                0,  # 无法估计具体节省
                "low"
            )
            
            self.result.add_optimization_suggestion(
                "全局",
                "优化循环和条件分支",
                0,  # 无法估计具体节省
                "low"
            )
        except Exception as e:
            print(f"生成优化建议时出错: {e}")

class CodeSizeVisualizer:
    """
    代码大小可视化器
    """
    def __init__(self, analysis_result):
        """
        初始化代码大小可视化器
        
        Args:
            analysis_result: 代码大小分析结果
        """
        self.analysis_result = analysis_result
    
    def create_code_size_chart(self, parent):
        """
        创建代码大小图表
        
        Args:
            parent: 父组件
        
        Returns:
            代码大小图表面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建图表标题
        title_label = GLabel("代码大小分析")
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        panel.add(title_label, BorderLayout.NORTH)
        
        # 创建图表内容
        chart_content = GTextArea()
        chart_content.setEditable(False)
        
        # 添加代码大小统计
        total_size = self.analysis_result.total_code_size
        unused_size = self.analysis_result.get_total_unused_size()
        redundant_size = self.analysis_result.get_total_reduntant_size()
        estimated_savings = self.analysis_result.get_total_estimated_savings()
        
        chart_content.append("=== 代码大小统计 ===\n")
        chart_content.append(f"总代码大小: {total_size} bytes\n")
        chart_content.append(f"未使用函数大小: {unused_size} bytes ({unused_size/total_size*100:.2f}%)\n")
        chart_content.append(f"冗余代码大小: {redundant_size} bytes ({redundant_size/total_size*100:.2f}%)\n")
        chart_content.append(f"估计可节省大小: {estimated_savings} bytes ({estimated_savings/total_size*100:.2f}%)\n\n")
        
        # 添加最大的函数
        largest_functions = self.analysis_result.get_largest_functions(10)
        if largest_functions:
            chart_content.append("=== 最大的函数 ===\n")
            for i, (function_name, info) in enumerate(largest_functions, 1):
                size = info["size"]
                chart_content.append(f"{i}. {function_name}: {size} bytes\n")
            chart_content.append("\n")
        
        # 添加未使用的函数
        unused_functions = self.analysis_result.get_unused_functions()[:10]
        if unused_functions:
            chart_content.append("=== 未使用的函数 ===\n")
            for i, func in enumerate(unused_functions, 1):
                chart_content.append(f"{i}. {func['name']}: {func['size']} bytes\n")
            chart_content.append("\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(chart_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_optimization_chart(self, parent):
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
        title_label = GLabel("优化建议")
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
                for suggestion in high_suggestions[:10]:  # 只显示前10个
                    chart_content.append(f"函数: {suggestion['function']}\n")
                    chart_content.append(f"  建议: {suggestion['suggestion']}\n")
                    if suggestion['estimated_savings'] > 0:
                        chart_content.append(f"  估计节省: {suggestion['estimated_savings']} bytes\n")
                    chart_content.append("\n")
            
            if medium_suggestions:
                chart_content.append("=== 中优先级建议 ===\n")
                for suggestion in medium_suggestions[:10]:  # 只显示前10个
                    chart_content.append(f"函数: {suggestion['function']}\n")
                    chart_content.append(f"  建议: {suggestion['suggestion']}\n")
                    if suggestion['estimated_savings'] > 0:
                        chart_content.append(f"  估计节省: {suggestion['estimated_savings']} bytes\n")
                    chart_content.append("\n")
            
            if low_suggestions:
                chart_content.append("=== 低优先级建议 ===\n")
                for suggestion in low_suggestions[:10]:  # 只显示前10个
                    chart_content.append(f"函数: {suggestion['function']}\n")
                    chart_content.append(f"  建议: {suggestion['suggestion']}\n")
                    if suggestion['estimated_savings'] > 0:
                        chart_content.append(f"  估计节省: {suggestion['estimated_savings']} bytes\n")
                    chart_content.append("\n")
        else:
            chart_content.append("没有优化建议\n")
        
        # 添加滚动面板
        scroll_pane = JScrollPane(chart_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel

class CodeSizeOptimizerDialog(GDialog):
    """
    代码大小优化对话框
    """
    def __init__(self, tool, program):
        """
        初始化代码大小优化对话框
        
        Args:
            tool: Ghidra工具实例
            program: Ghidra程序实例
        """
        super(CodeSizeOptimizerDialog, self).__init__(tool.getWindow(), "代码大小优化器", True)
        self.tool = tool
        self.program = program
        self.analyzer = CodeSizeAnalyzer(program)
        self.analysis_result = CodeSizeAnalysisResult()
        
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
        
        # 添加函数大小标签页
        self.function_size_panel = self.create_function_size_panel()
        tabbed_pane.addTab("函数大小", self.function_size_panel)
        
        # 添加未使用函数标签页
        self.unused_functions_panel = self.create_unused_functions_panel()
        tabbed_pane.addTab("未使用函数", self.unused_functions_panel)
        
        # 添加冗余代码标签页
        self.redundant_code_panel = self.create_redundant_code_panel()
        tabbed_pane.addTab("冗余代码", self.redundant_code_panel)
        
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
        self.analyze_button = GButton("开始代码大小分析")
        self.analyze_button.addActionListener(lambda e: self.analyze_code_size())
        panel.add(self.analyze_button, gbc)
        
        # 保存结果按钮
        gbc.gridx = 0
        gbc.gridy = 1
        gbc.gridwidth = 1
        gbc.weightx = 0.5
        save_button = GButton("保存分析结果")
        
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
        
        save_button.addActionListener(on_save)
        panel.add(save_button, gbc)
        
        # 加载结果按钮
        gbc.gridx = 1
        gbc.gridy = 1
        gbc.gridwidth = 1
        gbc.weightx = 0.5
        load_button = GButton("加载分析结果")
        
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
        
        load_button.addActionListener(on_load)
        panel.add(load_button, gbc)
        
        return panel
    
    def create_function_size_panel(self):
        """
        创建函数大小面板
        
        Returns:
            函数大小面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建函数大小表格
        column_names = ["函数名", "大小", "地址"]
        self.function_size_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.function_size_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_unused_functions_panel(self):
        """
        创建未使用函数面板
        
        Returns:
            未使用函数面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建未使用函数表格
        column_names = ["函数名", "大小", "地址"]
        self.unused_functions_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.unused_functions_table)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_redundant_code_panel(self):
        """
        创建冗余代码面板
        
        Returns:
            冗余代码面板
        """
        panel = GPanel()
        panel.setLayout(BorderLayout())
        
        # 创建冗余代码表格
        column_names = ["函数名", "地址", "原因", "估计节省大小"]
        self.redundant_code_table = GTable([], column_names)
        
        # 添加滚动面板
        scroll_pane = JScrollPane(self.redundant_code_table)
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
        column_names = ["函数名", "建议", "估计节省大小", "严重程度"]
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
        default_label = GLabel("点击 '开始代码大小分析' 按钮查看代码大小可视化")
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
    
    def analyze_code_size(self):
        """
        分析代码大小
        """
        try:
            # 显示分析进度
            JOptionPane.showMessageDialog(self, "开始代码大小分析，请稍候...", "信息", JOptionPane.INFORMATION_MESSAGE)
            
            # 执行代码大小分析
            self.analysis_result = self.analyzer.analyze_code_size()
            
            # 刷新面板
            self.refresh_panels()
            
            JOptionPane.showMessageDialog(self, "代码大小分析完成", "成功", JOptionPane.INFORMATION_MESSAGE)
        except Exception as e:
            JOptionPane.showMessageDialog(self, f"分析代码大小时出错: {e}", "错误", JOptionPane.ERROR_MESSAGE)
    
    def refresh_panels(self):
        """
        刷新所有面板
        """
        # 刷新函数大小面板
        self.refresh_function_size_panel()
        
        # 刷新未使用函数面板
        self.refresh_unused_functions_panel()
        
        # 刷新冗余代码面板
        self.refresh_redundant_code_panel()
        
        # 刷新优化建议面板
        self.refresh_optimization_panel()
        
        # 刷新可视化面板
        self.refresh_visualization_panel()
        
        # 刷新报告面板
        self.refresh_report_panel()
    
    def refresh_function_size_panel(self):
        """
        刷新函数大小面板
        """
        # 更新函数大小表格
        model = DefaultTableModel([], ["函数名", "大小", "地址"])
        sorted_functions = sorted(
            self.analysis_result.function_sizes.items(),
            key=lambda x: x[1]["size"],
            reverse=True
        )
        
        for function_name, info in sorted_functions[:100]:  # 只显示前100个
            model.addRow([
                function_name,
                info["size"],
                info["address"]
            ])
        
        self.function_size_table.setModel(model)
    
    def refresh_unused_functions_panel(self):
        """
        刷新未使用函数面板
        """
        # 更新未使用函数表格
        model = DefaultTableModel([], ["函数名", "大小", "地址"])
        unused_functions = self.analysis_result.get_unused_functions()
        
        for func in unused_functions[:100]:  # 只显示前100个
            model.addRow([
                func["name"],
                func["size"],
                func["address"]
            ])
        
        self.unused_functions_table.setModel(model)
    
    def refresh_redundant_code_panel(self):
        """
        刷新冗余代码面板
        """
        # 更新冗余代码表格
        model = DefaultTableModel([], ["函数名", "地址", "原因", "估计节省大小"])
        redundant_code = self.analysis_result.get_reduntant_code()
        
        for code in redundant_code[:100]:  # 只显示前100个
            model.addRow([
                code["function"],
                code["address"],
                code["reason"],
                code["estimated_savings"]
            ])
        
        self.redundant_code_table.setModel(model)
    
    def refresh_optimization_panel(self):
        """
        刷新优化建议面板
        """
        # 更新优化建议表格
        model = DefaultTableModel([], ["函数名", "建议", "估计节省大小", "严重程度"])
        suggestions = self.analysis_result.get_optimization_suggestions()
        
        for suggestion in suggestions[:100]:  # 只显示前100个
            model.addRow([
                suggestion["function"],
                suggestion["suggestion"],
                suggestion["estimated_savings"],
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
        visualizer = CodeSizeVisualizer(self.analysis_result)
        
        # 创建代码大小图表
        chart_panel = visualizer.create_code_size_chart(self)
        
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
        self.report_text.append("=== 代码大小分析报告 ===\n\n")
        self.report_text.append(f"分析时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.report_text.append(f"程序: {self.program.getName()}\n\n")
        
        # 添加代码大小统计
        total_size = self.analysis_result.total_code_size
        unused_size = self.analysis_result.get_total_unused_size()
        redundant_size = self.analysis_result.get_total_reduntant_size()
        estimated_savings = self.analysis_result.get_total_estimated_savings()
        
        self.report_text.append("=== 代码大小统计 ===\n")
        self.report_text.append(f"总代码大小: {total_size} bytes\n")
        self.report_text.append(f"未使用函数大小: {unused_size} bytes ({unused_size/total_size*100:.2f}%)\n")
        self.report_text.append(f"冗余代码大小: {redundant_size} bytes ({redundant_size/total_size*100:.2f}%)\n")
        self.report_text.append(f"估计可节省大小: {estimated_savings} bytes ({estimated_savings/total_size*100:.2f}%)\n\n")
        
        # 添加最大的函数
        largest_functions = self.analysis_result.get_largest_functions(10)
        if largest_functions:
            self.report_text.append("=== 最大的函数 ===\n")
            for i, (function_name, info) in enumerate(largest_functions, 1):
                size = info["size"]
                self.report_text.append(f"{i}. {function_name}: {size} bytes\n")
            self.report_text.append("\n")
        
        # 添加未使用的函数
        unused_functions = self.analysis_result.get_unused_functions()[:10]
        if unused_functions:
            self.report_text.append("=== 未使用的函数 ===\n")
            for i, func in enumerate(unused_functions, 1):
                self.report_text.append(f"{i}. {func['name']}: {func['size']} bytes\n")
            self.report_text.append("\n")
        
        # 添加冗余代码
        redundant_code = self.analysis_result.get_reduntant_code()[:10]
        if redundant_code:
            self.report_text.append("=== 冗余代码 ===\n")
            for i, code in enumerate(redundant_code, 1):
                self.report_text.append(f"{i}. 函数: {code['function']}\n")
                self.report_text.append(f"   原因: {code['reason']}\n")
                self.report_text.append(f"   估计节省: {code['estimated_savings']} bytes\n")
            self.report_text.append("\n")
        
        # 添加优化建议
        suggestions = self.analysis_result.get_optimization_suggestions()
        if suggestions:
            # 按严重程度分组
            high_suggestions = [s for s in suggestions if s["severity"] == "high"]
            medium_suggestions = [s for s in suggestions if s["severity"] == "medium"]
            
            if high_suggestions:
                self.report_text.append("=== 高优先级优化建议 ===\n")
                for suggestion in high_suggestions[:10]:
                    self.report_text.append(f"函数: {suggestion['function']}\n")
                    self.report_text.append(f"  建议: {suggestion['suggestion']}\n")
                    if suggestion['estimated_savings'] > 0:
                        self.report_text.append(f"  估计节省: {suggestion['estimated_savings']} bytes\n")
                    self.report_text.append("\n")
            
            if medium_suggestions:
                self.report_text.append("=== 中优先级优化建议 ===\n")
                for suggestion in medium_suggestions[:10]:
                    self.report_text.append(f"函数: {suggestion['function']}\n")
                    self.report_text.append(f"  建议: {suggestion['suggestion']}\n")
                    if suggestion['estimated_savings'] > 0:
                        self.report_text.append(f"  估计节省: {suggestion['estimated_savings']} bytes\n")
                    self.report_text.append("\n")

class CodeSizeOptimizerScript(GhidraScript):
    """
    代码大小优化脚本
    """
    def __init__(self):
        """
        初始化脚本
        """
        super(CodeSizeOptimizerScript, self).__init__()
    
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
            
            # 创建代码大小优化对话框
            dialog = CodeSizeOptimizerDialog(tool, program)
            dialog.setVisible(True)
            
        except Exception as e:
            self.println(f"运行脚本时出错: {e}")

# 主入口
if __name__ == "__main__":
    script = CodeSizeOptimizerScript()
    script.run()
