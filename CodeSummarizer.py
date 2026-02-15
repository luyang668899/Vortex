#!/usr/bin/env python3
# CodeSummarizer.py - 自动生成函数和代码块的自然语言摘要
# 功能：分析函数和代码块，生成自然语言摘要，帮助理解代码功能

import os
import json
import re
from datetime import datetime
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Dimension
from java.awt.event import ActionListener, ItemListener
from javax.swing import (
    JFrame, JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, 
    JCheckBox, JLabel, JComboBox, JTextField, JOptionPane, JTable, 
    DefaultTableModel, JFileChooser, JProgressBar, JMenuBar, JMenu, JMenuItem,
    BoxLayout, BorderFactory, JTree, DefaultMutableTreeNode, JSplitPane,
    JToolBar, JToggleButton, JPopupMenu
)
from javax.swing.border import LineBorder
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import Symbol, RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException

class CodeSummarizer(GhidraScript):
    def __init__(self):
        self.program = None
        self.current_function = None
        self.summaries = {}
        self.function_list = []
        self.settings = {
            'summary_length': '中等',  # 短、中等、长
            'include_parameters': True,
            'include_return_value': True,
            'include_control_flow': True,
            'include_data_flow': True,
            'include_comments': True
        }
    
    def run(self):
        """运行代码摘要生成器"""
        self.program = self.getCurrentProgram()
        if not self.program:
            self.println("没有打开的程序")
            return
        
        self.show_code_summarizer()
    
    def show_code_summarizer(self):
        """显示代码摘要生成器界面"""
        frame = JFrame("Code Summarizer - 代码摘要生成器")
        frame.setSize(1200, 800)
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setLocationRelativeTo(None)
        
        # 创建主面板
        main_panel = JPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建工具栏
        toolbar = JToolBar()
        toolbar.setRollover(True)
        
        # 函数选择
        function_combo = JComboBox()
        function_combo.setToolTipText("选择函数")
        toolbar.add(function_combo)
        toolbar.addSeparator()
        
        # 操作按钮
        summarize_button = JButton("生成摘要")
        summarize_button.setToolTipText("生成选中函数的摘要")
        toolbar.add(summarize_button)
        
        batch_button = JButton("批量生成")
        batch_button.setToolTipText("批量生成所有函数的摘要")
        toolbar.add(batch_button)
        toolbar.addSeparator()
        
        refresh_button = JButton("刷新函数")
        refresh_button.setToolTipText("刷新函数列表")
        toolbar.add(refresh_button)
        
        clear_button = JButton("清除摘要")
        clear_button.setToolTipText("清除当前摘要")
        toolbar.add(clear_button)
        toolbar.addSeparator()
        
        # 导出按钮
        export_button = JButton("导出摘要")
        export_button.setToolTipText("导出摘要为文件")
        toolbar.add(export_button)
        
        save_button = JButton("保存设置")
        save_button.setToolTipText("保存设置")
        toolbar.add(save_button)
        
        main_panel.add(toolbar, BorderLayout.NORTH)
        
        # 创建分割面板
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split_pane.setDividerLocation(400)
        
        # 左侧函数列表面板
        function_panel = JPanel()
        function_panel.setLayout(BorderLayout())
        
        # 函数列表
        self.function_list_model = DefaultTableModel(["函数名", "地址", "大小", "摘要状态"], 0)
        function_table = JTable(self.function_list_model)
        function_table.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        
        function_scroll_pane = JScrollPane(function_table)
        function_panel.add(function_scroll_pane, BorderLayout.CENTER)
        
        # 函数列表控制选项
        function_control_panel = JPanel()
        function_control_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        function_control_panel.setBorder(BorderFactory.createTitledBorder("函数列表选项"))
        
        sort_combo = JComboBox(["按名称排序", "按地址排序", "按大小排序"])
        function_control_panel.add(JLabel("排序方式："))
        function_control_panel.add(sort_combo)
        
        filter_field = JTextField(20)
        filter_field.setToolTipText("过滤函数")
        function_control_panel.add(JLabel("  过滤："))
        function_control_panel.add(filter_field)
        
        function_panel.add(function_control_panel, BorderLayout.SOUTH)
        
        split_pane.setLeftComponent(function_panel)
        
        # 右侧摘要面板
        summary_panel = JPanel()
        summary_panel.setLayout(BorderLayout())
        
        # 摘要标签页
        summary_tabbed_pane = JTabbedPane()
        
        # 函数摘要标签
        function_summary_panel = JPanel()
        function_summary_panel.setLayout(BoxLayout(function_summary_panel, BoxLayout.Y_AXIS))
        
        # 函数信息
        info_panel = JPanel()
        info_panel.setLayout(GridLayout(4, 2, 10, 10))
        info_panel.setBorder(BorderFactory.createTitledBorder("函数信息"))
        
        self.function_name_label = JLabel("函数名：")
        self.function_address_label = JLabel("地址：")
        self.function_size_label = JLabel("大小：")
        self.function_type_label = JLabel("类型：")
        
        info_panel.add(JLabel("函数名："))
        info_panel.add(self.function_name_label)
        info_panel.add(JLabel("地址："))
        info_panel.add(self.function_address_label)
        info_panel.add(JLabel("大小："))
        info_panel.add(self.function_size_label)
        info_panel.add(JLabel("类型："))
        info_panel.add(self.function_type_label)
        
        function_summary_panel.add(info_panel)
        
        # 函数摘要
        summary_text_panel = JPanel()
        summary_text_panel.setLayout(BorderLayout())
        summary_text_panel.setBorder(BorderFactory.createTitledBorder("函数摘要"))
        
        self.summary_text = JTextArea(15, 50)
        self.summary_text.setEditable(False)
        self.summary_text.setLineWrap(True)
        self.summary_text.setWrapStyleWord(True)
        summary_text_panel.add(JScrollPane(self.summary_text), BorderLayout.CENTER)
        
        function_summary_panel.add(summary_text_panel)
        
        # 代码块摘要
        code_block_panel = JPanel()
        code_block_panel.setLayout(BorderLayout())
        code_block_panel.setBorder(BorderFactory.createTitledBorder("代码块摘要"))
        
        self.code_block_table_model = DefaultTableModel(["代码块", "地址", "大小", "摘要"], 0)
        code_block_table = JTable(self.code_block_table_model)
        code_block_panel.add(JScrollPane(code_block_table), BorderLayout.CENTER)
        
        function_summary_panel.add(code_block_panel)
        
        summary_tabbed_pane.addTab("函数摘要", function_summary_panel)
        
        # 设置标签
        settings_panel = JPanel()
        settings_panel.setLayout(BoxLayout(settings_panel, BoxLayout.Y_AXIS))
        settings_panel.setBorder(BorderFactory.createTitledBorder("设置"))
        
        # 摘要设置
        summary_settings_panel = JPanel()
        summary_settings_panel.setLayout(GridLayout(5, 2, 10, 10))
        
        length_combo = JComboBox(["短", "中等", "长"])
        length_combo.setSelectedItem(self.settings['summary_length'])
        summary_settings_panel.add(JLabel("摘要长度："))
        summary_settings_panel.add(length_combo)
        
        include_params_checkbox = JCheckBox()
        include_params_checkbox.setSelected(self.settings['include_parameters'])
        summary_settings_panel.add(JLabel("包含参数："))
        summary_settings_panel.add(include_params_checkbox)
        
        include_return_checkbox = JCheckBox()
        include_return_checkbox.setSelected(self.settings['include_return_value'])
        summary_settings_panel.add(JLabel("包含返回值："))
        summary_settings_panel.add(include_return_checkbox)
        
        include_control_checkbox = JCheckBox()
        include_control_checkbox.setSelected(self.settings['include_control_flow'])
        summary_settings_panel.add(JLabel("包含控制流："))
        summary_settings_panel.add(include_control_checkbox)
        
        include_data_checkbox = JCheckBox()
        include_data_checkbox.setSelected(self.settings['include_data_flow'])
        summary_settings_panel.add(JLabel("包含数据流："))
        summary_settings_panel.add(include_data_checkbox)
        
        settings_panel.add(summary_settings_panel)
        
        # 高级设置
        advanced_settings_panel = JPanel()
        advanced_settings_panel.setLayout(BoxLayout(advanced_settings_panel, BoxLayout.Y_AXIS))
        advanced_settings_panel.setBorder(BorderFactory.createTitledBorder("高级设置"))
        
        comment_checkbox = JCheckBox("包含注释")
        comment_checkbox.setSelected(self.settings['include_comments'])
        advanced_settings_panel.add(comment_checkbox)
        
        settings_panel.add(advanced_settings_panel)
        
        summary_tabbed_pane.addTab("设置", settings_panel)
        
        # 统计标签
        stats_panel = JPanel()
        stats_panel.setLayout(BorderLayout())
        
        # 统计表格
        stats_table_model = DefaultTableModel(["统计项", "值"], 0)
        stats_table = JTable(stats_table_model)
        stats_panel.add(JScrollPane(stats_table), BorderLayout.CENTER)
        
        summary_tabbed_pane.addTab("统计", stats_panel)
        
        summary_panel.add(summary_tabbed_pane, BorderLayout.CENTER)
        
        # 底部状态栏
        status_bar = JPanel()
        status_bar.setLayout(FlowLayout(FlowLayout.LEFT))
        status_bar.setBorder(BorderFactory.createLoweredBevelBorder())
        
        self.status_label = JLabel("就绪")
        status_bar.add(self.status_label)
        
        summary_panel.add(status_bar, BorderLayout.SOUTH)
        
        split_pane.setRightComponent(summary_panel)
        
        main_panel.add(split_pane, BorderLayout.CENTER)
        
        frame.add(main_panel)
        frame.setVisible(True)
        
        # 初始化函数列表
        self.initialize_function_list()
    
    def initialize_function_list(self):
        """初始化函数列表"""
        # 实际实现中，这里应该：
        # 1. 获取程序中的函数列表
        # 2. 填充函数列表模型
        # 3. 更新状态
        
        # 示例：添加一些模拟的函数
        self.function_list_model.setRowCount(0)
        sample_functions = [
            {"name": "main", "address": "0x10001000", "size": 100, "status": "未生成"},
            {"name": "function1", "address": "0x10002000", "size": 50, "status": "未生成"},
            {"name": "function2", "address": "0x10003000", "size": 75, "status": "未生成"},
            {"name": "library_function", "address": "0x7fff0000", "size": 200, "status": "未生成"}
        ]
        
        for func in sample_functions:
            self.function_list_model.addRow([func["name"], func["address"], func["size"], func["status"]])
        
        # 更新状态
        self.status_label.setText("函数列表初始化完成")
    
    def generate_function_summary(self, function_name):
        """生成函数摘要"""
        # 实际实现中，这里应该：
        # 1. 分析函数的参数、返回值
        # 2. 分析函数的代码结构和逻辑
        # 3. 生成自然语言摘要
        # 4. 更新摘要状态
        
        # 示例：生成函数摘要
        sample_summaries = {
            "main": "main函数是程序的入口点，负责初始化程序环境，调用其他函数，并处理程序的主要逻辑。它接收命令行参数，初始化必要的资源，然后调用function1和function2函数执行具体任务，最后清理资源并返回退出码。",
            "function1": "function1函数执行特定的计算任务，接收输入参数并返回计算结果。它使用library_function来完成部分计算工作，处理错误情况，并返回适当的结果。",
            "function2": "function2函数负责数据处理，接收数据输入，执行转换和处理操作，然后返回处理后的数据。它也使用library_function来辅助完成数据处理工作。",
            "library_function": "library_function是一个库函数，提供通用的计算功能，可以被多个其他函数调用。它接收参数，执行复杂的计算，然后返回计算结果。"
        }
        
        summary = sample_summaries.get(function_name, "无法生成摘要")
        self.summaries[function_name] = summary
        
        # 更新摘要状态
        for i in range(self.function_list_model.getRowCount()):
            if self.function_list_model.getValueAt(i, 0) == function_name:
                self.function_list_model.setValueAt("已生成", i, 3)
                break
        
        # 更新函数信息
        self.update_function_info(function_name)
        
        # 更新摘要文本
        self.summary_text.setText(summary)
        
        # 更新代码块摘要
        self.update_code_block_summaries(function_name)
        
        # 更新状态
        self.status_label.setText(f"函数 {function_name} 的摘要生成完成")
    
    def update_function_info(self, function_name):
        """更新函数信息"""
        # 实际实现中，这里应该：
        # 1. 获取函数的详细信息
        # 2. 更新函数信息标签
        
        # 示例：更新函数信息
        sample_function_info = {
            "main": {"address": "0x10001000", "size": 100, "type": "入口函数"},
            "function1": {"address": "0x10002000", "size": 50, "type": "计算函数"},
            "function2": {"address": "0x10003000", "size": 75, "type": "数据处理函数"},
            "library_function": {"address": "0x7fff0000", "size": 200, "type": "库函数"}
        }
        
        info = sample_function_info.get(function_name, {"address": "", "size": 0, "type": "未知"})
        self.function_name_label.setText(function_name)
        self.function_address_label.setText(info["address"])
        self.function_size_label.setText(str(info["size"]) + " bytes")
        self.function_type_label.setText(info["type"])
    
    def update_code_block_summaries(self, function_name):
        """更新代码块摘要"""
        # 实际实现中，这里应该：
        # 1. 分析函数的代码块
        # 2. 生成代码块摘要
        # 3. 更新代码块表格
        
        # 示例：更新代码块摘要
        self.code_block_table_model.setRowCount(0)
        sample_code_blocks = {
            "main": [
                {"name": "初始化块", "address": "0x10001000", "size": 20, "summary": "初始化程序环境和变量"},
                {"name": "调用块", "address": "0x10001020", "size": 30, "summary": "调用function1和function2函数"},
                {"name": "清理块", "address": "0x10001050", "size": 20, "summary": "清理资源并返回退出码"}
            ],
            "function1": [
                {"name": "参数处理", "address": "0x10002000", "size": 15, "summary": "处理输入参数"},
                {"name": "计算块", "address": "0x10002015", "size": 20, "summary": "执行计算操作"},
                {"name": "返回块", "address": "0x10002035", "size": 15, "summary": "返回计算结果"}
            ],
            "function2": [
                {"name": "数据输入", "address": "0x10003000", "size": 20, "summary": "接收和验证输入数据"},
                {"name": "数据处理", "address": "0x10003020", "size": 35, "summary": "处理和转换数据"},
                {"name": "数据输出", "address": "0x10003055", "size": 20, "summary": "返回处理后的数据"}
            ],
            "library_function": [
                {"name": "参数验证", "address": "0x7fff0000", "size": 50, "summary": "验证输入参数的有效性"},
                {"name": "核心计算", "address": "0x7fff0050", "size": 100, "summary": "执行核心计算逻辑"},
                {"name": "结果处理", "address": "0x7fff00f0", "size": 50, "summary": "处理和返回计算结果"}
            ]
        }
        
        code_blocks = sample_code_blocks.get(function_name, [])
        for block in code_blocks:
            self.code_block_table_model.addRow([block["name"], block["address"], block["size"], block["summary"]])
    
    def batch_generate_summaries(self):
        """批量生成摘要"""
        # 实际实现中，这里应该：
        # 1. 遍历所有函数
        # 2. 生成每个函数的摘要
        # 3. 显示进度
        
        # 示例：批量生成摘要
        self.status_label.setText("开始批量生成摘要")
        
        for i in range(self.function_list_model.getRowCount()):
            function_name = self.function_list_model.getValueAt(i, 0)
            self.generate_function_summary(function_name)
            
        self.status_label.setText("批量生成摘要完成")
    
    def export_summaries(self, format_type):
        """导出摘要"""
        # 实际实现中，这里应该：
        # 1. 根据选择的格式导出摘要
        # 2. 保存到文件
        
        # 示例：导出为JSON文件
        summaries_data = {
            "functions": [],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        for function_name, summary in self.summaries.items():
            summaries_data["functions"].append({
                "name": function_name,
                "summary": summary
            })
        
        # 保存到文件
        pass
    
    def save_settings(self, filename):
        """保存设置"""
        # 实际实现中，这里应该：
        # 1. 保存设置到文件
        # 2. 包括摘要长度、详细程度等
        
        # 示例：保存为JSON文件
        pass
    
    def load_settings(self, filename):
        """加载设置"""
        # 实际实现中，这里应该：
        # 1. 从文件加载设置
        # 2. 应用设置
        
        pass
    
    def analyze_code_structure(self, function):
        """分析代码结构"""
        # 实际实现中，这里应该：
        # 1. 分析函数的代码结构
        # 2. 识别代码块和逻辑
        # 3. 返回分析结果
        
        pass
    
    def generate_code_block_summary(self, code_block):
        """生成代码块摘要"""
        # 实际实现中，这里应该：
        # 1. 分析代码块的功能
        # 2. 生成自然语言摘要
        # 3. 返回摘要
        
        pass

# 主函数
if __name__ == "__main__":
    summarizer = CodeSummarizer()
    summarizer.run()
