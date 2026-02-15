#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AnalysisDashboard.py

综合分析仪表板，显示所有分析结果的概览，集成各分析工具数据，实现数据联动分析。

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
    from java.awt.event import ActionListener
    from java.awt.event import MouseAdapter
    from java.awt.event import MouseEvent
    from javax.swing import JButton
    from javax.swing import JLabel
    from javax.swing import JScrollPane
    from javax.swing import JPanel
    from javax.swing import JTabbedPane
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
    from java.util import ArrayList
    from java.util import List
    from java.util import Map
    from java.util import HashMap
    from java.util import LinkedHashMap
    from java.util import Collections
    from java.util import Comparator
    from ghidra.program.model.address import Address
    from ghidra.program.model.listing import Function
    from ghidra.program.model.listing import Listing
    from ghidra.program.model.symbol import Symbol
    from ghidra.program.model.symbol import SymbolTable
    from ghidra.program.model.mem import Memory
    from ghidra.program.model.lang import Processor
    from ghidra.program.model.lang import CompilerSpec
except ImportError as e:
    print(f"导入Ghidra模块失败: {e}")
    sys.exit(1)

class AnalysisData:
    """分析数据类"""
    def __init__(self, tool_name, data_type, data, timestamp=None):
        self.tool_name = tool_name
        self.data_type = data_type
        self.data = data
        self.timestamp = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def to_dict(self):
        """转换为字典格式"""
        return {
            "tool_name": self.tool_name,
            "data_type": self.data_type,
            "data": self.data,
            "timestamp": self.timestamp
        }

    @staticmethod
    def from_dict(data):
        """从字典创建AnalysisData对象"""
        return AnalysisData(
            tool_name=data.get("tool_name"),
            data_type=data.get("data_type"),
            data=data.get("data"),
            timestamp=data.get("timestamp")
        )

class DashboardPanel(JPanel):
    """仪表板面板基类"""
    def __init__(self, dashboard, title):
        super(DashboardPanel, self).__init__()
        self.dashboard = dashboard
        self.title = title
        self.setLayout(BorderLayout())

    def update_data(self, analysis_data):
        """更新数据"""
        pass

    def refresh(self):
        """刷新面板"""
        pass

class SummaryPanel(DashboardPanel):
    """摘要面板"""
    def __init__(self, dashboard):
        super(SummaryPanel, self).__init__(dashboard, "分析摘要")
        self.init_components()

    def init_components(self):
        """初始化组件"""
        # 创建统计卡片面板
        stats_panel = JPanel()
        stats_panel.setLayout(GridBagLayout())
        gbc = GridBagConstraints()
        gbc.insets = Insets(10, 10, 10, 10)
        gbc.fill = GridBagConstraints.HORIZONTAL
        gbc.weightx = 1.0
        gbc.weighty = 1.0

        # 安全漏洞统计
        self.vulnerability_card = self.create_stat_card("安全漏洞", "0", Color(255, 100, 100))
        gbc.gridx = 0
        gbc.gridy = 0
        stats_panel.add(self.vulnerability_card, gbc)

        # 恶意软件特征统计
        self.malware_card = self.create_stat_card("恶意软件特征", "0", Color(255, 165, 0))
        gbc.gridx = 1
        gbc.gridy = 0
        stats_panel.add(self.malware_card, gbc)

        # 加密算法统计
        self.crypto_card = self.create_stat_card("加密算法", "0", Color(100, 149, 237))
        gbc.gridx = 0
        gbc.gridy = 1
        stats_panel.add(self.crypto_card, gbc)

        # 网络协议统计
        self.protocol_card = self.create_stat_card("网络协议", "0", Color(60, 179, 113))
        gbc.gridx = 1
        gbc.gridy = 1
        stats_panel.add(self.protocol_card, gbc)

        # 函数统计
        self.function_card = self.create_stat_card("函数数量", "0", Color(123, 104, 238))
        gbc.gridx = 0
        gbc.gridy = 2
        stats_panel.add(self.function_card, gbc)

        # 交叉引用统计
        self.xref_card = self.create_stat_card("交叉引用", "0", Color(255, 192, 203))
        gbc.gridx = 1
        gbc.gridy = 2
        stats_panel.add(self.xref_card, gbc)

        self.add(stats_panel, BorderLayout.CENTER)

    def create_stat_card(self, title, value, color):
        """创建统计卡片"""
        card = JPanel()
        card.setLayout(BorderLayout())
        card.setBorder(javax.swing.BorderFactory.createLineBorder(color, 2))
        card.setBackground(Color.WHITE)

        title_label = JLabel(title)
        title_label.setHorizontalAlignment(JLabel.CENTER)
        title_label.setFont(title_label.getFont().deriveFont(14.0))
        title_label.setForeground(color)

        value_label = JLabel(value)
        value_label.setHorizontalAlignment(JLabel.CENTER)
        value_label.setFont(value_label.getFont().deriveFont(24.0))
        value_label.setForeground(color)

        card.add(title_label, BorderLayout.NORTH)
        card.add(value_label, BorderLayout.CENTER)

        return card

    def update_data(self, analysis_data):
        """更新数据"""
        # 根据分析数据类型更新对应卡片
        if analysis_data.tool_name == "SecurityScanner":
            if analysis_data.data_type == "vulnerabilities":
                count = len(analysis_data.data)
                self.update_card_value(self.vulnerability_card, str(count))
        elif analysis_data.tool_name == "MalwareAnalyzer":
            if analysis_data.data_type == "signatures":
                count = len(analysis_data.data)
                self.update_card_value(self.malware_card, str(count))
        elif analysis_data.tool_name == "CryptoAnalyzer":
            if analysis_data.data_type == "algorithms":
                count = len(analysis_data.data)
                self.update_card_value(self.crypto_card, str(count))
        elif analysis_data.tool_name == "ProtocolAnalyzer":
            if analysis_data.data_type == "protocols":
                count = len(analysis_data.data)
                self.update_card_value(self.protocol_card, str(count))
        elif analysis_data.tool_name == "CodeSummarizer":
            if analysis_data.data_type == "functions":
                count = len(analysis_data.data)
                self.update_card_value(self.function_card, str(count))
        elif analysis_data.tool_name == "CrossReferenceExplorer":
            if analysis_data.data_type == "xrefs":
                count = len(analysis_data.data)
                self.update_card_value(self.xref_card, str(count))

    def update_card_value(self, card, value):
        """更新卡片值"""
        for component in card.getComponents():
            if isinstance(component, JLabel) and component.getFont().getSize() > 16:
                component.setText(value)
                break

    def refresh(self):
        """刷新面板"""
        # 重置所有卡片值
        self.update_card_value(self.vulnerability_card, "0")
        self.update_card_value(self.malware_card, "0")
        self.update_card_value(self.crypto_card, "0")
        self.update_card_value(self.protocol_card, "0")
        self.update_card_value(self.function_card, "0")
        self.update_card_value(self.xref_card, "0")

        # 重新计算统计数据
        for data in self.dashboard.analysis_data:
            self.update_data(data)

class SecurityPanel(DashboardPanel):
    """安全分析面板"""
    def __init__(self, dashboard):
        super(SecurityPanel, self).__init__(dashboard, "安全分析")
        self.init_components()

    def init_components(self):
        """初始化组件"""
        # 创建标签页
        tabbed_pane = JTabbedPane()

        # 安全漏洞标签
        vulnerability_panel = JPanel(BorderLayout())
        self.vulnerability_table = self.create_security_table()
        vulnerability_scroll = JScrollPane(self.vulnerability_table)
        vulnerability_panel.add(vulnerability_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("安全漏洞", vulnerability_panel)

        # 安全加固标签
        hardening_panel = JPanel(BorderLayout())
        self.hardening_table = self.create_hardening_table()
        hardening_scroll = JScrollPane(self.hardening_table)
        hardening_panel.add(hardening_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("安全加固", hardening_panel)

        # 安全编码标签
        secure_coding_panel = JPanel(BorderLayout())
        self.secure_coding_table = self.create_secure_coding_table()
        secure_coding_scroll = JScrollPane(self.secure_coding_table)
        secure_coding_panel.add(secure_coding_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("安全编码", secure_coding_panel)

        self.add(tabbed_pane, BorderLayout.CENTER)

    def create_security_table(self):
        """创建安全漏洞表格"""
        column_names = ["严重程度", "类型", "地址", "描述"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def create_hardening_table(self):
        """创建安全加固表格"""
        column_names = ["检查项", "状态", "描述"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def create_secure_coding_table(self):
        """创建安全编码表格"""
        column_names = ["类型", "地址", "描述", "建议"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def update_data(self, analysis_data):
        """更新数据"""
        if analysis_data.tool_name == "SecurityScanner":
            if analysis_data.data_type == "vulnerabilities":
                self.update_vulnerability_table(analysis_data.data)
        elif analysis_data.tool_name == "HardeningAnalyzer":
            if analysis_data.data_type == "hardening":
                self.update_hardening_table(analysis_data.data)
        elif analysis_data.tool_name == "SecureCodingChecker":
            if analysis_data.data_type == "issues":
                self.update_secure_coding_table(analysis_data.data)

    def update_vulnerability_table(self, vulnerabilities):
        """更新安全漏洞表格"""
        model = self.vulnerability_table.getModel()
        model.setRowCount(0)
        for vuln in vulnerabilities:
            model.addRow([
                vuln.get("severity", ""),
                vuln.get("type", ""),
                vuln.get("address", ""),
                vuln.get("description", "")
            ])

    def update_hardening_table(self, hardening_data):
        """更新安全加固表格"""
        model = self.hardening_table.getModel()
        model.setRowCount(0)
        for item in hardening_data:
            model.addRow([
                item.get("check", ""),
                "启用" if item.get("enabled", False) else "禁用",
                item.get("description", "")
            ])

    def update_secure_coding_table(self, issues):
        """更新安全编码表格"""
        model = self.secure_coding_table.getModel()
        model.setRowCount(0)
        for issue in issues:
            model.addRow([
                issue.get("type", ""),
                issue.get("address", ""),
                issue.get("description", ""),
                issue.get("recommendation", "")
            ])

    def refresh(self):
        """刷新面板"""
        # 清空表格
        self.vulnerability_table.getModel().setRowCount(0)
        self.hardening_table.getModel().setRowCount(0)
        self.secure_coding_table.getModel().setRowCount(0)

        # 重新加载数据
        for data in self.dashboard.analysis_data:
            self.update_data(data)

class ReverseEngineeringPanel(DashboardPanel):
    """逆向工程面板"""
    def __init__(self, dashboard):
        super(ReverseEngineeringPanel, self).__init__(dashboard, "逆向工程")
        self.init_components()

    def init_components(self):
        """初始化组件"""
        # 创建标签页
        tabbed_pane = JTabbedPane()

        # 恶意软件分析标签
        malware_panel = JPanel(BorderLayout())
        self.malware_table = self.create_malware_table()
        malware_scroll = JScrollPane(self.malware_table)
        malware_panel.add(malware_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("恶意软件分析", malware_panel)

        # 加密分析标签
        crypto_panel = JPanel(BorderLayout())
        self.crypto_table = self.create_crypto_table()
        crypto_scroll = JScrollPane(self.crypto_table)
        crypto_panel.add(crypto_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("加密分析", crypto_panel)

        # 协议分析标签
        protocol_panel = JPanel(BorderLayout())
        self.protocol_table = self.create_protocol_table()
        protocol_scroll = JScrollPane(self.protocol_table)
        protocol_panel.add(protocol_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("协议分析", protocol_panel)

        self.add(tabbed_pane, BorderLayout.CENTER)

    def create_malware_table(self):
        """创建恶意软件分析表格"""
        column_names = ["类型", "特征", "描述", "置信度"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def create_crypto_table(self):
        """创建加密分析表格"""
        column_names = ["算法", "地址", "强度", "描述"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def create_protocol_table(self):
        """创建协议分析表格"""
        column_names = ["协议", "地址", "版本", "描述"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def update_data(self, analysis_data):
        """更新数据"""
        if analysis_data.tool_name == "MalwareAnalyzer":
            if analysis_data.data_type == "signatures":
                self.update_malware_table(analysis_data.data)
        elif analysis_data.tool_name == "CryptoAnalyzer":
            if analysis_data.data_type == "algorithms":
                self.update_crypto_table(analysis_data.data)
        elif analysis_data.tool_name == "ProtocolAnalyzer":
            if analysis_data.data_type == "protocols":
                self.update_protocol_table(analysis_data.data)

    def update_malware_table(self, signatures):
        """更新恶意软件分析表格"""
        model = self.malware_table.getModel()
        model.setRowCount(0)
        for sig in signatures:
            model.addRow([
                sig.get("type", ""),
                sig.get("signature", ""),
                sig.get("description", ""),
                sig.get("confidence", "")
            ])

    def update_crypto_table(self, algorithms):
        """更新加密分析表格"""
        model = self.crypto_table.getModel()
        model.setRowCount(0)
        for algo in algorithms:
            model.addRow([
                algo.get("name", ""),
                algo.get("address", ""),
                algo.get("strength", ""),
                algo.get("description", "")
            ])

    def update_protocol_table(self, protocols):
        """更新协议分析表格"""
        model = self.protocol_table.getModel()
        model.setRowCount(0)
        for proto in protocols:
            model.addRow([
                proto.get("name", ""),
                proto.get("address", ""),
                proto.get("version", ""),
                proto.get("description", "")
            ])

    def refresh(self):
        """刷新面板"""
        # 清空表格
        self.malware_table.getModel().setRowCount(0)
        self.crypto_table.getModel().setRowCount(0)
        self.protocol_table.getModel().setRowCount(0)

        # 重新加载数据
        for data in self.dashboard.analysis_data:
            self.update_data(data)

class CodeUnderstandingPanel(DashboardPanel):
    """代码理解面板"""
    def __init__(self, dashboard):
        super(CodeUnderstandingPanel, self).__init__(dashboard, "代码理解")
        self.init_components()

    def init_components(self):
        """初始化组件"""
        # 创建标签页
        tabbed_pane = JTabbedPane()

        # 函数摘要标签
        summary_panel = JPanel(BorderLayout())
        self.summary_table = self.create_summary_table()
        summary_scroll = JScrollPane(self.summary_table)
        summary_panel.add(summary_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("函数摘要", summary_panel)

        # 交叉引用标签
        xref_panel = JPanel(BorderLayout())
        self.xref_table = self.create_xref_table()
        xref_scroll = JScrollPane(self.xref_table)
        xref_panel.add(xref_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("交叉引用", xref_panel)

        # API使用标签
        api_panel = JPanel(BorderLayout())
        self.api_table = self.create_api_table()
        api_scroll = JScrollPane(self.api_table)
        api_panel.add(api_scroll, BorderLayout.CENTER)
        tabbed_pane.addTab("API使用", api_panel)

        self.add(tabbed_pane, BorderLayout.CENTER)

    def create_summary_table(self):
        """创建函数摘要表格"""
        column_names = ["函数名", "地址", "摘要"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def create_xref_table(self):
        """创建交叉引用表格"""
        column_names = ["类型", "源地址", "目标地址", "引用计数"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def create_api_table(self):
        """创建API使用表格"""
        column_names = ["API名称", "调用次数", "模块", "描述"]
        model = DefaultTableModel(column_names, 0)
        table = GTable(model)
        return table

    def update_data(self, analysis_data):
        """更新数据"""
        if analysis_data.tool_name == "CodeSummarizer":
            if analysis_data.data_type == "functions":
                self.update_summary_table(analysis_data.data)
        elif analysis_data.tool_name == "CrossReferenceExplorer":
            if analysis_data.data_type == "xrefs":
                self.update_xref_table(analysis_data.data)
        elif analysis_data.tool_name == "APIUsageAnalyzer":
            if analysis_data.data_type == "api_usage":
                self.update_api_table(analysis_data.data)

    def update_summary_table(self, functions):
        """更新函数摘要表格"""
        model = self.summary_table.getModel()
        model.setRowCount(0)
        for func in functions:
            model.addRow([
                func.get("name", ""),
                func.get("address", ""),
                func.get("summary", "")[:100] + "..." if len(func.get("summary", "")) > 100 else func.get("summary", "")
            ])

    def update_xref_table(self, xrefs):
        """更新交叉引用表格"""
        model = self.xref_table.getModel()
        model.setRowCount(0)
        for xref in xrefs:
            model.addRow([
                xref.get("type", ""),
                xref.get("source", ""),
                xref.get("target", ""),
                xref.get("count", "")
            ])

    def update_api_table(self, api_usage):
        """更新API使用表格"""
        model = self.api_table.getModel()
        model.setRowCount(0)
        for api in api_usage:
            model.addRow([
                api.get("name", ""),
                api.get("count", ""),
                api.get("module", ""),
                api.get("description", "")
            ])

    def refresh(self):
        """刷新面板"""
        # 清空表格
        self.summary_table.getModel().setRowCount(0)
        self.xref_table.getModel().setRowCount(0)
        self.api_table.getModel().setRowCount(0)

        # 重新加载数据
        for data in self.dashboard.analysis_data:
            self.update_data(data)

class AnalysisDashboard(GhidraScript):
    """分析仪表板"""

    def __init__(self):
        super(AnalysisDashboard, self).__init__()
        self.analysis_data = []
        self.panels = []
        self.config_file = os.path.join(os.path.expanduser("~"), ".ghidra", "analysis_dashboard_config.json")

    def run(self):
        """运行脚本"""
        try:
            self.load_config()
            self.discover_analysis_data()
            self.show_dialog()
        except Exception as e:
            self.log_error(f"运行分析仪表板时出错: {e}")

    def load_config(self):
        """加载配置"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # 加载分析数据
                if "analysis_data" in config:
                    self.analysis_data = [AnalysisData.from_dict(data) for data in config["analysis_data"]]
        except Exception as e:
            self.log_error(f"加载配置时出错: {e}")

    def save_config(self):
        """保存配置"""
        try:
            config = {
                "analysis_data": [data.to_dict() for data in self.analysis_data]
            }
            
            # 确保配置目录存在
            config_dir = os.path.dirname(self.config_file)
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.log_error(f"保存配置时出错: {e}")

    def discover_analysis_data(self):
        """发现分析数据"""
        # 尝试从已有的分析工具结果中加载数据
        # 这里可以实现从文件系统或其他存储中加载之前的分析结果
        pass

    def add_analysis_data(self, analysis_data):
        """添加分析数据"""
        # 检查是否已存在相同的分析数据
        existing = next((d for d in self.analysis_data if 
                        d.tool_name == analysis_data.tool_name and 
                        d.data_type == analysis_data.data_type), None)
        if existing:
            # 更新现有数据
            existing.data = analysis_data.data
            existing.timestamp = analysis_data.timestamp
        else:
            # 添加新数据
            self.analysis_data.append(analysis_data)
        
        # 更新所有面板
        for panel in self.panels:
            panel.update_data(analysis_data)

    def import_analysis_data(self, file_path):
        """导入分析数据"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                for item in data:
                    analysis_data = AnalysisData.from_dict(item)
                    self.add_analysis_data(analysis_data)
                return True
            elif isinstance(data, dict):
                analysis_data = AnalysisData.from_dict(data)
                self.add_analysis_data(analysis_data)
                return True
            return False
        except Exception as e:
            self.log_error(f"导入分析数据时出错: {e}")
            return False

    def export_analysis_data(self, file_path):
        """导出分析数据"""
        try:
            data = [d.to_dict() for d in self.analysis_data]
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            self.log_error(f"导出分析数据时出错: {e}")
            return False

    def show_dialog(self):
        """显示对话框"""
        dialog = AnalysisDashboardDialog(self)
        dialog.setVisible(True)

    def log_error(self, message):
        """记录错误"""
        print(f"[ERROR] {message}")
        if hasattr(self, "println"):
            self.println(f"[ERROR] {message}")

class AnalysisDashboardDialog(GenericDialog):
    """分析仪表板对话框"""

    def __init__(self, dashboard):
        super(AnalysisDashboardDialog, self).__init__("分析仪表板")
        self.dashboard = dashboard
        self.init_components()

    def init_components(self):
        """初始化组件"""
        main_panel = JPanel(BorderLayout())
        
        # 创建标签页面板
        self.tabbed_pane = JTabbedPane()
        
        # 创建各功能面板
        self.summary_panel = SummaryPanel(self.dashboard)
        self.security_panel = SecurityPanel(self.dashboard)
        self.reverse_engineering_panel = ReverseEngineeringPanel(self.dashboard)
        self.code_understanding_panel = CodeUnderstandingPanel(self.dashboard)
        
        # 添加到标签页
        self.tabbed_pane.addTab("摘要", self.summary_panel)
        self.tabbed_pane.addTab("安全分析", self.security_panel)
        self.tabbed_pane.addTab("逆向工程", self.reverse_engineering_panel)
        self.tabbed_pane.addTab("代码理解", self.code_understanding_panel)
        
        # 将面板添加到仪表板的面板列表
        self.dashboard.panels = [
            self.summary_panel,
            self.security_panel,
            self.reverse_engineering_panel,
            self.code_understanding_panel
        ]
        
        # 创建工具栏
        toolbar = JPanel()
        
        # 刷新按钮
        refresh_button = JButton("刷新数据")
        refresh_button.addActionListener(self.create_action_listener(self.refresh_data))
        toolbar.add(refresh_button)
        
        # 导入数据按钮
        import_button = JButton("导入数据")
        import_button.addActionListener(self.create_action_listener(self.import_data))
        toolbar.add(import_button)
        
        # 导出数据按钮
        export_button = JButton("导出数据")
        export_button.addActionListener(self.create_action_listener(self.export_data))
        toolbar.add(export_button)
        
        # 清除数据按钮
        clear_button = JButton("清除数据")
        clear_button.addActionListener(self.create_action_listener(self.clear_data))
        toolbar.add(clear_button)
        
        # 组装面板
        main_panel.add(toolbar, BorderLayout.NORTH)
        main_panel.add(self.tabbed_pane, BorderLayout.CENTER)
        
        # 设置对话框内容
        self.setContent(main_panel)
        self.setPreferredSize(1000, 700)
        
        # 初始化面板数据
        self.refresh_data()

    def create_action_listener(self, func):
        """创建ActionListener"""
        class ActionListenerImpl(ActionListener):
            def actionPerformed(self, event):
                func()
        return ActionListenerImpl()

    def refresh_data(self):
        """刷新数据"""
        # 刷新所有面板
        for panel in self.dashboard.panels:
            panel.refresh()

    def import_data(self):
        """导入数据"""
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("导入分析数据")
        file_chooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON文件", "json"))
        
        if file_chooser.showOpenDialog(self) == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            if self.dashboard.import_analysis_data(file_path):
                JOptionPane.showMessageDialog(self, "数据导入成功", "成功", JOptionPane.INFORMATION_MESSAGE)
                self.refresh_data()
            else:
                JOptionPane.showMessageDialog(self, "数据导入失败", "错误", JOptionPane.ERROR_MESSAGE)

    def export_data(self):
        """导出数据"""
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("导出分析数据")
        file_chooser.setFileFilter(javax.swing.filechooser.FileNameExtensionFilter("JSON文件", "json"))
        file_chooser.setSelectedFile(File("analysis_dashboard_data.json"))
        
        if file_chooser.showSaveDialog(self) == JFileChooser.APPROVE_OPTION:
            file_path = file_chooser.getSelectedFile().getAbsolutePath()
            if not file_path.endswith(".json"):
                file_path += ".json"
            if self.dashboard.export_analysis_data(file_path):
                JOptionPane.showMessageDialog(self, "数据导出成功", "成功", JOptionPane.INFORMATION_MESSAGE)
            else:
                JOptionPane.showMessageDialog(self, "数据导出失败", "错误", JOptionPane.ERROR_MESSAGE)

    def clear_data(self):
        """清除数据"""
        confirm = JOptionPane.showConfirmDialog(self, "确定要清除所有分析数据吗?", "确认", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            self.dashboard.analysis_data = []
            self.refresh_data()

    def close(self):
        """关闭对话框"""
        self.dashboard.save_config()
        super(AnalysisDashboardDialog, self).close()

class AnalysisDashboardAction(DockingAction):
    """分析仪表板动作"""

    def __init__(self):
        super(AnalysisDashboardAction, self).__init__("AnalysisDashboard", "AnalysisDashboard")
        self.setMenuData(MenuData(["Tools", "Analysis Dashboard"], None, "AnalysisDashboard"))
        self.setEnabled(True)

    def actionPerformed(self, action_context):
        """执行动作"""
        dashboard = AnalysisDashboard()
        dashboard.run()

# 主函数
if __name__ == "__main__":
    script = AnalysisDashboard()
    script.run()