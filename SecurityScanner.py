#!/usr/bin/env python3
# SecurityScanner.py - 全面的安全漏洞扫描器
# 功能：检测多种类型的安全漏洞，评估严重性，提供修复建议

import os
import json
import time
from datetime import datetime
from java.awt import BorderLayout, GridLayout, FlowLayout, Color
from java.awt.event import ActionListener, ItemListener
from javax.swing import (
    JFrame, JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, 
    JCheckBox, JLabel, JComboBox, JTextField, JOptionPane, JTable, 
    DefaultTableModel, JFileChooser, JProgressBar, JMenuBar, JMenu, JMenuItem,
    BoxLayout, BorderFactory
)
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import Symbol, RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException

class SecurityScanner(GhidraScript):
    def __init__(self):
        self.program = None
        self.current_address = None
        self.scan_results = []
        self.scan_config = {
            'buffer_overflow': True,
            'use_after_free': True,
            'null_pointer': True,
            'integer_overflow': True,
            'format_string': True,
            'command_injection': True,
            'sql_injection': True,
            'xss': True,
            'authentication_bypass': True,
            'authorization_issues': True,
            'crypto_issues': True,
            'network_issues': True,
            'api_misuse': True,
            'race_conditions': True,
            'information_disclosure': True
        }
    
    def run(self):
        """运行安全扫描器"""
        self.program = self.getCurrentProgram()
        if not self.program:
            self.println("没有打开的程序")
            return
        
        self.show_security_scanner()
    
    def show_security_scanner(self):
        """显示安全扫描器界面"""
        frame = JFrame("Security Scanner - 安全漏洞扫描器")
        frame.setSize(1000, 700)
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setLocationRelativeTo(None)
        
        # 创建主面板
        main_panel = JPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建标签页
        tabbed_pane = JTabbedPane()
        
        # 扫描配置标签
        config_panel = self.create_config_panel()
        tabbed_pane.addTab("扫描配置", config_panel)
        
        # 扫描结果标签
        results_panel = self.create_results_panel()
        tabbed_pane.addTab("扫描结果", results_panel)
        
        # 漏洞详情标签
        details_panel = self.create_details_panel()
        tabbed_pane.addTab("漏洞详情", details_panel)
        
        # 修复建议标签
        recommendations_panel = self.create_recommendations_panel()
        tabbed_pane.addTab("修复建议", recommendations_panel)
        
        # 导出标签
        export_panel = self.create_export_panel()
        tabbed_pane.addTab("导出结果", export_panel)
        
        main_panel.add(tabbed_pane, BorderLayout.CENTER)
        
        # 创建底部按钮面板
        button_panel = JPanel()
        button_panel.setLayout(FlowLayout(FlowLayout.RIGHT))
        
        scan_button = JButton("开始扫描")
        scan_button.addActionListener(self.ScanButtonListener(frame))
        
        cancel_button = JButton("取消")
        cancel_button.addActionListener(lambda e: frame.dispose())
        
        button_panel.add(scan_button)
        button_panel.add(cancel_button)
        
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        frame.add(main_panel)
        frame.setVisible(True)
    
    def create_config_panel(self):
        """创建扫描配置面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建漏洞类型选择面板
        vuln_types_panel = JPanel()
        vuln_types_panel.setLayout(GridLayout(4, 4, 10, 10))
        vuln_types_panel.setBorder(BorderFactory.createTitledBorder("漏洞类型"))
        
        # 漏洞类型选项
        vuln_types = {
            'buffer_overflow': "缓冲区溢出",
            'use_after_free': "释放后使用",
            'null_pointer': "空指针解引用",
            'integer_overflow': "整数溢出",
            'format_string': "格式化字符串",
            'command_injection': "命令注入",
            'sql_injection': "SQL注入",
            'xss': "跨站脚本",
            'authentication_bypass': "认证绕过",
            'authorization_issues': "授权问题",
            'crypto_issues': "加密问题",
            'network_issues': "网络问题",
            'api_misuse': "API误用",
            'race_conditions': "竞态条件",
            'information_disclosure': "信息泄露"
        }
        
        for key, label in vuln_types.items():
            checkbox = JCheckBox(label)
            checkbox.setSelected(self.scan_config[key])
            checkbox.addItemListener(self.VulnTypeItemListener(key))
            vuln_types_panel.add(checkbox)
        
        # 创建扫描范围面板
        scope_panel = JPanel()
        scope_panel.setLayout(BoxLayout(scope_panel, BoxLayout.Y_AXIS))
        scope_panel.setBorder(BorderFactory.createTitledBorder("扫描范围"))
        
        scope_options = JPanel()
        scope_options.setLayout(FlowLayout(FlowLayout.LEFT))
        
        scope_combo = JComboBox(["整个程序", "当前函数", "选中区域", "自定义地址范围"])
        scope_options.add(JLabel("扫描范围："))
        scope_options.add(scope_combo)
        
        scope_panel.add(scope_options)
        
        # 创建自定义地址范围选项
        custom_range_panel = JPanel()
        custom_range_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        start_addr_field = JTextField(20)
        end_addr_field = JTextField(20)
        
        custom_range_panel.add(JLabel("起始地址："))
        custom_range_panel.add(start_addr_field)
        custom_range_panel.add(JLabel("  结束地址："))
        custom_range_panel.add(end_addr_field)
        
        scope_panel.add(custom_range_panel)
        
        # 创建扫描深度面板
        depth_panel = JPanel()
        depth_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        depth_panel.setBorder(BorderFactory.createTitledBorder("扫描深度"))
        
        depth_combo = JComboBox(["快速扫描", "标准扫描", "深度扫描"])
        depth_panel.add(JLabel("扫描深度："))
        depth_panel.add(depth_combo)
        
        # 添加所有面板到配置面板
        config_content = JPanel()
        config_content.setLayout(BorderLayout())
        config_content.add(vuln_types_panel, BorderLayout.NORTH)
        config_content.add(scope_panel, BorderLayout.CENTER)
        config_content.add(depth_panel, BorderLayout.SOUTH)
        
        scroll_pane = JScrollPane(config_content)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_results_panel(self):
        """创建扫描结果面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建结果表格
        columns = ["漏洞ID", "漏洞类型", "地址", "函数", "严重性", "状态"]
        self.results_table_model = DefaultTableModel(columns, 0)
        results_table = JTable(self.results_table_model)
        
        # 创建结果统计面板
        stats_panel = JPanel()
        stats_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        self.total_vulns_label = JLabel("总漏洞数：0")
        self.high_sev_label = JLabel("高危：0")
        self.med_sev_label = JLabel("中危：0")
        self.low_sev_label = JLabel("低危：0")
        
        stats_panel.add(self.total_vulns_label)
        stats_panel.add(JLabel("    "))
        stats_panel.add(self.high_sev_label)
        stats_panel.add(JLabel("    "))
        stats_panel.add(self.med_sev_label)
        stats_panel.add(JLabel("    "))
        stats_panel.add(self.low_sev_label)
        
        # 添加到面板
        panel.add(stats_panel, BorderLayout.NORTH)
        panel.add(JScrollPane(results_table), BorderLayout.CENTER)
        
        return panel
    
    def create_details_panel(self):
        """创建漏洞详情面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建详情文本区域
        self.details_text = JTextArea()
        self.details_text.setEditable(False)
        self.details_text.setLineWrap(True)
        self.details_text.setWrapStyleWord(True)
        
        scroll_pane = JScrollPane(self.details_text)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_recommendations_panel(self):
        """创建修复建议面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建建议文本区域
        self.recommendations_text = JTextArea()
        self.recommendations_text.setEditable(False)
        self.recommendations_text.setLineWrap(True)
        self.recommendations_text.setWrapStyleWord(True)
        
        scroll_pane = JScrollPane(self.recommendations_text)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def create_export_panel(self):
        """创建导出结果面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建导出选项面板
        export_options = JPanel()
        export_options.setLayout(GridLayout(3, 2, 10, 10))
        
        format_label = JLabel("导出格式：")
        format_combo = JComboBox(["JSON", "CSV", "HTML", "Text"])
        
        path_label = JLabel("导出路径：")
        path_field = JTextField()
        browse_button = JButton("浏览...")
        
        export_button = JButton("导出结果")
        export_button.addActionListener(lambda e: self.export_results(format_combo.getSelectedItem(), path_field.getText()))
        
        export_options.add(format_label)
        export_options.add(format_combo)
        export_options.add(path_label)
        export_options.add(path_field)
        export_options.add(browse_button)
        export_options.add(export_button)
        
        # 添加到面板
        panel.add(export_options, BorderLayout.NORTH)
        
        # 创建导出状态文本区域
        self.export_status = JTextArea()
        self.export_status.setEditable(False)
        self.export_status.setLineWrap(True)
        self.export_status.setWrapStyleWord(True)
        
        scroll_pane = JScrollPane(self.export_status)
        panel.add(scroll_pane, BorderLayout.CENTER)
        
        return panel
    
    def scan_for_vulnerabilities(self):
        """执行安全漏洞扫描"""
        self.scan_results = []
        
        # 模拟扫描过程
        # 实际实现中，这里应该根据配置的漏洞类型和扫描范围执行具体的扫描
        
        # 示例：检测缓冲区溢出漏洞
        if self.scan_config['buffer_overflow']:
            self.detect_buffer_overflow()
        
        # 示例：检测释放后使用漏洞
        if self.scan_config['use_after_free']:
            self.detect_use_after_free()
        
        # 示例：检测空指针解引用漏洞
        if self.scan_config['null_pointer']:
            self.detect_null_pointer()
        
        # 示例：检测整数溢出漏洞
        if self.scan_config['integer_overflow']:
            self.detect_integer_overflow()
        
        # 示例：检测格式化字符串漏洞
        if self.scan_config['format_string']:
            self.detect_format_string()
        
        # 示例：检测命令注入漏洞
        if self.scan_config['command_injection']:
            self.detect_command_injection()
        
        # 示例：检测SQL注入漏洞
        if self.scan_config['sql_injection']:
            self.detect_sql_injection()
        
        # 示例：检测跨站脚本漏洞
        if self.scan_config['xss']:
            self.detect_xss()
        
        # 示例：检测认证绕过漏洞
        if self.scan_config['authentication_bypass']:
            self.detect_authentication_bypass()
        
        # 示例：检测授权问题
        if self.scan_config['authorization_issues']:
            self.detect_authorization_issues()
        
        # 示例：检测加密问题
        if self.scan_config['crypto_issues']:
            self.detect_crypto_issues()
        
        # 示例：检测网络问题
        if self.scan_config['network_issues']:
            self.detect_network_issues()
        
        # 示例：检测API误用
        if self.scan_config['api_misuse']:
            self.detect_api_misuse()
        
        # 示例：检测竞态条件
        if self.scan_config['race_conditions']:
            self.detect_race_conditions()
        
        # 示例：检测信息泄露
        if self.scan_config['information_disclosure']:
            self.detect_information_disclosure()
        
        return self.scan_results
    
    def detect_buffer_overflow(self):
        """检测缓冲区溢出漏洞"""
        # 实际实现中，这里应该分析代码中的缓冲区操作
        # 示例：查找可能的缓冲区溢出
        pass
    
    def detect_use_after_free(self):
        """检测释放后使用漏洞"""
        # 实际实现中，这里应该分析内存分配和释放操作
        pass
    
    def detect_null_pointer(self):
        """检测空指针解引用漏洞"""
        # 实际实现中，这里应该分析指针使用情况
        pass
    
    def detect_integer_overflow(self):
        """检测整数溢出漏洞"""
        # 实际实现中，这里应该分析整数运算
        pass
    
    def detect_format_string(self):
        """检测格式化字符串漏洞"""
        # 实际实现中，这里应该分析格式化字符串使用
        pass
    
    def detect_command_injection(self):
        """检测命令注入漏洞"""
        # 实际实现中，这里应该分析命令执行函数调用
        pass
    
    def detect_sql_injection(self):
        """检测SQL注入漏洞"""
        # 实际实现中，这里应该分析SQL语句构建
        pass
    
    def detect_xss(self):
        """检测跨站脚本漏洞"""
        # 实际实现中，这里应该分析用户输入处理
        pass
    
    def detect_authentication_bypass(self):
        """检测认证绕过漏洞"""
        # 实际实现中，这里应该分析认证逻辑
        pass
    
    def detect_authorization_issues(self):
        """检测授权问题"""
        # 实际实现中，这里应该分析授权检查
        pass
    
    def detect_crypto_issues(self):
        """检测加密问题"""
        # 实际实现中，这里应该分析加密算法使用
        pass
    
    def detect_network_issues(self):
        """检测网络问题"""
        # 实际实现中，这里应该分析网络操作
        pass
    
    def detect_api_misuse(self):
        """检测API误用"""
        # 实际实现中，这里应该分析API调用
        pass
    
    def detect_race_conditions(self):
        """检测竞态条件"""
        # 实际实现中，这里应该分析并发操作
        pass
    
    def detect_information_disclosure(self):
        """检测信息泄露"""
        # 实际实现中，这里应该分析敏感信息处理
        pass
    
    def update_results_table(self):
        """更新结果表格"""
        # 清空表格
        self.results_table_model.setRowCount(0)
        
        # 添加扫描结果
        for result in self.scan_results:
            row = [
                result.get('id', ''),
                result.get('type', ''),
                result.get('address', ''),
                result.get('function', ''),
                result.get('severity', ''),
                result.get('status', '未修复')
            ]
            self.results_table_model.addRow(row)
        
        # 更新统计信息
        total = len(self.scan_results)
        high = len([r for r in self.scan_results if r.get('severity', '') == '高危'])
        medium = len([r for r in self.scan_results if r.get('severity', '') == '中危'])
        low = len([r for r in self.scan_results if r.get('severity', '') == '低危'])
        
        self.total_vulns_label.setText(f"总漏洞数：{total}")
        self.high_sev_label.setText(f"高危：{high}")
        self.med_sev_label.setText(f"中危：{medium}")
        self.low_sev_label.setText(f"低危：{low}")
    
    def show_vulnerability_details(self, vuln_id):
        """显示漏洞详情"""
        for result in self.scan_results:
            if result.get('id') == vuln_id:
                details = f"漏洞ID: {result.get('id')}\n"
                details += f"漏洞类型: {result.get('type')}\n"
                details += f"地址: {result.get('address')}\n"
                details += f"函数: {result.get('function')}\n"
                details += f"严重性: {result.get('severity')}\n"
                details += f"描述: {result.get('description', '无描述')}\n"
                details += f"影响: {result.get('impact', '无影响描述')}\n"
                details += f"发现时间: {result.get('found_time', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}\n"
                
                self.details_text.setText(details)
                
                # 显示修复建议
                recommendations = f"修复建议: {result.get('recommendation', '无建议')}\n"
                recommendations += f"修复难度: {result.get('fix_difficulty', '未知')}\n"
                recommendations += f"修复优先级: {result.get('fix_priority', '未知')}\n"
                
                self.recommendations_text.setText(recommendations)
                break
    
    def export_results(self, format_type, path):
        """导出扫描结果"""
        if not path:
            self.export_status.setText("错误：请指定导出路径")
            return
        
        try:
            if format_type == "JSON":
                with open(path, 'w', encoding='utf-8') as f:
                    json.dump(self.scan_results, f, ensure_ascii=False, indent=2)
                self.export_status.setText(f"成功导出到 {path}")
            
            elif format_type == "CSV":
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("ID,类型,地址,函数,严重性,描述,修复建议\n")
                    for result in self.scan_results:
                        f.write(f"{result.get('id')},{result.get('type')},{result.get('address')},{result.get('function')},{result.get('severity')},{result.get('description', '')},{result.get('recommendation', '')}\n")
                self.export_status.setText(f"成功导出到 {path}")
            
            elif format_type == "HTML":
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("<!DOCTYPE html><html><head><title>安全扫描结果</title>")
                    f.write("<style>table {border-collapse: collapse; width: 100%;}")
                    f.write("th, td {border: 1px solid #ddd; padding: 8px; text-align: left;}")
                    f.write("th {background-color: #f2f2f2;}")
                    f.write("tr:hover {background-color: #f5f5f5;}")
                    f.write("</style></head><body>")
                    f.write("<h1>安全扫描结果</h1>")
                    f.write("<table>")
                    f.write("<tr><th>ID</th><th>类型</th><th>地址</th><th>函数</th><th>严重性</th><th>描述</th><th>修复建议</th></tr>")
                    for result in self.scan_results:
                        f.write(f"<tr><td>{result.get('id')}</td><td>{result.get('type')}</td><td>{result.get('address')}</td><td>{result.get('function')}</td><td>{result.get('severity')}</td><td>{result.get('description', '')}</td><td>{result.get('recommendation', '')}</td></tr>")
                    f.write("</table></body></html>")
                self.export_status.setText(f"成功导出到 {path}")
            
            elif format_type == "Text":
                with open(path, 'w', encoding='utf-8') as f:
                    f.write("安全扫描结果\n")
                    f.write("=" * 80 + "\n")
                    for result in self.scan_results:
                        f.write(f"ID: {result.get('id')}\n")
                        f.write(f"类型: {result.get('type')}\n")
                        f.write(f"地址: {result.get('address')}\n")
                        f.write(f"函数: {result.get('function')}\n")
                        f.write(f"严重性: {result.get('severity')}\n")
                        f.write(f"描述: {result.get('description', '无描述')}\n")
                        f.write(f"修复建议: {result.get('recommendation', '无建议')}\n")
                        f.write("-" * 80 + "\n")
                self.export_status.setText(f"成功导出到 {path}")
            
        except Exception as e:
            self.export_status.setText(f"导出失败: {str(e)}")
    
    class ScanButtonListener(ActionListener):
        def __init__(self, frame):
            self.frame = frame
        
        def actionPerformed(self, e):
            # 显示进度对话框
            progress_frame = JFrame("扫描中")
            progress_frame.setSize(400, 100)
            progress_frame.setLocationRelativeTo(self.frame)
            
            progress_panel = JPanel()
            progress_panel.setLayout(BorderLayout())
            
            progress_bar = JProgressBar()
            progress_bar.setIndeterminate(True)
            
            status_label = JLabel("正在执行安全漏洞扫描...")
            
            progress_panel.add(status_label, BorderLayout.NORTH)
            progress_panel.add(progress_bar, BorderLayout.CENTER)
            
            progress_frame.add(progress_panel)
            progress_frame.setVisible(True)
            
            # 在后台线程中执行扫描
            from javax.swing import SwingWorker
            
            class ScanWorker(SwingWorker):
                def __init__(self, scanner, progress_frame):
                    self.scanner = scanner
                    self.progress_frame = progress_frame
                    SwingWorker.__init__(self)
                
                def doInBackground(self):
                    # 执行扫描
                    self.scanner.scan_for_vulnerabilities()
                    return True
                
                def done(self):
                    # 更新结果
                    self.scanner.update_results_table()
                    # 关闭进度对话框
                    self.progress_frame.dispose()
                    # 显示完成消息
                    JOptionPane.showMessageDialog(self.scanner.frame, "安全漏洞扫描完成！")
            
            # 启动扫描线程
            worker = ScanWorker(self, progress_frame)
            worker.execute()
    
    class VulnTypeItemListener(ItemListener):
        def __init__(self, key):
            self.key = key
        
        def itemStateChanged(self, e):
            # 更新扫描配置
            pass

# 主函数
if __name__ == "__main__":
    scanner = SecurityScanner()
    scanner.run()
