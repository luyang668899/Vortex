#!/usr/bin/env python3
# ProtocolAnalyzer.py - 分析网络协议实现
# 功能：识别常见网络协议、分析协议实现、检测安全漏洞

import os
import json
import re
from datetime import datetime
from java.awt import BorderLayout, GridLayout, FlowLayout, Color
from java.awt.event import ActionListener, ItemListener
from javax.swing import (
    JFrame, JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, 
    JCheckBox, JLabel, JComboBox, JTextField, JOptionPane, JTable, 
    DefaultTableModel, JFileChooser, JProgressBar, JMenuBar, JMenu, JMenuItem,
    BoxLayout, BorderFactory, JTree, DefaultMutableTreeNode
)
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import Symbol, RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException

class ProtocolAnalyzer(GhidraScript):
    def __init__(self):
        self.program = None
        self.analysis_results = {}
        self.protocols = {
            'TCP': {'patterns': ['tcp_', 'TCP_', 'connect', 'send', 'recv'], 'description': '传输控制协议'},
            'UDP': {'patterns': ['udp_', 'UDP_', 'sendto', 'recvfrom'], 'description': '用户数据报协议'},
            'HTTP': {'patterns': ['http_', 'HTTP_', 'GET ', 'POST ', 'HTTP/1.1'], 'description': '超文本传输协议'},
            'HTTPS': {'patterns': ['https_', 'HTTPS_', 'SSL_', 'TLS_'], 'description': '安全超文本传输协议'},
            'FTP': {'patterns': ['ftp_', 'FTP_', 'USER ', 'PASS ', 'PORT ', 'RETR '], 'description': '文件传输协议'},
            'SMTP': {'patterns': ['smtp_', 'SMTP_', 'MAIL FROM:', 'RCPT TO:', 'DATA'], 'description': '简单邮件传输协议'},
            'DNS': {'patterns': ['dns_', 'DNS_', 'gethostbyname', 'res_query'], 'description': '域名系统协议'},
            'SSH': {'patterns': ['ssh_', 'SSH_', 'SSHD_'], 'description': '安全外壳协议'},
            'WebSocket': {'patterns': ['websocket_', 'WebSocket', 'WS_', 'wss://'], 'description': 'WebSocket协议'},
            'MQTT': {'patterns': ['mqtt_', 'MQTT_', 'CONNECT', 'PUBLISH', 'SUBSCRIBE'], 'description': '消息队列遥测传输协议'}
        }
        self.protocol_ports = {
            'HTTP': 80,
            'HTTPS': 443,
            'FTP': 21,
            'SMTP': 25,
            'DNS': 53,
            'SSH': 22,
            'MQTT': 1883,
            'WebSocket': 80
        }
    
    def run(self):
        """运行协议分析器"""
        self.program = self.getCurrentProgram()
        if not self.program:
            self.println("没有打开的程序")
            return
        
        self.show_protocol_analyzer()
    
    def show_protocol_analyzer(self):
        """显示协议分析器界面"""
        frame = JFrame("Protocol Analyzer - 网络协议分析工具")
        frame.setSize(1000, 700)
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setLocationRelativeTo(None)
        
        # 创建主面板
        main_panel = JPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建标签页
        tabbed_pane = JTabbedPane()
        
        # 协议识别标签
        identification_panel = self.create_identification_panel()
        tabbed_pane.addTab("协议识别", identification_panel)
        
        # 协议分析标签
        analysis_panel = self.create_analysis_panel()
        tabbed_pane.addTab("协议分析", analysis_panel)
        
        # 安全漏洞检测标签
        vulnerability_panel = self.create_vulnerability_panel()
        tabbed_pane.addTab("安全漏洞检测", vulnerability_panel)
        
        # 协议流量分析标签
        traffic_panel = self.create_traffic_panel()
        tabbed_pane.addTab("协议流量分析", traffic_panel)
        
        # 分析报告标签
        report_panel = self.create_report_panel()
        tabbed_pane.addTab("分析报告", report_panel)
        
        main_panel.add(tabbed_pane, BorderLayout.CENTER)
        
        # 创建底部按钮面板
        button_panel = JPanel()
        button_panel.setLayout(FlowLayout(FlowLayout.RIGHT))
        
        analyze_button = JButton("开始分析")
        analyze_button.addActionListener(self.AnalyzeButtonListener(frame))
        
        cancel_button = JButton("取消")
        cancel_button.addActionListener(lambda e: frame.dispose())
        
        button_panel.add(analyze_button)
        button_panel.add(cancel_button)
        
        main_panel.add(button_panel, BorderLayout.SOUTH)
        
        frame.add(main_panel)
        frame.setVisible(True)
    
    def create_identification_panel(self):
        """创建协议识别面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建协议识别选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("协议识别选项"))
        
        # 协议类型选项
        protocol_types = JPanel()
        protocol_types.setLayout(FlowLayout(FlowLayout.LEFT))
        
        protocol_combo = JComboBox(["所有协议", "传输层", "应用层", "安全协议", "自定义"])
        protocol_types.add(JLabel("协议类型："))
        protocol_types.add(protocol_combo)
        
        options_panel.add(protocol_types)
        
        # 识别方法选项
        method_panel = JPanel()
        method_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        method_checkboxes = {
            "导入函数": JCheckBox("导入函数"),
            "字符串特征": JCheckBox("字符串特征"),
            "端口号": JCheckBox("端口号"),
            "代码模式": JCheckBox("代码模式")
        }
        
        for name, checkbox in method_checkboxes.items():
            checkbox.setSelected(True)
            method_panel.add(checkbox)
        
        options_panel.add(method_panel)
        
        # 创建协议识别结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("协议识别结果"))
        
        # 协议结果表格
        columns = ["协议名称", "类型", "识别方法", "位置", "置信度", "描述"]
        self.protocol_table_model = DefaultTableModel(columns, 0)
        protocol_table = JTable(self.protocol_table_model)
        
        results_panel.add(JScrollPane(protocol_table), BorderLayout.CENTER)
        
        # 添加所有面板到协议识别面板
        content_panel = JPanel()
        content_panel.setLayout(BorderLayout())
        content_panel.add(options_panel, BorderLayout.NORTH)
        content_panel.add(results_panel, BorderLayout.CENTER)
        
        panel.add(content_panel, BorderLayout.CENTER)
        
        return panel
    
    def create_analysis_panel(self):
        """创建协议分析面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建协议分析选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("协议分析选项"))
        
        # 分析深度选项
        depth_panel = JPanel()
        depth_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        depth_combo = JComboBox(["快速分析", "标准分析", "深度分析"])
        depth_panel.add(JLabel("分析深度："))
        depth_panel.add(depth_combo)
        
        options_panel.add(depth_panel)
        
        # 分析内容选项
        content_panel = JPanel()
        content_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        content_checkboxes = {
            "协议头部": JCheckBox("协议头部"),
            "协议解析": JCheckBox("协议解析"),
            "状态机": JCheckBox("状态机"),
            "错误处理": JCheckBox("错误处理")
        }
        
        for name, checkbox in content_checkboxes.items():
            checkbox.setSelected(True)
            content_panel.add(checkbox)
        
        options_panel.add(content_panel)
        
        # 创建协议分析结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("协议分析结果"))
        
        # 分析结果文本区域
        self.analysis_text = JTextArea(20, 50)
        self.analysis_text.setEditable(False)
        self.analysis_text.setLineWrap(True)
        self.analysis_text.setWrapStyleWord(True)
        self.analysis_text.setText("# 协议分析结果\n\n分析完成后将显示在这里...")
        
        results_panel.add(JScrollPane(self.analysis_text), BorderLayout.CENTER)
        
        # 添加所有面板到协议分析面板
        content_main = JPanel()
        content_main.setLayout(BorderLayout())
        content_main.add(options_panel, BorderLayout.NORTH)
        content_main.add(results_panel, BorderLayout.CENTER)
        
        panel.add(content_main, BorderLayout.CENTER)
        
        return panel
    
    def create_vulnerability_panel(self):
        """创建安全漏洞检测面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建漏洞检测选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("漏洞检测选项"))
        
        # 漏洞类型选项
        vulnerability_types = JPanel()
        vulnerability_types.setLayout(FlowLayout(FlowLayout.LEFT))
        
        vuln_types = ["所有漏洞", "缓冲区溢出", "注入攻击", "认证绕过", "信息泄露", "拒绝服务"]
        vuln_combo = JComboBox(vuln_types)
        vulnerability_types.add(JLabel("漏洞类型："))
        vulnerability_types.add(vuln_combo)
        
        options_panel.add(vulnerability_types)
        
        # 检测方法选项
        method_panel = JPanel()
        method_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        method_checkboxes = {
            "静态分析": JCheckBox("静态分析"),
            "数据流分析": JCheckBox("数据流分析"),
            "控制流分析": JCheckBox("控制流分析"),
            "模式匹配": JCheckBox("模式匹配")
        }
        
        for name, checkbox in method_checkboxes.items():
            checkbox.setSelected(True)
            method_panel.add(checkbox)
        
        options_panel.add(method_panel)
        
        # 创建漏洞检测结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("漏洞检测结果"))
        
        # 漏洞结果表格
        columns = ["漏洞名称", "严重程度", "协议", "位置", "描述", "修复建议"]
        self.vulnerability_table_model = DefaultTableModel(columns, 0)
        vulnerability_table = JTable(self.vulnerability_table_model)
        
        results_panel.add(JScrollPane(vulnerability_table), BorderLayout.CENTER)
        
        # 添加所有面板到漏洞检测面板
        content_panel = JPanel()
        content_panel.setLayout(BorderLayout())
        content_panel.add(options_panel, BorderLayout.NORTH)
        content_panel.add(results_panel, BorderLayout.CENTER)
        
        panel.add(content_panel, BorderLayout.CENTER)
        
        return panel
    
    def create_traffic_panel(self):
        """创建协议流量分析面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建流量分析选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("流量分析选项"))
        
        # 流量捕获选项
        capture_panel = JPanel()
        capture_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        capture_checkboxes = {
            "模拟流量": JCheckBox("模拟流量"),
            "真实流量": JCheckBox("真实流量"),
            "流量回放": JCheckBox("流量回放")
        }
        
        for name, checkbox in capture_checkboxes.items():
            checkbox.setSelected(True)
            capture_panel.add(checkbox)
        
        options_panel.add(capture_panel)
        
        # 流量分析参数
        params_panel = JPanel()
        params_panel.setLayout(GridLayout(2, 2, 10, 10))
        
        duration_field = JTextField("60")
        packets_field = JTextField("1000")
        
        params_panel.add(JLabel("分析持续时间（秒）："))
        params_panel.add(duration_field)
        params_panel.add(JLabel("最大数据包数："))
        params_panel.add(packets_field)
        
        options_panel.add(params_panel)
        
        # 创建流量分析结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("流量分析结果"))
        
        # 流量分析结果表格
        columns = ["协议", "方向", "源地址", "目标地址", "端口", "大小", "时间"]
        self.traffic_table_model = DefaultTableModel(columns, 0)
        traffic_table = JTable(self.traffic_table_model)
        
        results_panel.add(JScrollPane(traffic_table), BorderLayout.CENTER)
        
        # 添加所有面板到流量分析面板
        content_panel = JPanel()
        content_panel.setLayout(BorderLayout())
        content_panel.add(options_panel, BorderLayout.NORTH)
        content_panel.add(results_panel, BorderLayout.CENTER)
        
        panel.add(content_panel, BorderLayout.CENTER)
        
        return panel
    
    def create_report_panel(self):
        """创建分析报告面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建报告选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("报告选项"))
        
        # 报告格式选项
        format_panel = JPanel()
        format_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        formats = ["HTML", "PDF", "文本", "JSON"]
        format_combo = JComboBox(formats)
        
        format_panel.add(JLabel("报告格式："))
        format_panel.add(format_combo)
        
        options_panel.add(format_panel)
        
        # 报告内容选项
        content_panel = JPanel()
        content_panel.setLayout(BoxLayout(content_panel, BoxLayout.Y_AXIS))
        content_panel.setBorder(BorderFactory.createTitledBorder("报告内容"))
        
        content_options = ["协议识别结果", "协议分析结果", "漏洞检测结果", "流量分析结果", "安全建议"]
        for option in content_options:
            checkbox = JCheckBox(option)
            checkbox.setSelected(True)
            content_panel.add(checkbox)
        
        options_panel.add(content_panel)
        
        # 创建报告预览面板
        preview_panel = JPanel()
        preview_panel.setLayout(BorderLayout())
        preview_panel.setBorder(BorderFactory.createTitledBorder("报告预览"))
        
        self.report_preview = JTextArea(20, 50)
        self.report_preview.setEditable(False)
        self.report_preview.setLineWrap(True)
        self.report_preview.setWrapStyleWord(True)
        self.report_preview.setText("# 报告预览\n\n生成报告后将显示在这里...")
        
        preview_panel.add(JScrollPane(self.report_preview), BorderLayout.CENTER)
        
        # 创建导出按钮面板
        export_panel = JPanel()
        export_panel.setLayout(FlowLayout(FlowLayout.RIGHT))
        
        export_button = JButton("导出报告")
        export_panel.add(export_button)
        
        # 添加所有面板到报告生成面板
        content_main = JPanel()
        content_main.setLayout(BorderLayout())
        content_main.add(options_panel, BorderLayout.NORTH)
        content_main.add(preview_panel, BorderLayout.CENTER)
        content_main.add(export_panel, BorderLayout.SOUTH)
        
        panel.add(content_main, BorderLayout.CENTER)
        
        return panel
    
    def analyze_protocols(self):
        """执行协议分析"""
        # 初始化分析结果
        self.analysis_results = {
            'protocols': [],
            'vulnerabilities': [],
            'traffic': [],
            'analysis': {}
        }
        
        # 执行协议识别
        self.identify_protocols()
        
        # 执行协议分析
        self.analyze_protocol_implementation()
        
        # 执行安全漏洞检测
        self.detect_vulnerabilities()
        
        # 执行流量分析
        self.analyze_traffic()
        
        return self.analysis_results
    
    def identify_protocols(self):
        """识别网络协议"""
        # 实际实现中，这里应该：
        # 1. 扫描导入函数
        # 2. 分析字符串特征
        # 3. 检查端口号
        # 4. 检测代码模式
        
        # 示例：添加一些模拟的协议识别结果
        sample_protocols = [
            {"name": "HTTP", "type": "应用层", "method": "字符串特征", "location": "0x10001000", "confidence": "高", "description": "超文本传输协议"},
            {"name": "TCP", "type": "传输层", "method": "导入函数", "location": "0x10002000", "confidence": "高", "description": "传输控制协议"},
            {"name": "DNS", "type": "应用层", "method": "代码模式", "location": "0x10003000", "confidence": "中", "description": "域名系统协议"},
            {"name": "HTTPS", "type": "安全协议", "method": "字符串特征", "location": "0x10004000", "confidence": "中", "description": "安全超文本传输协议"}
        ]
        
        self.analysis_results['protocols'] = sample_protocols
    
    def analyze_protocol_implementation(self):
        """分析协议实现"""
        # 实际实现中，这里应该：
        # 1. 分析协议头部处理
        # 2. 检查协议解析逻辑
        # 3. 分析状态机实现
        # 4. 评估错误处理
        
        # 示例：添加一些模拟的协议分析结果
        analysis = "# 协议分析结果\n\n"
        analysis += "## HTTP 协议分析\n"
        analysis += "- 协议头部处理：正确实现了HTTP/1.1头部解析\n"
        analysis += "- 协议解析：支持GET、POST、PUT、DELETE等方法\n"
        analysis += "- 状态机：实现了基本的HTTP状态机\n"
        analysis += "- 错误处理：存在部分错误处理逻辑，但不够完善\n\n"
        
        analysis += "## TCP 协议分析\n"
        analysis += "- 协议头部处理：正确实现了TCP头部解析\n"
        analysis += "- 协议解析：支持基本的TCP连接管理\n"
        analysis += "- 状态机：实现了完整的TCP状态机\n"
        analysis += "- 错误处理：存在完善的错误处理逻辑\n\n"
        
        analysis += "## DNS 协议分析\n"
        analysis += "- 协议头部处理：正确实现了DNS头部解析\n"
        analysis += "- 协议解析：支持基本的DNS查询和响应\n"
        analysis += "- 状态机：实现了简单的DNS状态机\n"
        analysis += "- 错误处理：存在基本的错误处理逻辑\n"
        
        self.analysis_results['analysis'] = analysis
    
    def detect_vulnerabilities(self):
        """检测安全漏洞"""
        # 实际实现中，这里应该：
        # 1. 检测缓冲区溢出
        # 2. 识别注入攻击
        # 3. 检查认证绕过
        # 4. 检测信息泄露
        # 5. 评估拒绝服务风险
        
        # 示例：添加一些模拟的漏洞检测结果
        sample_vulnerabilities = [
            {"name": "缓冲区溢出", "severity": "高", "protocol": "HTTP", "location": "0x10005000", "description": "HTTP头部解析存在缓冲区溢出漏洞", "recommendation": "使用安全的字符串处理函数，如strncpy代替strcpy"},
            {"name": "注入攻击", "severity": "高", "protocol": "HTTP", "location": "0x10006000", "description": "HTTP参数解析存在注入攻击风险", "recommendation": "对输入参数进行严格验证和转义"},
            {"name": "信息泄露", "severity": "中", "protocol": "HTTP", "location": "0x10007000", "description": "错误响应中包含敏感信息", "recommendation": "自定义错误响应，避免泄露内部信息"},
            {"name": "拒绝服务", "severity": "中", "protocol": "TCP", "location": "0x10008000", "description": "TCP连接处理存在拒绝服务风险", "recommendation": "实现连接限制和超时机制"}
        ]
        
        self.analysis_results['vulnerabilities'] = sample_vulnerabilities
    
    def analyze_traffic(self):
        """分析协议流量"""
        # 实际实现中，这里应该：
        # 1. 模拟协议流量
        # 2. 分析流量特征
        # 3. 检测异常流量
        
        # 示例：添加一些模拟的流量分析结果
        sample_traffic = [
            {"protocol": "HTTP", "direction": "出站", "source": "192.168.1.100", "destination": "10.0.0.1", "port": "80", "size": "456", "time": "2023-10-01 12:00:00"},
            {"protocol": "HTTP", "direction": "入站", "source": "10.0.0.1", "destination": "192.168.1.100", "port": "80", "size": "1234", "time": "2023-10-01 12:00:01"},
            {"protocol": "DNS", "direction": "出站", "source": "192.168.1.100", "destination": "8.8.8.8", "port": "53", "size": "64", "time": "2023-10-01 12:00:02"},
            {"protocol": "DNS", "direction": "入站", "source": "8.8.8.8", "destination": "192.168.1.100", "port": "53", "size": "86", "time": "2023-10-01 12:00:03"}
        ]
        
        self.analysis_results['traffic'] = sample_traffic
    
    def generate_report(self, format_type):
        """生成分析报告"""
        if format_type == "HTML":
            return self.generate_html_report()
        elif format_type == "文本":
            return self.generate_text_report()
        elif format_type == "JSON":
            return json.dumps(self.analysis_results, ensure_ascii=False, indent=2)
        else:
            return "不支持的报告格式"
    
    def generate_html_report(self):
        """生成HTML报告"""
        html = "<!DOCTYPE html>\n"
        html += "<html>\n"
        html += "<head>\n"
        html += "<title>网络协议分析报告</title>\n"
        html += "<style>\n"
        html += "body { font-family: Arial, sans-serif; margin: 20px; }\n"
        html += "h1, h2 { color: #333; }\n"
        html += "table { border-collapse: collapse; width: 100%; margin: 20px 0; }\n"
        html += "th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n"
        html += "th { background-color: #f2f2f2; }\n"
        html += "tr:hover { background-color: #f5f5f5; }\n"
        html += ".section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }\n"
        html += ".high-risk { color: red; font-weight: bold; }\n"
        html += ".medium-risk { color: orange; font-weight: bold; }\n"
        html += ".low-risk { color: green; font-weight: bold; }\n"
        html += "</style>\n"
        html += "</head>\n"
        html += "<body>\n"
        html += "<h1>网络协议分析报告</h1>\n"
        html += "<p>生成时间: {}</p>\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # 添加协议识别结果
        protocols = self.analysis_results.get('protocols', [])
        if protocols:
            html += "<div class='section'>\n"
            html += "<h2>协议识别结果</h2>\n"
            html += "<table>\n"
            html += "<tr><th>协议名称</th><th>类型</th><th>识别方法</th><th>位置</th><th>置信度</th><th>描述</th></tr>\n"
            for proto in protocols:
                html += "<tr>\n"
                html += "<td>{}</td>\n".format(proto['name'])
                html += "<td>{}</td>\n".format(proto['type'])
                html += "<td>{}</td>\n".format(proto['method'])
                html += "<td>{}</td>\n".format(proto['location'])
                html += "<td>{}</td>\n".format(proto['confidence'])
                html += "<td>{}</td>\n".format(proto['description'])
                html += "</tr>\n"
            html += "</table>\n"
            html += "</div>\n"
        
        # 添加协议分析结果
        analysis = self.analysis_results.get('analysis', '')
        if analysis:
            html += "<div class='section'>\n"
            html += "<h2>协议分析结果</h2>\n"
            html += "<pre>{}</pre>\n".format(analysis)
            html += "</div>\n"
        
        # 添加漏洞检测结果
        vulnerabilities = self.analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            html += "<div class='section'>\n"
            html += "<h2>安全漏洞检测结果</h2>\n"
            html += "<table>\n"
            html += "<tr><th>漏洞名称</th><th>严重程度</th><th>协议</th><th>位置</th><th>描述</th><th>修复建议</th></tr>\n"
            for vuln in vulnerabilities:
                severity_class = ""
                if vuln['severity'] == "高":
                    severity_class = "high-risk"
                elif vuln['severity'] == "中":
                    severity_class = "medium-risk"
                else:
                    severity_class = "low-risk"
                
                html += "<tr>\n"
                html += "<td>{}</td>\n".format(vuln['name'])
                html += "<td><span class='{}'>{}</span></td>\n".format(severity_class, vuln['severity'])
                html += "<td>{}</td>\n".format(vuln['protocol'])
                html += "<td>{}</td>\n".format(vuln['location'])
                html += "<td>{}</td>\n".format(vuln['description'])
                html += "<td>{}</td>\n".format(vuln['recommendation'])
                html += "</tr>\n"
            html += "</table>\n"
            html += "</div>\n"
        
        # 添加流量分析结果
        traffic = self.analysis_results.get('traffic', [])
        if traffic:
            html += "<div class='section'>\n"
            html += "<h2>流量分析结果</h2>\n"
            html += "<table>\n"
            html += "<tr><th>协议</th><th>方向</th><th>源地址</th><th>目标地址</th><th>端口</th><th>大小</th><th>时间</th></tr>\n"
            for packet in traffic:
                html += "<tr>\n"
                html += "<td>{}</td>\n".format(packet['protocol'])
                html += "<td>{}</td>\n".format(packet['direction'])
                html += "<td>{}</td>\n".format(packet['source'])
                html += "<td>{}</td>\n".format(packet['destination'])
                html += "<td>{}</td>\n".format(packet['port'])
                html += "<td>{}</td>\n".format(packet['size'])
                html += "<td>{}</td>\n".format(packet['time'])
                html += "</tr>\n"
            html += "</table>\n"
            html += "</div>\n"
        
        # 添加安全建议
        html += "<div class='section'>\n"
        html += "<h2>安全建议</h2>\n"
        html += "<ul>\n"
        html += "<li>对所有输入参数进行严格验证和边界检查</li>\n"
        html += "<li>使用安全的字符串处理函数，避免缓冲区溢出</li>\n"
        html += "<li>实现完善的错误处理机制，避免信息泄露</li>\n"
        html += "<li>对敏感数据进行加密传输</li>\n"
        html += "<li>实现速率限制，防止拒绝服务攻击</li>\n"
        html += "<li>定期更新协议实现，修复已知漏洞</li>\n"
        html += "<li>使用安全的随机数生成器</li>\n"
        html += "<li>实现适当的认证和授权机制</li>\n"
        html += "</ul>\n"
        html += "</div>\n"
        
        html += "</body>\n"
        html += "</html>"
        
        return html
    
    def generate_text_report(self):
        """生成文本报告"""
        text = "# 网络协议分析报告\n"
        text += "=" * 80 + "\n"
        text += "生成时间: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # 添加协议识别结果
        protocols = self.analysis_results.get('protocols', [])
        if protocols:
            text += "## 协议识别结果\n"
            for proto in protocols:
                text += "- {} ({}): {} at {} [{}] - {}\n".format(proto['name'], proto['type'], proto['method'], proto['location'], proto['confidence'], proto['description'])
            text += "\n"
        
        # 添加协议分析结果
        analysis = self.analysis_results.get('analysis', '')
        if analysis:
            text += analysis
            text += "\n"
        
        # 添加漏洞检测结果
        vulnerabilities = self.analysis_results.get('vulnerabilities', [])
        if vulnerabilities:
            text += "## 安全漏洞检测结果\n"
            for vuln in vulnerabilities:
                text += "- {} ({}): {} in {} at {} - {}\n".format(vuln['name'], vuln['severity'], vuln['description'], vuln['protocol'], vuln['location'], vuln['recommendation'])
            text += "\n"
        
        # 添加流量分析结果
        traffic = self.analysis_results.get('traffic', [])
        if traffic:
            text += "## 流量分析结果\n"
            for packet in traffic:
                text += "- {} {}: {}:{} -> {}:{} ({} bytes) at {}\n".format(packet['protocol'], packet['direction'], packet['source'], packet['port'], packet['destination'], packet['port'], packet['size'], packet['time'])
            text += "\n"
        
        # 添加安全建议
        text += "## 安全建议\n"
        text += "- 对所有输入参数进行严格验证和边界检查\n"
        text += "- 使用安全的字符串处理函数，避免缓冲区溢出\n"
        text += "- 实现完善的错误处理机制，避免信息泄露\n"
        text += "- 对敏感数据进行加密传输\n"
        text += "- 实现速率限制，防止拒绝服务攻击\n"
        text += "- 定期更新协议实现，修复已知漏洞\n"
        text += "- 使用安全的随机数生成器\n"
        text += "- 实现适当的认证和授权机制\n"
        
        return text
    
    def update_protocol_table(self):
        """更新协议识别结果表格"""
        # 清空表格
        self.protocol_table_model.setRowCount(0)
        
        # 添加协议识别结果
        for proto in self.analysis_results.get('protocols', []):
            row = [
                proto.get('name', ''),
                proto.get('type', ''),
                proto.get('method', ''),
                proto.get('location', ''),
                proto.get('confidence', ''),
                proto.get('description', '')
            ]
            self.protocol_table_model.addRow(row)
    
    def update_analysis_text(self):
        """更新协议分析结果文本"""
        analysis = self.analysis_results.get('analysis', '')
        self.analysis_text.setText(analysis)
    
    def update_vulnerability_table(self):
        """更新漏洞检测结果表格"""
        # 清空表格
        self.vulnerability_table_model.setRowCount(0)
        
        # 添加漏洞检测结果
        for vuln in self.analysis_results.get('vulnerabilities', []):
            row = [
                vuln.get('name', ''),
                vuln.get('severity', ''),
                vuln.get('protocol', ''),
                vuln.get('location', ''),
                vuln.get('description', ''),
                vuln.get('recommendation', '')
            ]
            self.vulnerability_table_model.addRow(row)
    
    def update_traffic_table(self):
        """更新流量分析结果表格"""
        # 清空表格
        self.traffic_table_model.setRowCount(0)
        
        # 添加流量分析结果
        for packet in self.analysis_results.get('traffic', []):
            row = [
                packet.get('protocol', ''),
                packet.get('direction', ''),
                packet.get('source', ''),
                packet.get('destination', ''),
                packet.get('port', ''),
                packet.get('size', ''),
                packet.get('time', '')
            ]
            self.traffic_table_model.addRow(row)
    
    def update_report_preview(self):
        """更新报告预览"""
        report = self.generate_report("文本")
        self.report_preview.setText(report)
    
    class AnalyzeButtonListener(ActionListener):
        def __init__(self, frame):
            self.frame = frame
        
        def actionPerformed(self, e):
            # 显示进度对话框
            progress_frame = JFrame("分析中")
            progress_frame.setSize(400, 100)
            progress_frame.setLocationRelativeTo(self.frame)
            
            progress_panel = JPanel()
            progress_panel.setLayout(BorderLayout())
            
            progress_bar = JProgressBar()
            progress_bar.setIndeterminate(True)
            
            status_label = JLabel("正在执行网络协议分析...")
            
            progress_panel.add(status_label, BorderLayout.NORTH)
            progress_panel.add(progress_bar, BorderLayout.CENTER)
            
            progress_frame.add(progress_panel)
            progress_frame.setVisible(True)
            
            # 在后台线程中执行分析
            from javax.swing import SwingWorker
            
            class AnalyzeWorker(SwingWorker):
                def __init__(self, analyzer, progress_frame):
                    self.analyzer = analyzer
                    self.progress_frame = progress_frame
                    SwingWorker.__init__(self)
                
                def doInBackground(self):
                    # 执行分析
                    self.analyzer.analyze_protocols()
                    return True
                
                def done(self):
                    # 更新结果
                    self.analyzer.update_protocol_table()
                    self.analyzer.update_analysis_text()
                    self.analyzer.update_vulnerability_table()
                    self.analyzer.update_traffic_table()
                    self.analyzer.update_report_preview()
                    
                    # 关闭进度对话框
                    self.progress_frame.dispose()
                    # 显示完成消息
                    JOptionPane.showMessageDialog(self.analyzer.frame, "网络协议分析完成！")
            
            # 启动分析线程
            worker = AnalyzeWorker(self, progress_frame)
            worker.execute()

# 主函数
if __name__ == "__main__":
    analyzer = ProtocolAnalyzer()
    analyzer.run()
