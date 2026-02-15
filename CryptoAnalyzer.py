#!/usr/bin/env python3
# CryptoAnalyzer.py - 识别和分析加密算法和密钥
# 功能：识别常见加密算法、分析密钥、检测密码学实现缺陷

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

class CryptoAnalyzer(GhidraScript):
    def __init__(self):
        self.program = None
        self.analysis_results = {}
        self.crypto_algorithms = {
            'AES': {'patterns': ['AES_', 'aes_', 'CryptEncrypt', 'AES_set_encrypt_key'], 'description': '高级加密标准'},
            'RSA': {'patterns': ['RSA_', 'rsa_', 'RSASign', 'RSA_encrypt'], 'description': 'RSA公钥加密算法'},
            'DES': {'patterns': ['DES_', 'des_', 'CryptEncrypt'], 'description': '数据加密标准'},
            '3DES': {'patterns': ['3DES_', 'des3_', 'TripleDES'], 'description': '三重数据加密标准'},
            'MD5': {'patterns': ['MD5_', 'md5_', 'MD5Init', 'MD5Update'], 'description': 'MD5哈希算法'},
            'SHA1': {'patterns': ['SHA1_', 'sha1_', 'SHAInit', 'SHAUpdate'], 'description': 'SHA-1哈希算法'},
            'SHA256': {'patterns': ['SHA256_', 'sha256_', 'SHA256_Init', 'SHA256_Update'], 'description': 'SHA-256哈希算法'},
            'Blowfish': {'patterns': ['Blowfish_', 'blowfish_', 'BF_set_key'], 'description': 'Blowfish加密算法'},
            'RC4': {'patterns': ['RC4_', 'rc4_', 'ARC4'], 'description': 'RC4流加密算法'},
            'ECC': {'patterns': ['ECC_', 'ecc_', 'EC_KEY', 'EC_POINT'], 'description': '椭圆曲线密码学'}
        }
        self.key_patterns = [
            {'name': '固定密钥', 'pattern': r'0x[0-9a-fA-F]{16,}', 'description': '可能的固定密钥'},
            {'name': '密钥数组', 'pattern': r'unsigned char\s+key\[\d+\]\s*=\s*\{[^}]+\}', 'description': '可能的密钥数组'},
            {'name': '硬编码密钥', 'pattern': r'"[0-9a-fA-F]{16,}"', 'description': '可能的硬编码密钥'},
            {'name': 'Base64编码密钥', 'pattern': r'[A-Za-z0-9+/]{24,}=*', 'description': '可能的Base64编码密钥'}
        ]
    
    def run(self):
        """运行加密分析器"""
        self.program = self.getCurrentProgram()
        if not self.program:
            self.println("没有打开的程序")
            return
        
        self.show_crypto_analyzer()
    
    def show_crypto_analyzer(self):
        """显示加密分析器界面"""
        frame = JFrame("Crypto Analyzer - 加密算法和密钥分析工具")
        frame.setSize(1000, 700)
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setLocationRelativeTo(None)
        
        # 创建主面板
        main_panel = JPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建标签页
        tabbed_pane = JTabbedPane()
        
        # 加密算法识别标签
        algorithm_panel = self.create_algorithm_panel()
        tabbed_pane.addTab("加密算法识别", algorithm_panel)
        
        # 密钥分析标签
        key_panel = self.create_key_panel()
        tabbed_pane.addTab("密钥分析", key_panel)
        
        # 密码学缺陷检测标签
        flaw_panel = self.create_flaw_panel()
        tabbed_pane.addTab("密码学缺陷检测", flaw_panel)
        
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
    
    def create_algorithm_panel(self):
        """创建加密算法识别面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建算法识别选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("算法识别选项"))
        
        # 算法类型选项
        algo_types = JPanel()
        algo_types.setLayout(FlowLayout(FlowLayout.LEFT))
        
        algo_combo = JComboBox(["所有算法", "对称加密", "非对称加密", "哈希函数", "流加密"])
        algo_types.add(JLabel("算法类型："))
        algo_types.add(algo_combo)
        
        options_panel.add(algo_types)
        
        # 识别方法选项
        method_panel = JPanel()
        method_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        method_checkboxes = {
            "导入函数": JCheckBox("导入函数"),
            "字符串特征": JCheckBox("字符串特征"),
            "代码模式": JCheckBox("代码模式"),
            "常量特征": JCheckBox("常量特征")
        }
        
        for name, checkbox in method_checkboxes.items():
            checkbox.setSelected(True)
            method_panel.add(checkbox)
        
        options_panel.add(method_panel)
        
        # 创建算法识别结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("算法识别结果"))
        
        # 算法结果表格
        columns = ["算法名称", "类型", "识别方法", "位置", "置信度", "描述"]
        self.algorithm_table_model = DefaultTableModel(columns, 0)
        algorithm_table = JTable(self.algorithm_table_model)
        
        results_panel.add(JScrollPane(algorithm_table), BorderLayout.CENTER)
        
        # 添加所有面板到算法识别面板
        content_panel = JPanel()
        content_panel.setLayout(BorderLayout())
        content_panel.add(options_panel, BorderLayout.NORTH)
        content_panel.add(results_panel, BorderLayout.CENTER)
        
        panel.add(content_panel, BorderLayout.CENTER)
        
        return panel
    
    def create_key_panel(self):
        """创建密钥分析面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建密钥分析选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("密钥分析选项"))
        
        # 密钥类型选项
        key_types = JPanel()
        key_types.setLayout(FlowLayout(FlowLayout.LEFT))
        
        key_type_checkboxes = {
            "固定密钥": JCheckBox("固定密钥"),
            "密钥数组": JCheckBox("密钥数组"),
            "硬编码密钥": JCheckBox("硬编码密钥"),
            "Base64编码密钥": JCheckBox("Base64编码密钥")
        }
        
        for name, checkbox in key_type_checkboxes.items():
            checkbox.setSelected(True)
            key_types.add(checkbox)
        
        options_panel.add(key_types)
        
        # 密钥长度选项
        length_panel = JPanel()
        length_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        
        length_combo = JComboBox(["所有长度", "16字节 (128位)", "24字节 (192位)", "32字节 (256位)", "自定义"])
        length_panel.add(JLabel("密钥长度："))
        length_panel.add(length_combo)
        
        options_panel.add(length_panel)
        
        # 自定义长度选项
        custom_length = JPanel()
        custom_length.setLayout(FlowLayout(FlowLayout.LEFT))
        
        min_length = JTextField(5)
        max_length = JTextField(5)
        
        custom_length.add(JLabel("最小长度："))
        custom_length.add(min_length)
        custom_length.add(JLabel("  最大长度："))
        custom_length.add(max_length)
        
        options_panel.add(custom_length)
        
        # 创建密钥分析结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("密钥分析结果"))
        
        # 密钥结果表格
        columns = ["密钥类型", "位置", "长度", "内容", "描述"]
        self.key_table_model = DefaultTableModel(columns, 0)
        key_table = JTable(self.key_table_model)
        
        results_panel.add(JScrollPane(key_table), BorderLayout.CENTER)
        
        # 添加所有面板到密钥分析面板
        content_panel = JPanel()
        content_panel.setLayout(BorderLayout())
        content_panel.add(options_panel, BorderLayout.NORTH)
        content_panel.add(results_panel, BorderLayout.CENTER)
        
        panel.add(content_panel, BorderLayout.CENTER)
        
        return panel
    
    def create_flaw_panel(self):
        """创建密码学缺陷检测面板"""
        panel = JPanel()
        panel.setLayout(BorderLayout())
        
        # 创建缺陷检测选项面板
        options_panel = JPanel()
        options_panel.setLayout(BoxLayout(options_panel, BoxLayout.Y_AXIS))
        options_panel.setBorder(BorderFactory.createTitledBorder("缺陷检测选项"))
        
        # 缺陷类型选项
        flaw_types = JPanel()
        flaw_types.setLayout(FlowLayout(FlowLayout.LEFT))
        
        flaw_checkboxes = {
            "弱加密算法": JCheckBox("弱加密算法"),
            "硬编码密钥": JCheckBox("硬编码密钥"),
            "不安全的随机数": JCheckBox("不安全的随机数"),
            "密钥管理缺陷": JCheckBox("密钥管理缺陷"),
            "填充 Oracle 漏洞": JCheckBox("填充 Oracle 漏洞"),
            "侧信道攻击风险": JCheckBox("侧信道攻击风险")
        }
        
        for name, checkbox in flaw_checkboxes.items():
            checkbox.setSelected(True)
            flaw_types.add(checkbox)
        
        options_panel.add(flaw_types)
        
        # 创建缺陷检测结果面板
        results_panel = JPanel()
        results_panel.setLayout(BorderLayout())
        results_panel.setBorder(BorderFactory.createTitledBorder("缺陷检测结果"))
        
        # 缺陷结果表格
        columns = ["缺陷名称", "严重程度", "位置", "描述", "修复建议"]
        self.flaw_table_model = DefaultTableModel(columns, 0)
        flaw_table = JTable(self.flaw_table_model)
        
        results_panel.add(JScrollPane(flaw_table), BorderLayout.CENTER)
        
        # 添加所有面板到缺陷检测面板
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
        
        content_options = ["算法识别结果", "密钥分析结果", "缺陷检测结果", "安全建议", "详细分析"]
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
    
    def analyze_crypto(self):
        """执行加密分析"""
        # 初始化分析结果
        self.analysis_results = {
            'algorithms': [],
            'keys': [],
            'flaws': []
        }
        
        # 执行加密算法识别
        self.identify_algorithms()
        
        # 执行密钥分析
        self.analyze_keys()
        
        # 执行密码学缺陷检测
        self.detect_crypto_flaws()
        
        return self.analysis_results
    
    def identify_algorithms(self):
        """识别加密算法"""
        # 实际实现中，这里应该：
        # 1. 扫描导入函数
        # 2. 分析字符串特征
        # 3. 检测代码模式
        # 4. 识别常量特征
        
        # 示例：添加一些模拟的算法识别结果
        sample_algorithms = [
            {"name": "AES", "type": "对称加密", "method": "导入函数", "location": "0x10001000", "confidence": "高", "description": "高级加密标准"},
            {"name": "RSA", "type": "非对称加密", "method": "字符串特征", "location": "0x10002000", "confidence": "中", "description": "RSA公钥加密算法"},
            {"name": "MD5", "type": "哈希函数", "method": "代码模式", "location": "0x10003000", "confidence": "高", "description": "MD5哈希算法"},
            {"name": "SHA256", "type": "哈希函数", "method": "常量特征", "location": "0x10004000", "confidence": "中", "description": "SHA-256哈希算法"},
            {"name": "RC4", "type": "流加密", "method": "导入函数", "location": "0x10005000", "confidence": "高", "description": "RC4流加密算法"}
        ]
        
        self.analysis_results['algorithms'] = sample_algorithms
    
    def analyze_keys(self):
        """分析密钥"""
        # 实际实现中，这里应该：
        # 1. 扫描固定密钥
        # 2. 分析密钥数组
        # 3. 检测硬编码密钥
        # 4. 识别Base64编码密钥
        
        # 示例：添加一些模拟的密钥分析结果
        sample_keys = [
            {"type": "固定密钥", "location": "0x10006000", "length": "32字节", "content": "0x0123456789ABCDEF0123456789ABCDEF", "description": "可能的固定密钥"},
            {"type": "密钥数组", "location": "0x10007000", "length": "16字节", "content": "{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}", "description": "可能的密钥数组"},
            {"type": "硬编码密钥", "location": "0x10008000", "length": "24字节", "content": "\"ABCDEF0123456789ABCDEF0123456789\"", "description": "可能的硬编码密钥"},
            {"type": "Base64编码密钥", "location": "0x10009000", "length": "24字节", "content": "SGVsbG8gV29ybGQhIC0gQnJlYWsgaW4gdGhlIHBhc3MK", "description": "可能的Base64编码密钥"}
        ]
        
        self.analysis_results['keys'] = sample_keys
    
    def detect_crypto_flaws(self):
        """检测密码学缺陷"""
        # 实际实现中，这里应该：
        # 1. 检测弱加密算法
        # 2. 识别硬编码密钥
        # 3. 检测不安全的随机数
        # 4. 分析密钥管理缺陷
        # 5. 检测填充 Oracle 漏洞
        # 6. 评估侧信道攻击风险
        
        # 示例：添加一些模拟的缺陷检测结果
        sample_flaws = [
            {"name": "弱加密算法", "severity": "高", "location": "0x1000A000", "description": "使用了不安全的MD5哈希算法", "recommendation": "替换为SHA-256或更安全的哈希算法"},
            {"name": "硬编码密钥", "severity": "高", "location": "0x1000B000", "description": "发现硬编码的加密密钥", "recommendation": "使用安全的密钥管理方案，如密钥派生函数或硬件安全模块"},
            {"name": "不安全的随机数", "severity": "中", "location": "0x1000C000", "description": "使用了不安全的随机数生成器", "recommendation": "替换为密码学安全的随机数生成器，如/dev/urandom或CryptGenRandom"},
            {"name": "密钥管理缺陷", "severity": "中", "location": "0x1000D000", "description": "密钥存储不安全", "recommendation": "使用安全的密钥存储机制，避免明文存储密钥"},
            {"name": "侧信道攻击风险", "severity": "低", "location": "0x1000E000", "description": "加密实现可能容易受到侧信道攻击", "recommendation": "实现恒定时间加密操作，避免基于密钥的分支和内存访问"}
        ]
        
        self.analysis_results['flaws'] = sample_flaws
    
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
        html += "<title>加密分析报告</title>\n"
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
        html += "<h1>加密分析报告</h1>\n"
        html += "<p>生成时间: {}</p>\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # 添加算法识别结果
        algorithms = self.analysis_results.get('algorithms', [])
        if algorithms:
            html += "<div class='section'>\n"
            html += "<h2>加密算法识别结果</h2>\n"
            html += "<table>\n"
            html += "<tr><th>算法名称</th><th>类型</th><th>识别方法</th><th>位置</th><th>置信度</th><th>描述</th></tr>\n"
            for algo in algorithms:
                html += "<tr>\n"
                html += "<td>{}</td>\n".format(algo['name'])
                html += "<td>{}</td>\n".format(algo['type'])
                html += "<td>{}</td>\n".format(algo['method'])
                html += "<td>{}</td>\n".format(algo['location'])
                html += "<td>{}</td>\n".format(algo['confidence'])
                html += "<td>{}</td>\n".format(algo['description'])
                html += "</tr>\n"
            html += "</table>\n"
            html += "</div>\n"
        
        # 添加密钥分析结果
        keys = self.analysis_results.get('keys', [])
        if keys:
            html += "<div class='section'>\n"
            html += "<h2>密钥分析结果</h2>\n"
            html += "<table>\n"
            html += "<tr><th>密钥类型</th><th>位置</th><th>长度</th><th>内容</th><th>描述</th></tr>\n"
            for key in keys:
                html += "<tr>\n"
                html += "<td>{}</td>\n".format(key['type'])
                html += "<td>{}</td>\n".format(key['location'])
                html += "<td>{}</td>\n".format(key['length'])
                html += "<td>{}</td>\n".format(key['content'])
                html += "<td>{}</td>\n".format(key['description'])
                html += "</tr>\n"
            html += "</table>\n"
            html += "</div>\n"
        
        # 添加缺陷检测结果
        flaws = self.analysis_results.get('flaws', [])
        if flaws:
            html += "<div class='section'>\n"
            html += "<h2>密码学缺陷检测结果</h2>\n"
            html += "<table>\n"
            html += "<tr><th>缺陷名称</th><th>严重程度</th><th>位置</th><th>描述</th><th>修复建议</th></tr>\n"
            for flaw in flaws:
                severity_class = ""
                if flaw['severity'] == "高":
                    severity_class = "high-risk"
                elif flaw['severity'] == "中":
                    severity_class = "medium-risk"
                else:
                    severity_class = "low-risk"
                
                html += "<tr>\n"
                html += "<td>{}</td>\n".format(flaw['name'])
                html += "<td><span class='{}'>{}</span></td>\n".format(severity_class, flaw['severity'])
                html += "<td>{}</td>\n".format(flaw['location'])
                html += "<td>{}</td>\n".format(flaw['description'])
                html += "<td>{}</td>\n".format(flaw['recommendation'])
                html += "</tr>\n"
            html += "</table>\n"
            html += "</div>\n"
        
        # 添加安全建议
        html += "<div class='section'>\n"
        html += "<h2>安全建议</h2>\n"
        html += "<ul>\n"
        html += "<li>使用强加密算法，如AES-256、RSA-2048或更高</li>\n"
        html += "<li>避免硬编码密钥，使用安全的密钥管理方案</li>\n"
        html += "<li>使用密码学安全的随机数生成器</li>\n"
        html += "<li>定期更新加密实现，修复已知漏洞</li>\n"
        html += "<li>实施适当的密钥轮换机制</li>\n"
        html += "<li>使用恒定时间加密操作，防止侧信道攻击</li>\n"
        html += "<li>考虑使用硬件安全模块(HSM)存储密钥</li>\n"
        html += "</ul>\n"
        html += "</div>\n"
        
        html += "</body>\n"
        html += "</html>"
        
        return html
    
    def generate_text_report(self):
        """生成文本报告"""
        text = "# 加密分析报告\n"
        text += "=" * 80 + "\n"
        text += "生成时间: {}\n\n".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        
        # 添加算法识别结果
        algorithms = self.analysis_results.get('algorithms', [])
        if algorithms:
            text += "## 加密算法识别结果\n"
            for algo in algorithms:
                text += "- {} ({}): {} at {} [{}] - {}\n".format(algo['name'], algo['type'], algo['method'], algo['location'], algo['confidence'], algo['description'])
            text += "\n"
        
        # 添加密钥分析结果
        keys = self.analysis_results.get('keys', [])
        if keys:
            text += "## 密钥分析结果\n"
            for key in keys:
                text += "- {}: {} at {} ({} bytes) - {}\n".format(key['type'], key['content'], key['location'], key['length'], key['description'])
            text += "\n"
        
        # 添加缺陷检测结果
        flaws = self.analysis_results.get('flaws', [])
        if flaws:
            text += "## 密码学缺陷检测结果\n"
            for flaw in flaws:
                text += "- {} ({}): {} at {} - {}\n".format(flaw['name'], flaw['severity'], flaw['description'], flaw['location'], flaw['recommendation'])
            text += "\n"
        
        # 添加安全建议
        text += "## 安全建议\n"
        text += "- 使用强加密算法，如AES-256、RSA-2048或更高\n"
        text += "- 避免硬编码密钥，使用安全的密钥管理方案\n"
        text += "- 使用密码学安全的随机数生成器\n"
        text += "- 定期更新加密实现，修复已知漏洞\n"
        text += "- 实施适当的密钥轮换机制\n"
        text += "- 使用恒定时间加密操作，防止侧信道攻击\n"
        text += "- 考虑使用硬件安全模块(HSM)存储密钥\n"
        
        return text
    
    def update_algorithm_table(self):
        """更新算法识别结果表格"""
        # 清空表格
        self.algorithm_table_model.setRowCount(0)
        
        # 添加算法识别结果
        for algo in self.analysis_results.get('algorithms', []):
            row = [
                algo.get('name', ''),
                algo.get('type', ''),
                algo.get('method', ''),
                algo.get('location', ''),
                algo.get('confidence', ''),
                algo.get('description', '')
            ]
            self.algorithm_table_model.addRow(row)
    
    def update_key_table(self):
        """更新密钥分析结果表格"""
        # 清空表格
        self.key_table_model.setRowCount(0)
        
        # 添加密钥分析结果
        for key in self.analysis_results.get('keys', []):
            row = [
                key.get('type', ''),
                key.get('location', ''),
                key.get('length', ''),
                key.get('content', ''),
                key.get('description', '')
            ]
            self.key_table_model.addRow(row)
    
    def update_flaw_table(self):
        """更新缺陷检测结果表格"""
        # 清空表格
        self.flaw_table_model.setRowCount(0)
        
        # 添加缺陷检测结果
        for flaw in self.analysis_results.get('flaws', []):
            row = [
                flaw.get('name', ''),
                flaw.get('severity', ''),
                flaw.get('location', ''),
                flaw.get('description', ''),
                flaw.get('recommendation', '')
            ]
            self.flaw_table_model.addRow(row)
    
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
            
            status_label = JLabel("正在执行加密分析...")
            
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
                    self.analyzer.analyze_crypto()
                    return True
                
                def done(self):
                    # 更新结果
                    self.analyzer.update_algorithm_table()
                    self.analyzer.update_key_table()
                    self.analyzer.update_flaw_table()
                    self.analyzer.update_report_preview()
                    
                    # 关闭进度对话框
                    self.progress_frame.dispose()
                    # 显示完成消息
                    JOptionPane.showMessageDialog(self.analyzer.frame, "加密分析完成！")
            
            # 启动分析线程
            worker = AnalyzeWorker(self, progress_frame)
            worker.execute()

# 主函数
if __name__ == "__main__":
    analyzer = CryptoAnalyzer()
    analyzer.run()
