#!/usr/bin/env python3
# CallTreeVisualizer.py - 交互式调用树可视化工具
# 功能：显示函数调用关系树、支持展开/折叠、搜索过滤、详情查看

import os
import json
import re
from datetime import datetime
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Dimension, Point
from java.awt.event import ActionListener, ItemListener, MouseAdapter, MouseEvent
from javax.swing import (
    JFrame, JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, 
    JCheckBox, JLabel, JComboBox, JTextField, JOptionPane, JTable, 
    DefaultTableModel, JFileChooser, JProgressBar, JMenuBar, JMenu, JMenuItem,
    BoxLayout, BorderFactory, JTree, DefaultMutableTreeNode, JSplitPane,
    JToolBar, JToggleButton, JPopupMenu, JScrollPane as SwingJScrollPane,
    JTextPane, JList, DefaultListModel
)
from javax.swing.border import LineBorder
from javax.swing.tree import TreeSelectionModel
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import Symbol, RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException

class CallTreeVisualizer(GhidraScript):
    def __init__(self):
        self.program = None
        self.call_tree = None
        self.current_function = None
        self.tree_model = None
        self.function_details = {}
        self.expansion_state = {}
        self.search_results = []
        self.filter_pattern = ""
        self.max_depth = 10
        self.show_recursive = False
        self.show_system_calls = True
        self.show_library_functions = True
    
    def run(self):
        """运行调用树可视化工具"""
        self.program = self.getCurrentProgram()
        if not self.program:
            self.println("没有打开的程序")
            return
        
        self.show_call_tree_visualizer()
    
    def show_call_tree_visualizer(self):
        """显示调用树可视化工具界面"""
        frame = JFrame("Call Tree Visualizer - 交互式调用树可视化工具")
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
        function_combo.setToolTipText("选择起始函数")
        toolbar.add(function_combo)
        toolbar.addSeparator()
        
        # 操作按钮
        expand_all_button = JButton("全部展开")
        expand_all_button.setToolTipText("展开所有节点")
        toolbar.add(expand_all_button)
        
        collapse_all_button = JButton("全部折叠")
        collapse_all_button.setToolTipText("折叠所有节点")
        toolbar.add(collapse_all_button)
        toolbar.addSeparator()
        
        refresh_button = JButton("刷新树")
        refresh_button.setToolTipText("刷新调用树")
        toolbar.add(refresh_button)
        
        clear_button = JButton("清除树")
        clear_button.setToolTipText("清除调用树")
        toolbar.add(clear_button)
        toolbar.addSeparator()
        
        # 搜索框
        search_field = JTextField(20)
        search_field.setToolTipText("搜索函数")
        toolbar.add(search_field)
        
        search_button = JButton("搜索")
        search_button.setToolTipText("搜索函数")
        toolbar.add(search_button)
        toolbar.addSeparator()
        
        # 导出按钮
        export_button = JButton("导出")
        export_button.setToolTipText("导出调用树")
        toolbar.add(export_button)
        
        save_button = JButton("保存")
        save_button.setToolTipText("保存调用树")
        toolbar.add(save_button)
        
        main_panel.add(toolbar, BorderLayout.NORTH)
        
        # 创建分割面板
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split_pane.setDividerLocation(500)
        
        # 左侧调用树面板
        tree_panel = JPanel()
        tree_panel.setLayout(BorderLayout())
        
        # 调用树
        self.tree_model = DefaultMutableTreeNode("调用树")
        self.call_tree = JTree(self.tree_model)
        self.call_tree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION)
        self.call_tree.setShowsRootHandles(True)
        self.call_tree.setRootVisible(True)
        
        # 添加鼠标监听器
        self.call_tree.addMouseListener(self.TreeMouseListener())
        
        tree_scroll_pane = JScrollPane(self.call_tree)
        tree_panel.add(tree_scroll_pane, BorderLayout.CENTER)
        
        # 调用树控制选项
        tree_control_panel = JPanel()
        tree_control_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        tree_control_panel.setBorder(BorderFactory.createTitledBorder("显示选项"))
        
        recursive_checkbox = JCheckBox("显示递归调用")
        recursive_checkbox.setSelected(self.show_recursive)
        recursive_checkbox.addItemListener(self.OptionItemListener("recursive"))
        tree_control_panel.add(recursive_checkbox)
        
        system_checkbox = JCheckBox("显示系统调用")
        system_checkbox.setSelected(self.show_system_calls)
        system_checkbox.addItemListener(self.OptionItemListener("system"))
        tree_control_panel.add(system_checkbox)
        
        library_checkbox = JCheckBox("显示库函数")
        library_checkbox.setSelected(self.show_library_functions)
        library_checkbox.addItemListener(self.OptionItemListener("library"))
        tree_control_panel.add(library_checkbox)
        
        depth_label = JLabel("最大深度：")
        depth_combo = JComboBox(["3", "5", "10", "20", "无限制"])
        depth_combo.setSelectedItem(str(self.max_depth))
        tree_control_panel.add(depth_label)
        tree_control_panel.add(depth_combo)
        
        tree_panel.add(tree_control_panel, BorderLayout.SOUTH)
        
        split_pane.setLeftComponent(tree_panel)
        
        # 右侧详情面板
        detail_panel = JPanel()
        detail_panel.setLayout(BorderLayout())
        
        # 详情标签页
        detail_tabbed_pane = JTabbedPane()
        
        # 函数详情标签
        function_detail_panel = JPanel()
        function_detail_panel.setLayout(BoxLayout(function_detail_panel, BoxLayout.Y_AXIS))
        
        # 函数信息
        info_panel = JPanel()
        info_panel.setLayout(GridLayout(5, 2, 10, 10))
        info_panel.setBorder(BorderFactory.createTitledBorder("函数信息"))
        
        self.function_name_label = JLabel("函数名：")
        self.function_address_label = JLabel("地址：")
        self.function_size_label = JLabel("大小：")
        self.function_type_label = JLabel("类型：")
        self.function_calls_label = JLabel("调用数：")
        
        info_panel.add(JLabel("函数名："))
        info_panel.add(self.function_name_label)
        info_panel.add(JLabel("地址："))
        info_panel.add(self.function_address_label)
        info_panel.add(JLabel("大小："))
        info_panel.add(self.function_size_label)
        info_panel.add(JLabel("类型："))
        info_panel.add(self.function_type_label)
        info_panel.add(JLabel("调用数："))
        info_panel.add(self.function_calls_label)
        
        function_detail_panel.add(info_panel)
        
        # 函数代码
        code_panel = JPanel()
        code_panel.setLayout(BorderLayout())
        code_panel.setBorder(BorderFactory.createTitledBorder("函数代码"))
        
        self.code_text = JTextArea(15, 50)
        self.code_text.setEditable(False)
        self.code_text.setFont(java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12))
        code_panel.add(JScrollPane(self.code_text), BorderLayout.CENTER)
        
        function_detail_panel.add(code_panel)
        
        detail_tabbed_pane.addTab("函数详情", function_detail_panel)
        
        # 调用统计标签
        stats_panel = JPanel()
        stats_panel.setLayout(BorderLayout())
        
        # 统计表格
        stats_table_model = DefaultTableModel(["统计项", "值"], 0)
        stats_table = JTable(stats_table_model)
        stats_panel.add(JScrollPane(stats_table), BorderLayout.CENTER)
        
        detail_tabbed_pane.addTab("调用统计", stats_panel)
        
        # 调用关系标签
        calls_panel = JPanel()
        calls_panel.setLayout(BorderLayout())
        
        # 调用关系表格
        calls_table_model = DefaultTableModel(["调用函数", "被调用函数", "调用次数", "地址"], 0)
        calls_table = JTable(calls_table_model)
        calls_panel.add(JScrollPane(calls_table), BorderLayout.CENTER)
        
        detail_tabbed_pane.addTab("调用关系", calls_panel)
        
        detail_panel.add(detail_tabbed_pane, BorderLayout.CENTER)
        
        # 底部状态栏
        status_bar = JPanel()
        status_bar.setLayout(FlowLayout(FlowLayout.LEFT))
        status_bar.setBorder(BorderFactory.createLoweredBevelBorder())
        
        self.status_label = JLabel("就绪")
        status_bar.add(self.status_label)
        
        detail_panel.add(status_bar, BorderLayout.SOUTH)
        
        split_pane.setRightComponent(detail_panel)
        
        main_panel.add(split_pane, BorderLayout.CENTER)
        
        frame.add(main_panel)
        frame.setVisible(True)
        
        # 初始化调用树
        self.initialize_call_tree()
    
    def initialize_call_tree(self):
        """初始化调用树"""
        # 实际实现中，这里应该：
        # 1. 获取程序中的函数列表
        # 2. 构建调用关系
        # 3. 创建调用树模型
        # 4. 显示调用树
        
        # 示例：创建一个简单的调用树
        root = self.tree_model
        root.removeAllChildren()
        
        # 添加主函数节点
        main_node = DefaultMutableTreeNode({"name": "main", "address": "0x10001000", "type": "函数", "calls": 2})
        root.add(main_node)
        
        # 添加函数1节点
        func1_node = DefaultMutableTreeNode({"name": "function1", "address": "0x10002000", "type": "函数", "calls": 1})
        main_node.add(func1_node)
        
        # 添加函数2节点
        func2_node = DefaultMutableTreeNode({"name": "function2", "address": "0x10003000", "type": "函数", "calls": 1})
        main_node.add(func2_node)
        
        # 添加库函数节点
        lib_node = DefaultMutableTreeNode({"name": "library_function", "address": "0x7fff0000", "type": "库函数", "calls": 0})
        func1_node.add(lib_node)
        func2_node.add(lib_node)
        
        # 刷新树
        self.call_tree.setModel(self.tree_model)
        self.call_tree.expandRow(0)
        
        # 更新状态
        self.status_label.setText("调用树初始化完成")
    
    def build_call_tree(self, function_name, max_depth=10):
        """构建调用树"""
        # 实际实现中，这里应该：
        # 1. 从指定函数开始
        # 2. 递归构建调用树
        # 3. 应用过滤条件
        # 4. 限制深度
        
        pass
    
    def update_function_details(self, function_info):
        """更新函数详情"""
        # 实际实现中，这里应该：
        # 1. 更新函数信息标签
        # 2. 显示函数代码
        # 3. 更新统计信息
        
        # 示例：更新函数详情
        if function_info:
            self.function_name_label.setText(function_info.get("name", ""))
            self.function_address_label.setText(function_info.get("address", ""))
            self.function_size_label.setText("100 bytes")
            self.function_type_label.setText(function_info.get("type", ""))
            self.function_calls_label.setText(str(function_info.get("calls", 0)))
            
            # 示例：显示函数代码
            code = "// 函数: " + function_info.get("name", "") + "\n"
            code += "// 地址: " + function_info.get("address", "") + "\n"
            code += "void " + function_info.get("name", "") + "() {\n"
            code += "    // 函数代码...\n"
            code += "    return;\n"
            code += "}\n"
            
            self.code_text.setText(code)
            
            # 更新状态
            self.status_label.setText(f"显示函数 {function_info.get('name', '')} 的详情")
    
    def search_function(self, pattern):
        """搜索函数"""
        # 实际实现中，这里应该：
        # 1. 搜索匹配的函数
        # 2. 显示搜索结果
        # 3. 支持高亮显示
        
        # 示例：搜索函数
        self.search_results = []
        # 模拟搜索结果
        self.search_results.append({"name": "main", "address": "0x10001000", "type": "函数"})
        self.search_results.append({"name": "function1", "address": "0x10002000", "type": "函数"})
        
        # 显示搜索结果
        results_list = JList([result["name"] for result in self.search_results])
        results_dialog = JOptionPane.showMessageDialog(
            None,
            JScrollPane(results_list),
            "搜索结果",
            JOptionPane.PLAIN_MESSAGE
        )
    
    def export_call_tree(self, format_type):
        """导出调用树"""
        # 实际实现中，这里应该：
        # 1. 根据选择的格式导出调用树
        # 2. 保存到文件
        
        # 示例：导出为JSON文件
        call_tree_data = self.export_tree_to_json(self.tree_model)
        
        # 保存到文件
        pass
    
    def export_tree_to_json(self, node):
        """将调用树导出为JSON格式"""
        # 实际实现中，这里应该：
        # 1. 递归遍历调用树
        # 2. 构建JSON对象
        # 3. 返回JSON数据
        
        # 示例：导出为JSON
        data = {}
        if node.getUserObject():
            if isinstance(node.getUserObject(), dict):
                data = node.getUserObject().copy()
            else:
                data = {"name": node.getUserObject()}
        
        children = []
        for i in range(node.getChildCount()):
            child_node = node.getChildAt(i)
            children.append(self.export_tree_to_json(child_node))
        
        if children:
            data["children"] = children
        
        return data
    
    def save_call_tree(self, filename):
        """保存调用树"""
        # 实际实现中，这里应该：
        # 1. 保存调用树配置到文件
        # 2. 包括节点状态、过滤选项等
        
        # 示例：保存为JSON文件
        pass
    
    def load_call_tree(self, filename):
        """加载调用树"""
        # 实际实现中，这里应该：
        # 1. 从文件加载调用树配置
        # 2. 恢复调用树状态
        # 3. 应用过滤选项
        
        pass
    
    class OptionItemListener(ItemListener):
        def __init__(self, option):
            self.option = option
        
        def itemStateChanged(self, e):
            if self.option == "recursive":
                self.show_recursive = e.getStateChange() == e.SELECTED
            elif self.option == "system":
                self.show_system_calls = e.getStateChange() == e.SELECTED
            elif self.option == "library":
                self.show_library_functions = e.getStateChange() == e.SELECTED
            
            # 刷新调用树
            self.initialize_call_tree()
    
    class TreeMouseListener(MouseAdapter):
        def mouseClicked(self, e):
            # 处理鼠标点击事件
            if e.getClickCount() == 2:
                # 双击事件：展开/折叠节点
                path = self.call_tree.getPathForLocation(e.getX(), e.getY())
                if path:
                    node = path.getLastPathComponent()
                    if self.call_tree.isExpanded(path):
                        self.call_tree.collapsePath(path)
                    else:
                        self.call_tree.expandPath(path)
            elif e.getButton() == MouseEvent.BUTTON3:
                # 右键事件：显示上下文菜单
                path = self.call_tree.getPathForLocation(e.getX(), e.getY())
                if path:
                    self.call_tree.setSelectionPath(path)
                    node = path.getLastPathComponent()
                    self.show_context_menu(e, node)
        
        def mousePressed(self, e):
            # 处理鼠标按下事件
            path = self.call_tree.getPathForLocation(e.getX(), e.getY())
            if path:
                node = path.getLastPathComponent()
                if isinstance(node, DefaultMutableTreeNode):
                    user_object = node.getUserObject()
                    if isinstance(user_object, dict):
                        self.update_function_details(user_object)
        
        def show_context_menu(self, e, node):
            """显示上下文菜单"""
            # 实际实现中，这里应该：
            # 1. 创建上下文菜单
            # 2. 添加菜单项
            # 3. 显示菜单
            
            # 示例：显示上下文菜单
            popup = JPopupMenu()
            
            expand_item = JMenuItem("展开")
            collapse_item = JMenuItem("折叠")
            refresh_item = JMenuItem("刷新子树")
            export_item = JMenuItem("导出子树")
            
            popup.add(expand_item)
            popup.add(collapse_item)
            popup.addSeparator()
            popup.add(refresh_item)
            popup.addSeparator()
            popup.add(export_item)
            
            popup.show(e.getComponent(), e.getX(), e.getY())

# 主函数
if __name__ == "__main__":
    visualizer = CallTreeVisualizer()
    visualizer.run()
