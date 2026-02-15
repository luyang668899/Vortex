#!/usr/bin/env python3
# InteractiveGraphExplorer.py - 更交互式的图形探索工具
# 功能：支持拖拽、实时修改、多种图形类型、自定义样式

import os
import json
import re
from datetime import datetime
from java.awt import BorderLayout, GridLayout, FlowLayout, Color, Dimension, Point, Rectangle
from java.awt.event import ActionListener, ItemListener, MouseAdapter, MouseEvent, MouseMotionAdapter
from javax.swing import (
    JFrame, JPanel, JTabbedPane, JTextArea, JScrollPane, JButton, 
    JCheckBox, JLabel, JComboBox, JTextField, JOptionPane, JTable, 
    DefaultTableModel, JFileChooser, JProgressBar, JMenuBar, JMenu, JMenuItem,
    BoxLayout, BorderFactory, JTree, DefaultMutableTreeNode, JSplitPane,
    JToolBar, JToggleButton, JPopupMenu, JMenuItem as SwingJMenuItem
)
from javax.swing.border import LineBorder
from ghidra.app.script import GhidraScript
from ghidra.program.model.listing import Function, Instruction
from ghidra.program.model.symbol import Symbol, RefType
from ghidra.program.model.address import AddressSet
from ghidra.program.model.mem import MemoryAccessException
from ghidra.util.exception import CancelledException

class InteractiveGraphExplorer(GhidraScript):
    def __init__(self):
        self.program = None
        self.current_graph = None
        self.graph_type = "调用图"
        self.graph_nodes = []
        self.graph_edges = []
        self.selected_node = None
        self.dragging_node = None
        self.drag_offset = Point(0, 0)
        self.zoom_level = 1.0
        self.graph_types = {
            "调用图": "函数调用关系图",
            "控制流图": "函数内部控制流图",
            "交叉引用图": "变量和函数的交叉引用关系",
            "依赖图": "模块和函数之间的依赖关系",
            "内存访问图": "内存访问模式图"
        }
        self.layout_algorithms = ["力导向布局", "层次布局", "圆形布局", "树形布局", "网格布局"]
        self.node_styles = {
            "默认": {"color": Color(200, 200, 255), "border": Color(100, 100, 200)},  # 蓝色
            "函数": {"color": Color(200, 255, 200), "border": Color(100, 200, 100)},  # 绿色
            "库函数": {"color": Color(255, 200, 200), "border": Color(200, 100, 100)},  # 红色
            "系统调用": {"color": Color(255, 255, 200), "border": Color(200, 200, 100)},  # 黄色
            "数据": {"color": Color(255, 200, 255), "border": Color(200, 100, 200)}  # 紫色
        }
    
    def run(self):
        """运行交互式图形探索工具"""
        self.program = self.getCurrentProgram()
        if not self.program:
            self.println("没有打开的程序")
            return
        
        self.show_graph_explorer()
    
    def show_graph_explorer(self):
        """显示图形探索工具界面"""
        frame = JFrame("Interactive Graph Explorer - 交互式图形探索工具")
        frame.setSize(1200, 800)
        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
        frame.setLocationRelativeTo(None)
        
        # 创建主面板
        main_panel = JPanel()
        main_panel.setLayout(BorderLayout())
        
        # 创建工具栏
        toolbar = JToolBar()
        toolbar.setRollover(True)
        
        # 图形类型选择
        graph_type_combo = JComboBox(self.graph_types.keys())
        graph_type_combo.setToolTipText("选择图形类型")
        toolbar.add(graph_type_combo)
        toolbar.addSeparator()
        
        # 布局算法选择
        layout_combo = JComboBox(self.layout_algorithms)
        layout_combo.setToolTipText("选择布局算法")
        toolbar.add(layout_combo)
        toolbar.addSeparator()
        
        # 缩放按钮
        zoom_in_button = JButton("放大")
        zoom_in_button.setToolTipText("放大图形")
        zoom_in_button.addActionListener(self.ZoomButtonListener("in"))
        toolbar.add(zoom_in_button)
        
        zoom_out_button = JButton("缩小")
        zoom_out_button.setToolTipText("缩小图形")
        zoom_out_button.addActionListener(self.ZoomButtonListener("out"))
        toolbar.add(zoom_out_button)
        
        zoom_reset_button = JButton("重置缩放")
        zoom_reset_button.setToolTipText("重置缩放级别")
        zoom_reset_button.addActionListener(self.ZoomButtonListener("reset"))
        toolbar.add(zoom_reset_button)
        toolbar.addSeparator()
        
        # 布局按钮
        layout_button = JButton("应用布局")
        layout_button.setToolTipText("应用选中的布局算法")
        toolbar.add(layout_button)
        
        refresh_button = JButton("刷新图形")
        refresh_button.setToolTipText("刷新图形显示")
        toolbar.add(refresh_button)
        toolbar.addSeparator()
        
        # 导出按钮
        export_button = JButton("导出图形")
        export_button.setToolTipText("导出图形为文件")
        toolbar.add(export_button)
        
        save_button = JButton("保存图形")
        save_button.setToolTipText("保存图形配置")
        toolbar.add(save_button)
        
        main_panel.add(toolbar, BorderLayout.NORTH)
        
        # 创建分割面板
        split_pane = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        split_pane.setDividerLocation(300)
        
        # 左侧控制面板
        control_panel = JPanel()
        control_panel.setLayout(BorderLayout())
        control_panel.setPreferredSize(Dimension(300, 600))
        
        # 图形配置标签
        config_tabbed_pane = JTabbedPane()
        
        # 节点配置标签
        node_config_panel = JPanel()
        node_config_panel.setLayout(BoxLayout(node_config_panel, BoxLayout.Y_AXIS))
        node_config_panel.setBorder(BorderFactory.createTitledBorder("节点配置"))
        
        # 节点样式选择
        node_style_panel = JPanel()
        node_style_panel.setLayout(GridLayout(3, 2, 5, 5))
        
        node_style_combo = JComboBox(self.node_styles.keys())
        node_style_panel.add(JLabel("节点样式："))
        node_style_panel.add(node_style_combo)
        
        node_size_field = JTextField("40")
        node_style_panel.add(JLabel("节点大小："))
        node_style_panel.add(node_size_field)
        
        node_opacity_field = JTextField("1.0")
        node_style_panel.add(JLabel("节点透明度："))
        node_style_panel.add(node_opacity_field)
        
        node_config_panel.add(node_style_panel)
        
        # 节点过滤选项
        node_filter_panel = JPanel()
        node_filter_panel.setBorder(BorderFactory.createTitledBorder("节点过滤"))
        
        filter_text = JTextField("")
        filter_text.setToolTipText("输入过滤条件")
        node_filter_panel.add(filter_text)
        
        node_config_panel.add(node_filter_panel)
        
        config_tabbed_pane.addTab("节点", node_config_panel)
        
        # 边配置标签
        edge_config_panel = JPanel()
        edge_config_panel.setLayout(BoxLayout(edge_config_panel, BoxLayout.Y_AXIS))
        edge_config_panel.setBorder(BorderFactory.createTitledBorder("边配置"))
        
        # 边样式选择
        edge_style_panel = JPanel()
        edge_style_panel.setLayout(GridLayout(3, 2, 5, 5))
        
        edge_width_field = JTextField("2")
        edge_style_panel.add(JLabel("边宽度："))
        edge_style_panel.add(edge_width_field)
        
        edge_opacity_field = JTextField("0.8")
        edge_style_panel.add(JLabel("边透明度："))
        edge_style_panel.add(edge_opacity_field)
        
        edge_style_combo = JComboBox(["直线", "曲线", "虚线", "点线"])
        edge_style_panel.add(JLabel("边样式："))
        edge_style_panel.add(edge_style_combo)
        
        edge_config_panel.add(edge_style_panel)
        
        # 边过滤选项
        edge_filter_panel = JPanel()
        edge_filter_panel.setBorder(BorderFactory.createTitledBorder("边过滤"))
        
        edge_filter_combo = JComboBox(["所有边", "调用边", "数据边", "控制边"])
        edge_filter_panel.add(edge_filter_combo)
        
        edge_config_panel.add(edge_filter_panel)
        
        config_tabbed_pane.addTab("边", edge_config_panel)
        
        # 布局配置标签
        layout_config_panel = JPanel()
        layout_config_panel.setLayout(BoxLayout(layout_config_panel, BoxLayout.Y_AXIS))
        layout_config_panel.setBorder(BorderFactory.createTitledBorder("布局配置"))
        
        # 布局参数
        layout_params_panel = JPanel()
        layout_params_panel.setLayout(GridLayout(4, 2, 5, 5))
        
        layout_force_field = JTextField("1.0")
        layout_params_panel.add(JLabel("布局力："))
        layout_params_panel.add(layout_force_field)
        
        layout_repulsion_field = JTextField("1.0")
        layout_params_panel.add(JLabel("排斥力："))
        layout_params_panel.add(layout_repulsion_field)
        
        layout_iterations_field = JTextField("100")
        layout_params_panel.add(JLabel("迭代次数："))
        layout_params_panel.add(layout_iterations_field)
        
        layout_damping_field = JTextField("0.9")
        layout_params_panel.add(JLabel("阻尼系数："))
        layout_params_panel.add(layout_damping_field)
        
        layout_config_panel.add(layout_params_panel)
        
        config_tabbed_pane.addTab("布局", layout_config_panel)
        
        control_panel.add(config_tabbed_pane, BorderLayout.CENTER)
        
        # 右侧图形显示面板
        graph_panel = JPanel()
        graph_panel.setLayout(BorderLayout())
        graph_panel.setBorder(BorderFactory.createTitledBorder("图形显示"))
        
        # 图形画布
        self.graph_canvas = JPanel()
        self.graph_canvas.setBackground(Color.WHITE)
        self.graph_canvas.setBorder(LineBorder(Color.LIGHT_GRAY))
        
        # 添加鼠标事件监听器
        self.graph_canvas.addMouseListener(self.GraphMouseListener())
        self.graph_canvas.addMouseMotionListener(self.GraphMouseMotionListener())
        
        graph_scroll_pane = JScrollPane(self.graph_canvas)
        graph_panel.add(graph_scroll_pane, BorderLayout.CENTER)
        
        # 图形信息面板
        info_panel = JPanel()
        info_panel.setLayout(FlowLayout(FlowLayout.LEFT))
        info_panel.setBorder(BorderFactory.createTitledBorder("图形信息"))
        
        self.nodes_count_label = JLabel("节点: 0")
        self.edges_count_label = JLabel("边: 0")
        self.zoom_label = JLabel("缩放: 100%")
        
        info_panel.add(self.nodes_count_label)
        info_panel.add(JLabel("    "))
        info_panel.add(self.edges_count_label)
        info_panel.add(JLabel("    "))
        info_panel.add(self.zoom_label)
        
        graph_panel.add(info_panel, BorderLayout.SOUTH)
        
        split_pane.setLeftComponent(control_panel)
        split_pane.setRightComponent(graph_panel)
        
        main_panel.add(split_pane, BorderLayout.CENTER)
        
        # 创建底部状态栏
        status_bar = JPanel()
        status_bar.setLayout(FlowLayout(FlowLayout.LEFT))
        status_bar.setBorder(BorderFactory.createLoweredBevelBorder())
        
        status_label = JLabel("就绪")
        status_bar.add(status_label)
        
        main_panel.add(status_bar, BorderLayout.SOUTH)
        
        frame.add(main_panel)
        frame.setVisible(True)
        
        # 初始化图形
        self.initialize_graph()
    
    def initialize_graph(self):
        """初始化图形"""
        # 实际实现中，这里应该：
        # 1. 根据选择的图形类型生成图形数据
        # 2. 应用初始布局
        # 3. 绘制图形
        
        # 示例：创建一个简单的调用图
        self.graph_nodes = [
            {"id": 1, "name": "main", "type": "函数", "x": 100, "y": 100, "size": 40},
            {"id": 2, "name": "function1", "type": "函数", "x": 200, "y": 50, "size": 40},
            {"id": 3, "name": "function2", "type": "函数", "x": 200, "y": 150, "size": 40},
            {"id": 4, "name": "library_function", "type": "库函数", "x": 300, "y": 100, "size": 40}
        ]
        
        self.graph_edges = [
            {"id": 1, "source": 1, "target": 2, "type": "调用边"},
            {"id": 2, "source": 1, "target": 3, "type": "调用边"},
            {"id": 3, "source": 2, "target": 4, "type": "调用边"},
            {"id": 4, "source": 3, "target": 4, "type": "调用边"}
        ]
        
        # 更新图形信息
        self.update_graph_info()
        
        # 绘制图形
        self.draw_graph()
    
    def draw_graph(self):
        """绘制图形"""
        # 实际实现中，这里应该：
        # 1. 清除画布
        # 2. 绘制边
        # 3. 绘制节点
        # 4. 绘制标签
        
        # 示例：更新图形画布
        self.graph_canvas.repaint()
    
    def update_graph_info(self):
        """更新图形信息"""
        # 更新节点和边的数量
        self.nodes_count_label.setText(f"节点: {len(self.graph_nodes)}")
        self.edges_count_label.setText(f"边: {len(self.graph_edges)}")
        self.zoom_label.setText(f"缩放: {int(self.zoom_level * 100)}%")
    
    def apply_layout(self, algorithm):
        """应用布局算法"""
        # 实际实现中，这里应该：
        # 1. 根据选择的布局算法计算节点位置
        # 2. 更新节点坐标
        # 3. 重新绘制图形
        
        # 示例：应用力导向布局
        if algorithm == "力导向布局":
            # 简单的力导向布局实现
            pass
        elif algorithm == "层次布局":
            # 层次布局实现
            pass
        elif algorithm == "圆形布局":
            # 圆形布局实现
            pass
        elif algorithm == "树形布局":
            # 树形布局实现
            pass
        elif algorithm == "网格布局":
            # 网格布局实现
            pass
        
        # 重新绘制图形
        self.draw_graph()
    
    def zoom_graph(self, factor):
        """缩放图形"""
        # 实际实现中，这里应该：
        # 1. 更新缩放级别
        # 2. 重新计算节点大小和位置
        # 3. 重新绘制图形
        
        # 示例：更新缩放级别
        self.zoom_level *= factor
        self.update_graph_info()
        self.draw_graph()
    
    def reset_zoom(self):
        """重置缩放"""
        # 实际实现中，这里应该：
        # 1. 重置缩放级别为1.0
        # 2. 重置节点大小和位置
        # 3. 重新绘制图形
        
        # 示例：重置缩放级别
        self.zoom_level = 1.0
        self.update_graph_info()
        self.draw_graph()
    
    def export_graph(self, format_type):
        """导出图形"""
        # 实际实现中，这里应该：
        # 1. 根据选择的格式导出图形
        # 2. 保存到文件
        
        # 示例：导出为PNG文件
        pass
    
    def save_graph(self, filename):
        """保存图形"""
        # 实际实现中，这里应该：
        # 1. 保存图形配置到文件
        # 2. 包括节点位置、样式、布局等
        
        # 示例：保存为JSON文件
        graph_data = {
            "nodes": self.graph_nodes,
            "edges": self.graph_edges,
            "layout": "力导向布局",
            "zoom": self.zoom_level,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # 保存到文件
        pass
    
    def load_graph(self, filename):
        """加载图形"""
        # 实际实现中，这里应该：
        # 1. 从文件加载图形配置
        # 2. 更新图形数据
        # 3. 重新绘制图形
        
        pass
    
    class ZoomButtonListener(ActionListener):
        def __init__(self, action):
            self.action = action
        
        def actionPerformed(self, e):
            if self.action == "in":
                self.zoom_graph(1.2)
            elif self.action == "out":
                self.zoom_graph(0.8)
            elif self.action == "reset":
                self.reset_zoom()
    
    class GraphMouseListener(MouseAdapter):
        def mousePressed(self, e):
            # 实际实现中，这里应该：
            # 1. 检测是否点击了节点
            # 2. 如果点击了节点，开始拖拽
            # 3. 记录拖拽起始位置
            
            # 示例：检测节点点击
            x = e.getX()
            y = e.getY()
            
            # 检查是否点击了节点
            for node in self.graph_nodes:
                node_x = node["x"]
                node_y = node["y"]
                node_size = node["size"]
                
                if (x - node_x) ** 2 + (y - node_y) ** 2 <= (node_size / 2) ** 2:
                    self.selected_node = node
                    self.dragging_node = node
                    self.drag_offset = Point(x - node_x, y - node_y)
                    break
        
        def mouseReleased(self, e):
            # 实际实现中，这里应该：
            # 1. 结束拖拽
            # 2. 更新节点位置
            # 3. 重新绘制图形
            
            # 示例：结束拖拽
            self.dragging_node = None
            self.draw_graph()
        
        def mouseClicked(self, e):
            # 实际实现中，这里应该：
            # 1. 处理节点点击事件
            # 2. 显示节点详情
            # 3. 处理边点击事件
            
            # 示例：处理节点点击
            x = e.getX()
            y = e.getY()
            
            # 检查是否点击了节点
            for node in self.graph_nodes:
                node_x = node["x"]
                node_y = node["y"]
                node_size = node["size"]
                
                if (x - node_x) ** 2 + (y - node_y) ** 2 <= (node_size / 2) ** 2:
                    # 显示节点详情
                    JOptionPane.showMessageDialog(self.graph_canvas, 
                                                f"节点: {node['name']}\n类型: {node['type']}", 
                                                "节点详情", 
                                                JOptionPane.INFORMATION_MESSAGE)
                    break
    
    class GraphMouseMotionListener(MouseMotionAdapter):
        def mouseDragged(self, e):
            # 实际实现中，这里应该：
            # 1. 如果正在拖拽节点，更新节点位置
            # 2. 重新绘制图形
            
            # 示例：处理节点拖拽
            if self.dragging_node:
                x = e.getX() - self.drag_offset.x
                y = e.getY() - self.drag_offset.y
                
                # 更新节点位置
                self.dragging_node["x"] = x
                self.dragging_node["y"] = y
                
                # 重新绘制图形
                self.draw_graph()

# 主函数
if __name__ == "__main__":
    explorer = InteractiveGraphExplorer()
    explorer.run()
