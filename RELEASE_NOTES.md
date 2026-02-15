# Vortex 发行说明

## 项目概述

Vortex 是基于 Ghidra 的增强型软件逆向工程框架，由美国国家安全局 (NSA) 的 Ghidra 项目扩展而来。该框架集成了多种先进的分析工具，为软件逆向工程和安全分析提供了全面的解决方案。

## 版本信息

- **版本号**：12.1
- **发行类型**：DEV
- **构建日期**：2026-02-15
- **基于 Ghidra**：12.1

## 主要特性

### 1. 自动化分析工作流
- **AnalysisWorkflowAutomator**：创建和执行自定义分析工作流
- **BatchAnalyzer**：批量分析多个程序或程序区段

### 2. 高级逆向工程工具
- **MalwareAnalyzer**：分析恶意软件，生成签名，检测恶意代码
- **CryptoAnalyzer**：识别和分析程序中的密码学算法实现
- **ProtocolAnalyzer**：识别和分析程序中的网络协议实现

### 3. 可视化增强
- **InteractiveGraphExplorer**：交互式图形探索，支持多种图形类型和操作
- **3DMemoryVisualizer**：3D内存布局可视化，帮助理解程序内存结构
- **CallTreeVisualizer**：交互式调用树可视化，显示函数调用关系

### 4. 代码理解工具
- **CodeSummarizer**：自动生成代码摘要，帮助理解函数和代码块的功能
- **CrossReferenceExplorer**：高级交叉引用分析，可视化代码引用关系
- **APIUsageAnalyzer**：分析程序中的API使用模式，识别潜在问题

### 5. 安全分析工具
- **SecurityScanner**：综合安全漏洞扫描，检测各种安全问题
- **HardeningAnalyzer**：安全加固分析，评估程序的安全加固状态
- **SecureCodingChecker**：安全编码实践检查，检测不安全的编码模式

### 6. 工具集成
- **ExternalToolIntegrator**：集成外部工具，如IDA Pro、Binwalk、Radare2等
- **PluginManager**：管理Ghidra插件，包括安装、卸载和配置
- **ScriptRunner**：管理和执行脚本序列

### 7. 用户体验改进
- **AnalysisDashboard**：综合分析仪表板，集成来自所有分析工具的数据
- **CustomizableUI**：可自定义UI布局，支持拖放功能和布局保存
- **KeyboardShortcutsManager**：键盘快捷键管理，支持自定义快捷键和冲突检测

### 8. 性能优化
- **PerformanceProfiler**：性能分析工具，识别性能瓶颈并提供优化建议
- **MemoryOptimizer**：内存优化工具，分析内存使用模式并提供优化建议
- **CodeSizeOptimizer**：代码大小优化工具，分析代码大小并提供优化建议

## 系统要求

- **操作系统**：Windows 7+、macOS 10.14+、Linux
- **Java**：JDK 21 64位
- **内存**：至少4GB RAM（推荐8GB以上）
- **磁盘空间**：至少10GB可用空间
- **处理器**：64位处理器，至少2核

## 安装说明

1. **安装Java**
   - 访问 [Adoptium](https://adoptium.net/temurin/releases) 下载JDK 21 64位
   - 运行安装程序并按照提示完成安装
   - 验证Java安装：`java -version`

2. **安装Vortex**
   - 下载本发行包
   - 解压下载的ZIP文件到任意目录
   - 启动Vortex：
     - Windows：运行 `ghidraRun.bat`
     - macOS/Linux：运行 `./ghidraRun`

3. **安装扩展模块**
   - 打开Vortex CodeBrowser
   - 选择 **File -> Install Extensions...**
   - 点击 **Add Extension** 按钮
   - 浏览到扩展模块所在目录并选择
   - 勾选要安装的扩展
   - 点击 **OK** 按钮
   - 重启Vortex以应用更改

## 使用指南

### 快速上手

1. **启动Vortex**
   - 运行 `ghidraRun` 脚本
   - 在欢迎界面点击 **New Project** 创建新项目
   - 选择 **Non-Shared Project** 并指定项目目录
   - 点击 **Finish** 完成项目创建

2. **导入程序**
   - 在项目窗口中，选择 **File -> Import File**
   - 浏览到要分析的程序文件并选择
   - 点击 **OK** 按钮
   - 在导入对话框中选择适当的语言和处理器
   - 点击 **Import** 按钮

3. **分析程序**
   - 双击导入的程序打开CodeBrowser
   - 在分析对话框中选择要执行的分析选项
   - 点击 **Analyze** 按钮开始分析
   - 等待分析完成

4. **使用扩展工具**
   - 选择 **Tools** 菜单查看可用的扩展工具
   - 选择要使用的工具并按照提示操作

### 常用快捷键

- `F5`：切换到反编译视图
- `Ctrl+F`：在当前视图中搜索
- `Ctrl+Shift+F`：在整个程序中搜索
- `Ctrl+N`：跳转到指定地址
- `Ctrl+Alt+N`：跳转到指定函数
- `Ctrl+D`：创建数据
- `Ctrl+R`：重命名选中项
- `Ctrl+Shift+E`：导出数据

## 文档资源

- **用户指南**：`USER_GUIDE.md` - 详细的用户使用手册
- **开发指南**：`DEVELOPMENT_GUIDE.md` - 项目开发文档
- **测试报告**：`TEST_REPORT.md` - 测试结果报告
- **贡献指南**：`CONTRIBUTING.md` - 如何为项目贡献代码

## 支持与反馈

- **GitHub Issues**：[https://github.com/luyang668899/Vortex/issues](https://github.com/luyang668899/Vortex/issues)
- **Discord社区**：加入Vortex Discord服务器获取社区支持
- **Stack Overflow**：使用 `vortex` 或 `ghidra` 标签提问

## 许可证

Vortex 基于 Apache License 2.0 开源协议发布。详见 `LICENSE` 文件。

## 致谢

- 感谢 NSA 开发的 Ghidra 基础框架
- 感谢所有为 Vortex 项目做出贡献的开发者
- 感谢社区提供的反馈和建议

---

**Vortex 团队**

© 2026 Vortex Project