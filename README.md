# Excel Data View

![Java](https://img.shields.io/badge/Java-17-orange.svg)
![Maven](https://img.shields.io/badge/Maven-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Release](https://img.shields.io/github/v/release/GitHubNull/excelDataView)
![Stars](https://img.shields.io/github/stars/GitHubNull/excelDataView?style=social)

一个专为 Burp Suite 设计的 Excel 数据查看插件，能够自动检测和显示 HTTP 响应中的 Excel 文件内容。

## 📈 项目增长

<!-- Star History Chart -->
<p align="center">
  <a href="https://star-history.com/#GitHubNull/excelDataView&Date">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=GitHubNull/excelDataView&type=Date&theme=dark" />
      <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=GitHubNull/excelDataView&type=Date" />
      <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=GitHubNull/excelDataView&type=Date" />
    </picture>
  </a>
</p>

<!-- Quick Stats -->
<div align="center">

![GitHub Stats](https://github-readme-stats.vercel.app/api?username=GitHubNull&repo=excelDataView&show_icons=true&theme=radical&hide_border=true)

</div>

## 🚀 功能特性

- **自动检测**：智能识别 HTTP 响应中的 Excel 格式数据
- **多格式支持**：支持 `.xls` 和 `.xlsx` 格式的 Excel 文件
- **多工作表**：支持查看 Excel 文件中的多个工作表
- **中文编码**：自动处理中文编码问题，确保正确显示
- **实时预览**：在 Burp Suite 中直接预览 Excel 数据
- **模块化设计**：采用模块化架构，易于扩展和维护
- **完整日志**：使用 Burp Suite 统一的日志系统进行调试

## 📋 系统要求

- **Java**: 17+
- **Burp Suite**: Professional / Community
- **操作系统**: Windows / macOS / Linux

## 🛠️ 安装指南

### 方式一：直接安装（推荐）

1. 下载最新版本的 JAR 文件：
   - [GitHub Releases](https://github.com/GitHubNull/excelDataView/releases)
   - 下载 `excelDataView-*-jar-with-dependencies.jar` 文件

2. 在 Burp Suite 中安装：
   - 打开 Burp Suite
   - 进入 `Extender` -> `Extensions` -> `Add`
   - 选择 `Java` 扩展类型
   - 点击 `Select file...` 选择下载的 JAR 文件
   - 点击 `Next` 完成安装

### 方式二：从源码构建

1. 克隆项目：
   ```bash
   git clone https://github.com/GitHubNull/excelDataView.git
   cd excelDataView
   ```

2. 构建项目：
   ```bash
   mvn clean package
   ```

3. 在 `target/` 目录中找到生成的 JAR 文件并按照上述步骤安装

## 📖 使用说明

### 基本使用

1. 安装插件后，插件会自动加载并在 Burp Suite 中注册
2. 当 HTTP 响应包含 Excel 格式数据时，会在响应编辑器中显示 **"Excel数据"** 标签页
3. 点击该标签页即可查看 Excel 内容

### 支持的场景

- **API 响应**：当 API 返回 Excel 文件时
- **文件下载**：当下载 Excel 文件时
- **数据导出**：当系统导出 Excel 格式的数据时
- **报表生成**：当动态生成 Excel 报表时

### 工作表切换

- 如果 Excel 文件包含多个工作表，会在标签页中显示所有工作表
- 点击对应的标签即可切换查看不同的工作表内容

## 🔧 开发指南

### 项目结构

```
excelDataView/
├── src/
│   ├── main/
│   │   ├── java/
│   │   │   ├── burp/                 # Burp Suite 入口
│   │   │   │   └── BurpExtender.java
│   │   │   └── org/oxff/excel/      # 核心功能模块
│   │   │       ├── ExcelTabFactory.java    # Tab 工厂类
│   │   │       ├── ExcelViewerTab.java     # 主视图类
│   │   │       └── ExcelProcessor.java     # 数据处理类
│   │   └── resources/
│   └── test/
├── .github/                          # GitHub Actions 配置
│   └── workflows/
│       └── release.yml
├── target/                          # 构建输出
├── pom.xml                          # Maven 配置
├── README.md                        # 项目说明
├── LICENSE.md                       # 开源协议
└── RELEASE.md                       # 发布指南
```

### 核心组件

#### BurpExtender
- 插件入口类，实现 `IBurpExtender` 接口
- 负责插件初始化和注册自定义 Tab 工厂

#### ExcelTabFactory
- Tab 工厂类，实现 `IMessageEditorTabFactory` 接口
- 负责创建 Excel 数据查看 Tab 实例

#### ExcelViewerTab
- 主视图类，实现 `IMessageEditorTab` 接口
- 负责 Excel 数据的显示和用户交互

#### ExcelProcessor
- 数据处理类，包含 Excel 文件解析的核心逻辑
- 支持 XLS 和 XLSX 格式
- 提供中文编码修复功能

### 开发环境设置

1. **安装 JDK 17**：
   ```bash
   # Ubuntu/Debian
   sudo apt install openjdk-17-jdk
   
   # macOS (使用 Homebrew)
   brew install openjdk@17
   
   # Windows
   # 下载并安装 Oracle JDK 17 或 OpenJDK 17
   ```

2. **安装 Maven**：
   ```bash
   # Ubuntu/Debian
   sudo apt install maven
   
   # macOS (使用 Homebrew)
   brew install maven
   
   # Windows
   # 下载并配置 Maven
   ```

3. **IDE 配置**：
   - 推荐使用 IntelliJ IDEA
   - 导入项目为 Maven 项目
   - 确保使用 JDK 17

### 构建和测试

```bash
# 编译项目
mvn clean compile

# 运行测试
mvn test

# 打包项目
mvn clean package

# 安装到本地仓库
mvn clean install
```

## 📦 发布管理

### 自动发布

项目使用 GitHub Actions 实现自动化发布：

- **触发条件**：推送版本标签（如 `v1.0.0`）
- **自动流程**：
  1. 版本号提取
  2. 更新 pom.xml 版本
  3. Maven 构建打包
  4. 生成发布说明
  5. 创建 GitHub Release
  6. 上传 JAR 文件

### 手动发布

如需手动发布，请参考 [RELEASE.md](./RELEASE.md) 文档。

## 🤝 贡献指南

### 贡献代码

1. Fork 本项目
2. 创建功能分支：`git checkout -b feature/new-feature`
3. 提交更改：`git commit -am 'Add new feature'`
4. 推送分支：`git push origin feature/new-feature`
5. 提交 Pull Request

### 问题反馈

- **Bug 报告**：请使用 [GitHub Issues](https://github.com/GitHubNull/excelDataView/issues)
- **功能建议**：欢迎提交新功能建议
- **使用问题**：请在 Issues 中详细描述问题场景

### 开发规范

- 遵循 Java 编码规范
- 添加适当的注释和文档
- 确保代码通过所有测试
- 更新相关文档

## 📄 开源协议

本项目采用 MIT 协议开源，详见 [LICENSE.md](./LICENSE.md) 文件。

## 🙏 致谢

- [Burp Suite](https://portswigger.net/burp) - 强大的安全测试平台
- [Apache POI](https://poi.apache.org/) - Java Excel 处理库
- [Swing](https://docs.oracle.com/javase/tutorial/uiswing/) - Java GUI 工具包

## 📊 详细统计

### 项目活跃度
<div align="center">

![GitHub Stats](https://github-readme-stats.vercel.app/api/pin/?username=GitHubNull&repo=excelDataView&theme=radical)

![Language Stats](https://github-readme-stats.vercel.app/api/top-langs/?username=GitHubNull&repo=excelDataView&layout=compact&theme=radical)

</div>

### 贡献者
感谢所有为项目做出贡献的开发者！

<div align="center">

![Contributors](https://contrib.rocks/image?repo=GitHubNull/excelDataView)

</div>

## 📈 增长里程碑

- **2025-09-22**: 项目初始化，第一个版本发布 (v1.0.0)
- **2025-09-23**: 完善文档和 CI/CD 流程 (v1.1.1)
- **目标**: 获得 100+ Stars
- **目标**: 社区贡献者达到 10+ 人

## 📞 联系方式

- **项目地址**：https://github.com/GitHubNull/excelDataView
- **问题反馈**：https://github.com/GitHubNull/excelDataView/issues
- **邮箱**：[your-email@example.com](mailto:your-email@example.com)

---

<div align="center">
  
**Excel Data View** - 让 Burp Suite 中的 Excel 数据查看变得简单！

[⭐ Star this project](https://github.com/GitHubNull/excelDataView) | [🐛 Report an issue](https://github.com/GitHubNull/excelDataView/issues) | [📊 查看统计](https://star-history.com/#GitHubNull/excelDataView&Date)

</div>