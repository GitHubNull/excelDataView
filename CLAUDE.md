# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

**Excel Data View** 是一个成熟的 Burp Suite 插件项目，专门用于在 Burp Suite 中查看和处理 HTTP 响应中的 Excel 数据。项目采用 Java 17 + Maven 构建，具有完整的 CI/CD 流程和文档体系。

### 核心功能
- **Excel 数据预览**：在 Burp Suite 中直接查看 Excel 文件内容
- **多格式支持**：支持 `.xls` 和 `.xlsx` 格式
- **多工作表**：支持查看 Excel 文件中的多个工作表
- **自动检测**：智能识别 HTTP 响应中的 Excel 数据
- **中文编码**：自动处理中文编码问题
- **模块化设计**：采用模块化架构，易于扩展

### 版本信息
- **当前版本**：1.0.0
- **Java 版本**：17+
- **构建工具**：Maven 3.x
- **许可证**：MIT

## 技术架构

### 整体架构
项目采用模块化设计，主要分为以下几个模块：

```
excelDataView/
├── burp/                    # Burp Suite 集成层
│   └── BurpExtender.java   # 插件入口类
└── org/oxff/excel/         # 核心功能模块
    ├── ExcelTabFactory.java    # Tab 工厂类
    ├── ExcelViewerTab.java     # 主视图类
    └── ExcelProcessor.java     # 数据处理类
```

### 核心组件说明

#### BurpExtender
- **作用**：插件入口点，实现 `IBurpExtender` 接口
- **职责**：
  - 设置插件名称
  - 注册自定义 Tab 工厂
  - 初始化日志系统

#### ExcelTabFactory
- **作用**：Tab 工厂类，实现 `IMessageEditorTabFactory` 接口
- **职责**：
  - 创建 Excel 数据查看 Tab 实例
  - 管理 Tab 生命周期

#### ExcelViewerTab
- **作用**：主视图类，实现 `IMessageEditorTab` 接口
- **职责**：
  - 处理 HTTP 响应消息
  - 创建和显示 Excel 数据表格
  - 管理用户界面交互

#### ExcelProcessor
- **作用**：数据处理类，包含 Excel 文件解析的核心逻辑
- **职责**：
  - 检测 Excel 格式的 HTTP 响应
  - 解析 Excel 文件内容
  - 处理中文编码问题
  - 提供 Excel 数据提取 API

## 开发环境

### 系统要求
- **JDK**：17+ (推荐 OpenJDK 或 Oracle JDK)
- **Maven**：3.6+
- **IDE**：IntelliJ IDEA (推荐) 或 Eclipse
- **Burp Suite**：Professional 或 Community 版本

### 环境配置

#### 1. 安装 JDK 17
```bash
# Ubuntu/Debian
sudo apt install openjdk-17-jdk

# macOS (使用 Homebrew)
brew install openjdk@17

# Windows
# 下载并安装 Oracle JDK 17 或 OpenJDK 17
```

#### 2. 配置 Maven
项目使用标准 Maven 配置，确保 Maven 版本为 3.6+：

```bash
mvn --version
```

#### 3. IDE 配置
- **IntelliJ IDEA**：
  - 导入项目为 Maven 项目
  - 确保 JDK 17 设置正确
  - 配置 Maven 仓库

## 构建和开发命令

### 基本构建命令
```bash
# 清理编译产物
mvn clean

# 编译项目
mvn compile

# 运行测试
mvn test

# 打包项目
mvn package

# 完整构建
mvn clean package

# 安装到本地仓库
mvn clean install
```

### 开发调试命令
```bash
# 编译并跳过测试
mvn compile -DskipTests

# 打包并跳过测试
mvn package -DskipTests

# 查看依赖树
mvn dependency:tree

# 更新依赖
mvn versions:use-latest-versions
```

### 质量检查
```bash
# 运行代码检查
mvn checkstyle:check

# 运行测试覆盖率
mvn cobertura:cobertura

# 生成项目报告
mvn site
```

## 依赖项

### 核心依赖
- **burp-extender-api:2.1** - Burp Suite 扩展 API
- **commons-io:2.14.0** - Apache Commons IO 工具库
- **commons-lang3:3.18.0** - Apache Commons Lang 工具库

### Excel 处理
- **poi:5.2.3** - Apache POI Excel 处理库
- **poi-ooxml:5.4.0** - Apache POI OOXML 支持

### 构建插件
- **maven-compiler-plugin:3.13.0** - Java 编译器
- **maven-assembly-plugin:3.3.0** - 构建 fat JAR
- **versions-maven-plugin** - 版本管理

## CI/CD 流程

### GitHub Actions 工作流

项目使用 GitHub Actions 实现自动化 CI/CD：

- **自动触发**：推送版本标签 (`v*`) 时触发
- **构建流程**：
  1. 设置 Java 17 环境
  2. 缓存 Maven 依赖
  3. 提取版本号
  4. 更新 pom.xml 版本
  5. Maven 构建打包
  6. 生成发布说明
  7. 创建 GitHub Release
  8. 上传构建产物

### 发布流程

#### 自动发布
1. 创建版本标签：`git tag -a v1.2.0 -m "Release version 1.2.0"`
2. 推送标签：`git push origin v1.2.0`
3. GitHub Actions 自动触发构建和发布

#### 手动发布
1. 手动触发 GitHub Actions 工作流
2. 或在 GitHub Actions 页面点击 "Run workflow"

### 版本管理
- **版本格式**：语义化版本 (主版本.次版本.修订号)
- **标签格式**：`v` + 版本号 (如 `v1.0.0`)
- **发布策略**：通过标签触发自动发布

## 开发规范

### 代码风格

#### Java 代码规范
- 使用 4 空格缩进
- 类名使用 PascalCase
- 方法名使用 camelCase
- 常量使用大写字母和下划线
- 行长度不超过 120 字符

#### 注释规范
- 类注释：包含类的作用和职责说明
- 方法注释：包含参数、返回值和异常说明
- 复杂逻辑：添加行内注释解释实现思路
- TODO 标记：使用 TODO 标记待完成的功能

### 日志记录

#### 日志规范
- 使用 Burp Suite 的回调日志系统 (`callbacks.printOutput()`)
- 不使用 `System.out.println()` 或 `System.err.println()`
- 日志信息要有意义，避免冗余
- 错误信息要详细，便于调试

#### 日志级别
- **INFO**：常规信息，如插件加载完成
- **ERROR**：错误信息，如数据处理失败
- **DEBUG**：调试信息，如详细的处理步骤

### 错误处理

#### 异常处理
- 使用具体的异常类型，避免捕获 Exception
- 提供有意义的错误信息
- 适当记录错误日志
- 避免吞没异常

#### 资源管理
- 使用 try-with-resources 管理资源
- 确保文件流、数据库连接等资源正确关闭
- 避免资源泄漏

### 文档编写

#### 代码文档
- 所有公共 API 需要添加 JavaDoc 注释
- 复杂算法需要添加详细注释
- 配置项需要说明作用和可选值

#### 项目文档
- README.md：项目介绍和使用指南
- CLAUDE.md：开发指南（本文件）
- LICENSE.md：开源协议
- RELEASE.md：发布指南

## 常见开发任务

### 添加新的 Excel 处理功能
1. 在 `ExcelProcessor.java` 中添加新的处理方法
2. 更新相关方法的重载版本（包含 callbacks 参数）
3. 添加适当的日志记录
4. 编写单元测试
5. 更新文档

### 修改用户界面
1. 在 `ExcelViewerTab.java` 中修改 UI 组件
2. 使用 SwingWorker 处理长时间运行的任务
3. 确保线程安全（在 EDT 中更新 UI）
4. 添加错误处理和用户反馈

### 添加新的依赖
1. 在 `pom.xml` 的 `<dependencies>` 部分添加新依赖
2. 运行 `mvn clean install` 更新依赖
3. 更新 CLAUDE.md 中的依赖列表
4. 测试新功能

### 创建测试
1. 在 `src/test/java/` 目录下创建测试类
2. 使用 JUnit 5 编写测试用例
3. 添加适当的测试数据
4. 确保测试覆盖关键功能

## 故障排除

### 常见问题

#### 1. 编译错误
```bash
# 清理并重新编译
mvn clean compile

# 检查 Java 版本
java -version

# 更新 Maven 依赖
mvn clean install -U
```

#### 2. 依赖问题
```bash
# 查看依赖树
mvn dependency:tree

# 检查依赖冲突
mvn dependency:analyze

# 清理本地仓库缓存
mvn dependency:purge-local-repository
```

#### 3. GitHub Actions 失败
- 检查工作流配置文件语法
- 确认权限设置正确
- 查看 Actions 日志了解详细错误
- 检查 Maven 构建是否成功

#### 4. 插件加载失败
- 确认 Burp Suite 版本兼容性
- 检查 JAR 文件完整性
- 查看 Burp Suite 错误日志
- 确认 Java 版本兼容性

### 调试技巧

#### 本地调试
1. 在 IDE 中设置断点
2. 使用 Burp Suite 的调试功能
3. 查看 Burp Suite 的输出日志
4. 使用 `callbacks.printOutput()` 输出调试信息

#### 远程调试
1. 在 Burp Suite 中启用远程调试
2. 配置 IDE 远程调试
3. 设置断点和监控变量
4. 分析调用栈和执行流程

### 性能优化

#### 内存管理
- 及时关闭大型 Excel 文件资源
- 避免在内存中保存大量数据
- 使用流式处理大型文件

#### 并发处理
- 使用 SwingWorker 处理后台任务
- 避免在 EDT 中执行耗时操作
- 合理使用线程池

## 贡献指南

### 代码贡献流程
1. Fork 项目到个人账户
2. 创建功能分支：`git checkout -b feature/new-feature`
3. 提交代码：`git commit -m "feat: add new feature"`
4. 推送分支：`git push origin feature/new-feature`
5. 创建 Pull Request

### 提交规范
- **feat**: 新功能
- **fix**: 错误修复
- **docs**: 文档更新
- **style**: 代码格式调整
- **refactor**: 代码重构
- **test**: 测试相关
- **chore**: 构建或辅助工具变动

### 代码审查
- 所有代码变更需要经过 Code Review
- 确保代码符合项目规范
- 添加必要的测试
- 更新相关文档

## 项目资源

### 链接
- **GitHub 仓库**：https://github.com/GitHubNull/excelDataView
- **Issues**：https://github.com/GitHubNull/excelDataView/issues
- **Releases**：https://github.com/GitHubNull/excelDataView/releases

### 文档
- **README.md**：项目介绍和使用指南
- **LICENSE.md**：MIT 开源协议
- **RELEASE.md**：发布指南

### 社区
- **贡献指南**：参考本文件的贡献指南部分
- **问题反馈**：通过 GitHub Issues 提交
- **功能建议**：欢迎提交 Feature Request

---

**注意**：本文档随项目发展持续更新，请确保使用最新版本。如有疑问，请参考项目文档或提交 Issue。