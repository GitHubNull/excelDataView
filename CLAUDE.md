# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

这是一个基于Java 17的Maven项目，名为`excelDataView`，用于Excel数据查看和处理。项目目前处于初始状态，尚未包含具体的源代码实现。

## 构建和开发命令

### 基本Maven命令
- `mvn clean compile` - 清理并编译项目
- `mvn test` - 运行测试（目前没有测试文件）
- `mvn package` - 打包项目
- `mvn clean install` - 清理并安装到本地仓库

### 开发环境设置
- Java版本：17
- Maven：3.x
- IDE：IntelliJ IDEA（项目包含.idea目录）

## 项目结构

```
excelDataView/
├── src/
│   ├── main/
│   │   ├── java/           # Java源代码目录（目前为空）
│   │   └── resources/      # 资源文件目录（目前为空）
│   └── test/               # 测试代码目录（目前为空）
├── target/                 # Maven构建输出目录
├── .idea/                  # IntelliJ IDEA配置文件
├── pom.xml                 # Maven项目配置
└── .gitignore              # Git忽略文件配置
```

## 依赖项

主要依赖包括：
- `burp-extender-api:2.1` - Burp Suite扩展API
- `commons-io:2.14.0` - Apache Commons IO工具库
- `commons-lang3:3.18.0` - Apache Commons Lang工具库

## 开发注意事项

1. **项目状态**：项目目前处于初始化阶段，没有实际的源代码实现
2. **包结构**：根据groupId `org.oxff`，Java类应该放在 `src/main/java/org/oxff/` 目录下
3. **Burp Suite集成**：项目包含Burp Suite扩展API，可能是为了开发Burp Suite插件
4. **Excel处理**：项目名称暗示与Excel数据处理相关，但目前没有具体的Excel处理依赖

## 常见开发任务

### 添加新的Java类
1. 在 `src/main/java/org/oxff/` 目录下创建对应的包结构
2. 按照Java命名规范创建类文件

### 添加新的依赖
1. 在 `pom.xml` 的 `<dependencies>` 部分添加新的依赖
2. 运行 `mvn clean install` 更新依赖

### 创建测试
1. 在 `src/test/java/org/oxff/` 目录下创建测试类
2. 使用JUnit 5进行测试（通过Maven默认配置）