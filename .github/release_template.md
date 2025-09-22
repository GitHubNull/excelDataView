## Excel Data View Plugin v{{VERSION}}

### 功能特性
- 在Burp Suite中显示Excel响应数据的自定义标签页
- 支持XLS和XLSX格式的Excel文件
- 支持多工作表显示
- 自动检测HTTP响应中的Excel数据
- 修复中文编码问题
- 使用Burp Suite日志系统进行调试

### 安装方法
1. 下载 `excelDataView-{{VERSION}}-jar-with-dependencies.jar`
2. 在Burp Suite中导入该JAR文件
3. 插件会自动注册并在Excel响应中显示"Excel数据"标签页

### 使用说明
- 当HTTP响应包含Excel格式数据时，会自动显示"Excel数据"标签页
- 支持查看多个工作表
- 自动处理中文编码问题

### 更新日志
- 改进了HTTP响应数据提取
- 使用Burp Suite统一的日志系统
- 增强了错误处理和调试信息
- 支持模块化设计

### 技术架构
- Java 17 + Maven
- Apache POI for Excel处理
- Burp Suite Extender API
- Swing UI组件

---

*此版本由GitHub Actions自动构建发布*