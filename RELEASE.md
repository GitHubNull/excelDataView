# 发布指南

## 自动发布流程

本项目使用GitHub Actions实现自动化的版本发布流程。

### 触发条件
- 推送版本标签：`git tag v1.0.0 && git push origin v1.0.0`
- 标签格式：`v` + 版本号（如 `v1.0.0`, `v1.0.1`）
- 也可以在GitHub Actions页面手动触发

### 发布流程
1. **版本检测**：自动从标签中提取版本号
2. **版本更新**：自动更新pom.xml中的版本号
3. **项目构建**：使用Maven编译并打包
4. **发布说明**：自动生成发布说明
5. **创建Release**：自动创建GitHub Release
6. **文件上传**：上传JAR文件到Release

### 生成的文件
- `excelDataView-{version}.jar` - 基础JAR文件
- `excelDataView-{version}-jar-with-dependencies.jar` - 包含所有依赖的完整JAR文件

### 使用方法
1. 下载包含依赖的JAR文件：`excelDataView-{version}-jar-with-dependencies.jar`
2. 在Burp Suite中导入该文件
3. 插件会自动加载并注册

## 手动发布

如果需要手动发布：

1. **编译项目**
   ```bash
   mvn clean package
   ```

2. **创建Release**
   - 在GitHub上创建新的Release
   - 上传target目录中的JAR文件
   - 填写发布说明

## 版本管理

### 版本号格式
- 遵循语义化版本：`主版本号.次版本号.修订号`
- 例如：`1.0.0`, `1.0.1`, `1.1.0`

### 发布新版本
```bash
# 创建并推送版本标签
git tag v1.0.0
git push origin v1.0.0

# 或者使用 annotated tag
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

### 查看发布状态
- GitHub Actions页面：https://github.com/[username]/excelDataView/actions
- Release页面：https://github.com/[username]/excelDataView/releases

## 故障排除

### 常见问题
1. **标签格式错误**：确保标签以`v`开头
2. **权限问题**：确保有推送标签和创建Release的权限
3. **构建失败**：检查GitHub Actions日志

### 调试方法
1. 在本地运行构建：`mvn clean package`
2. 检查Maven配置和依赖
3. 查看GitHub Actions错误日志