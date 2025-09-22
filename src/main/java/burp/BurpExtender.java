package burp;

import org.oxff.excel.ExcelTabFactory;
import java.io.InputStream;
import java.util.Properties;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    
    private String version = "1.1.5"; // 默认版本号
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 读取版本信息
        loadVersion();
        
        // 设置插件名称（包含版本号）
        callbacks.setExtensionName("Excel Data View v" + version);
        
        // 注册自定义tab工厂
        callbacks.registerMessageEditorTabFactory(new ExcelTabFactory(callbacks));
        
        // 注册扩展状态监听器
        callbacks.registerExtensionStateListener(this);
        
        // 输出详细的插件加载信息
        printPluginInfo(callbacks, true);
    }
    
    @Override
    public void extensionUnloaded() {
        // 插件卸载时的处理
        // 注意：此时callbacks可能已经不可用，所以这里不使用callbacks
        System.out.println(getUnloadedMessage());
    }
    
    private void loadVersion() {
        try {
            InputStream is = getClass().getResourceAsStream("/version.properties");
            if (is != null) {
                Properties props = new Properties();
                props.load(is);
                version = props.getProperty("version", version);
            }
        } catch (Exception e) {
            // 读取失败时使用默认版本号
        }
    }
    
    private void printPluginInfo(IBurpExtenderCallbacks callbacks, boolean isLoading) {
        if (isLoading) {
            callbacks.printOutput("Excel Data View v" + version + " 插件加载完成");
            callbacks.printOutput("============================================");
            callbacks.printOutput("开发者信息:");
            callbacks.printOutput("- 作者: GitHubNull");
            callbacks.printOutput("- 仓库: https://github.com/GitHubNull/excelDataView");
            callbacks.printOutput("- 许可证: MIT License");
            callbacks.printOutput("");
            callbacks.printOutput("开源依赖:");
            callbacks.printOutput("- Burp Extender API: 2.1");
            callbacks.printOutput("- Apache POI: 5.2.3");
            callbacks.printOutput("- Apache POI OOXML: 5.4.0");
            callbacks.printOutput("");
            callbacks.printOutput("感谢使用本插件！如有问题请提交Issues或联系开发者。");
            callbacks.printOutput("============================================");
        }
    }
    
    private String getUnloadedMessage() {
        StringBuilder sb = new StringBuilder();
        sb.append("Excel Data View v").append(version).append(" 插件已卸载\n");
        sb.append("============================================\n");
        sb.append("感谢使用 Excel Data View 插件！\n");
        sb.append("如果您在使用过程中遇到任何问题或有改进建议，\n");
        sb.append("请访问: https://github.com/GitHubNull/excelDataView/issues\n");
        sb.append("\n");
        sb.append("欢迎继续关注我们的项目更新！\n");
        sb.append("============================================");
        return sb.toString();
    }
}