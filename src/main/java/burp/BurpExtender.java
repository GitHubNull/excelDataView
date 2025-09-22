package burp;

import org.oxff.excel.ExcelTabFactory;

public class BurpExtender implements IBurpExtender {
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        // 设置插件名称
        callbacks.setExtensionName("Excel Data View");
        
        // 注册自定义tab工厂
        callbacks.registerMessageEditorTabFactory(new ExcelTabFactory(callbacks));
        
        callbacks.printOutput("Excel Data View 插件加载完成");
    }
}