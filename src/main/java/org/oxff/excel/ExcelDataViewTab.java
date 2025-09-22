package org.oxff.excel;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;

public class ExcelDataViewTab implements IBurpExtender {

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        
        System.out.println("Excel Data View 插件加载中...");
        
        // 设置插件名称
        callbacks.registerExtensionStateListener(new ExtensionStateListener());
        
        // 注册自定义tab工厂
        callbacks.registerMessageEditorTabFactory(new ExcelTabFactory(callbacks));
        
        System.out.println("Excel Data View 插件加载完成");
    }
    
    private static class ExtensionStateListener implements burp.IExtensionStateListener {
        @Override
        public void extensionUnloaded() {
            System.out.println("Excel Data View 插件已卸载");
        }
    }
}