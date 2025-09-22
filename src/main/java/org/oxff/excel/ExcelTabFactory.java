package org.oxff.excel;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorTab;
import burp.IMessageEditorTabFactory;
import burp.IMessageEditorController;

@SuppressWarnings("ClassCanBeRecord")
public class ExcelTabFactory implements IMessageEditorTabFactory {
    
    private final IBurpExtenderCallbacks callbacks;
    
    public ExcelTabFactory(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    @Override
    public IMessageEditorTab createNewInstance(IMessageEditorController controller, boolean editable) {
        return new ExcelViewerTab(callbacks, controller);
    }
}