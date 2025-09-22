package org.oxff.excel;

import burp.IBurpExtenderCallbacks;
import burp.IMessageEditorTab;
import burp.IMessageEditorController;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.util.List;
import java.util.Map;
import javax.swing.SwingWorker;
import javax.swing.ListSelectionModel;

@SuppressWarnings({"unused", "FieldCanBeLocal"})
public class ExcelViewerTab implements IMessageEditorTab {

    private final IBurpExtenderCallbacks callbacks;
    private final IMessageEditorController controller;

    private JPanel mainPanel;
    private JTabbedPane sheetTabbedPane;
    private byte[] currentMessage;
    
    public ExcelViewerTab(IBurpExtenderCallbacks callbacks, IMessageEditorController controller) {
        this.callbacks = callbacks;
        this.controller = controller;

        initializeUI();
    }
    
    private void initializeUI() {
        mainPanel = new JPanel(new BorderLayout());
        sheetTabbedPane = new JTabbedPane();
        
        // 添加说明标签
        JLabel infoLabel = new JLabel("此标签页显示Excel格式的响应数据", SwingConstants.CENTER);
        infoLabel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        
        mainPanel.add(infoLabel, BorderLayout.CENTER);
    }
    
    @Override
    public void setMessage(byte[] message, boolean isRequest) {
        if (isRequest) {
            return; // 只处理响应
        }
        
        this.currentMessage = message;
        if (message != null) {
            processResponse();
        } else {
            clearDisplay();
        }
    }
    
    @Override
    public byte[] getMessage() {
        return currentMessage;
    }
    
    @Override
    public boolean isEnabled(byte[] message, boolean isRequest) {
        if (isRequest || message == null) {
            return false;
        }
        
        return ExcelProcessor.isExcelResponse(message);
    }
    
    @Override
    public String getTabCaption() {
        return "Excel数据";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    @Override
    public boolean isModified() {
        return false;
    }
    
    @Override
    public byte[] getSelectedData() {
        return null; // 不支持选择数据
    }
    
    private void processResponse() {
        if (currentMessage == null) {
            clearDisplay();
            return;
        }
        
        // 在后台线程处理Excel数据，然后在EDT中更新UI
        new SwingWorker<Map<String, List<List<String>>>, Void>() {
            @Override
            protected Map<String, List<List<String>>> doInBackground() throws Exception {
                return ExcelProcessor.processExcelData(currentMessage);
            }
            
            @Override
            protected void done() {
                try {
                    Map<String, List<List<String>>> excelData = get();
                    updateUIWithExcelData(excelData);
                } catch (Exception e) {
                    System.err.println("处理Excel数据时出错: " + e.getMessage());
                    showErrorMessage("处理Excel数据时出错: " + e.getMessage());
                }
            }
        }.execute();
    }
    
    private void updateUIWithExcelData(Map<String, List<List<String>>> excelData) {
        // 清空现有显示
        mainPanel.removeAll();
        
        if (excelData == null || excelData.isEmpty()) {
            showEmptyMessage();
            return;
        }
        
        try {
            // 创建新的标签页容器
            sheetTabbedPane = new JTabbedPane();
            
            // 为每个工作表创建表格
            for (Map.Entry<String, List<List<String>>> entry : excelData.entrySet()) {
                String sheetName = entry.getKey();
                List<List<String>> sheetData = entry.getValue();
                
                JTable table = createTableFromData(sheetData);
                JScrollPane scrollPane = new JScrollPane(table);
                
                sheetTabbedPane.addTab(sheetName, scrollPane);
            }
            
            mainPanel.add(sheetTabbedPane, BorderLayout.CENTER);
            mainPanel.revalidate();
            mainPanel.repaint();
            
            System.out.println("成功解析Excel数据，包含 " + excelData.size() + " 个工作表");
            
        } catch (Exception e) {
            System.err.println("更新UI时出错: " + e.getMessage());
            showErrorMessage("更新UI时出错: " + e.getMessage());
        }
    }
    
    private JTable createTableFromData(List<List<String>> data) {
        if (data == null || data.isEmpty()) {
            // 创建一个带有默认列的空表格，避免空模型导致的渲染问题
            DefaultTableModel emptyModel = new DefaultTableModel();
            emptyModel.addColumn("无数据");
            emptyModel.addRow(new Object[]{"表格为空"});
            JTable emptyTable = new JTable(emptyModel);
            emptyTable.setEnabled(false);
            return emptyTable;
        }
        
        // 确定列数
        int maxColumns = 0;
        for (List<String> row : data) {
            maxColumns = Math.max(maxColumns, row.size());
        }
        
        try {
            // 创建表格模型
            DefaultTableModel model = new DefaultTableModel();
            
            // 设置列名
            for (int i = 0; i < maxColumns; i++) {
                model.addColumn("列 " + (i + 1));
            }
            
            // 添加数据行
            for (List<String> rowData : data) {
                if (rowData == null) continue;
                
                Object[] rowArray = new Object[maxColumns];
                for (int i = 0; i < maxColumns; i++) {
                    if (i < rowData.size()) {
                        // 处理中文编码
                        String cellValue = rowData.get(i);
                        rowArray[i] = ExcelProcessor.fixChineseEncoding(cellValue != null ? cellValue : "");
                    } else {
                        rowArray[i] = "";
                    }
                }
                model.addRow(rowArray);
            }
            
            JTable table = new JTable(model);
            
            // 使用更安全的表格配置
            table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            table.setFillsViewportHeight(true);
            table.setAutoCreateRowSorter(true);
            table.setRowHeight(22);
            
            // 设置表格选择模式
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
            table.setCellSelectionEnabled(false);
            
            return table;
            
        } catch (Exception e) {
            System.err.println("创建表格时出错: " + e.getMessage());
            // 创建错误表格
            DefaultTableModel errorModel = new DefaultTableModel();
            errorModel.addColumn("错误");
            errorModel.addRow(new Object[]{"创建表格时出错: " + e.getMessage()});
            JTable errorTable = new JTable(errorModel);
            errorTable.setEnabled(false);
            return errorTable;
        }
    }
    
    private void clearDisplay() {
        mainPanel.removeAll();
        JLabel infoLabel = new JLabel("此标签页显示Excel格式的响应数据", SwingConstants.CENTER);
        infoLabel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        mainPanel.add(infoLabel, BorderLayout.CENTER);
        mainPanel.revalidate();
        mainPanel.repaint();
    }
    
    private void showEmptyMessage() {
        mainPanel.removeAll();
        JLabel label = new JLabel("未找到有效的Excel数据", SwingConstants.CENTER);
        label.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        mainPanel.add(label, BorderLayout.CENTER);
        mainPanel.revalidate();
        mainPanel.repaint();
    }
    
    private void showErrorMessage(String message) {
        mainPanel.removeAll();
        JLabel label = new JLabel("<html><font color='red'>" + message + "</font></html>", SwingConstants.CENTER);
        label.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        mainPanel.add(label, BorderLayout.CENTER);
        mainPanel.revalidate();
        mainPanel.repaint();
    }
}