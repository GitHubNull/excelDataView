package org.oxff.excel;

import burp.IBurpExtenderCallbacks;
import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

/**
 * Excel风格增强表格组件，提供Excel风格的显示和功能
 */
public class ExcelTable extends JTable {
    
    private final ExcelTableModel excelTableModel;
    private final IBurpExtenderCallbacks callbacks;
    private final RowNumberRenderer rowNumberRenderer;
    private final ExcelColumnHeaderRenderer columnHeaderRenderer;
    
    /**
     * 构造函数
     * 
     * @param excelData Excel数据
     * @param callbacks Burp Suite回调接口
     */
    public ExcelTable(List<List<String>> excelData, IBurpExtenderCallbacks callbacks) {
        this.excelTableModel = new ExcelTableModel(excelData);
        this.callbacks = callbacks;
        this.rowNumberRenderer = new RowNumberRenderer();
        this.columnHeaderRenderer = new ExcelColumnHeaderRenderer(1); // 第一个数据列从索引1开始
        
        // 设置模型
        setModel(excelTableModel);
        
        // 配置Excel风格
        configureExcelStyle();
        
        // 设置自定义渲染器
        setupRenderers();
        
        // 设置列宽
        setupColumnWidths(excelData);
        
        // 添加右键菜单
        setupContextMenu();
        
        // 设置工具提示
        setupToolTips();
    }
    
    /**
     * 配置Excel风格
     */
    private void configureExcelStyle() {
        // 使用ExcelStyleUtils配置基本样式
        ExcelStyleUtils.configureExcelStyle(this);
        
        // 设置行高
        setRowHeight(22);
        
        // 设置行号列宽度
        int rowNumberWidth = rowNumberRenderer.getPreferredWidth(getRowCount());
        getColumnModel().getColumn(0).setPreferredWidth(rowNumberWidth);
        getColumnModel().getColumn(0).setMinWidth(rowNumberWidth);
        getColumnModel().getColumn(0).setMaxWidth(rowNumberWidth);
        
        // 设置表头
        JTableHeader header = getTableHeader();
        header.setDefaultRenderer(columnHeaderRenderer);
        header.setReorderingAllowed(false);
        header.setResizingAllowed(true);
    }
    
    /**
     * 设置自定义渲染器
     */
    private void setupRenderers() {
        // 行号列使用行号渲染器
        getColumnModel().getColumn(0).setCellRenderer(rowNumberRenderer);
        
        // 数据列使用默认渲染器，但自定义样式
        DefaultTableCellRenderer dataRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, 
                                                           boolean isSelected, boolean hasFocus, 
                                                           int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                
                // 设置字体
                label.setFont(ExcelStyleUtils.createExcelFont());
                
                // 设置背景色（交替行颜色）
                if (!isSelected) {
                    label.setBackground(ExcelStyleUtils.getExcelRowBackgroundColor(row));
                } else {
                    label.setBackground(ExcelStyleUtils.getExcelSelectionBackgroundColor());
                }
                
                // 设置边框
                label.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 1, ExcelStyleUtils.getExcelBorderColor()));
                
                // 设置工具提示
                label.setToolTipText(excelTableModel.getCellToolTip(row, column));
                
                return label;
            }
        };
        
        // 为数据列设置渲染器
        for (int i = 1; i < getColumnCount(); i++) {
            getColumnModel().getColumn(i).setCellRenderer(dataRenderer);
        }
    }
    
    /**
     * 设置列宽
     * 
     * @param excelData Excel数据
     */
    private void setupColumnWidths(List<List<String>> excelData) {
        if (excelData == null || excelData.isEmpty()) {
            return;
        }
        
        // 为数据列设置宽度
        for (int i = 1; i < getColumnCount(); i++) {
            int columnIndex = i - 1; // 转换为数据索引
            int preferredWidth = ExcelStyleUtils.calculateColumnWidth(excelData, columnIndex);
            getColumnModel().getColumn(i).setPreferredWidth(preferredWidth);
            getColumnModel().getColumn(i).setMinWidth(50);
            getColumnModel().getColumn(i).setMaxWidth(500);
        }
    }
    
    /**
     * 设置右键菜单
     */
    private void setupContextMenu() {
        JPopupMenu contextMenu = new JPopupMenu();
        
        // 复制单元格
        JMenuItem copyCellItem = new JMenuItem("复制单元格");
        copyCellItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedCell();
            }
        });
        contextMenu.add(copyCellItem);
        
        // 复制行
        JMenuItem copyRowItem = new JMenuItem("复制行");
        copyRowItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedRow();
            }
        });
        contextMenu.add(copyRowItem);
        
        // 复制列
        JMenuItem copyColumnItem = new JMenuItem("复制列");
        copyColumnItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copySelectedColumn();
            }
        });
        contextMenu.add(copyColumnItem);
        
        // 分隔线
        contextMenu.addSeparator();
        
        // 复制全部
        JMenuItem copyAllItem = new JMenuItem("复制全部");
        copyAllItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                copyAllData();
            }
        });
        contextMenu.add(copyAllItem);
        
        // 添加到表格
        setComponentPopupMenu(contextMenu);
    }
    
    /**
     * 设置工具提示
     */
    private void setupToolTips() {
        // 表格的工具提示
        setToolTipText("Excel数据表格 - 右键点击复制数据");
        
        // 表头的工具提示
        JTableHeader header = getTableHeader();
        header.setToolTipText("Excel风格列标题 - 点击可排序");
    }
    
    /**
     * 复制选中的单元格
     */
    private void copySelectedCell() {
        int row = getSelectedRow();
        int column = getSelectedColumn();
        
        if (row >= 0 && column >= 0) {
            Object value = getValueAt(row, column);
            if (value != null) {
                copyToClipboard(value.toString());
                callbacks.printOutput("已复制单元格: " + excelTableModel.getExcelCellReference(row, column));
            }
        }
    }
    
    /**
     * 复制选中的行
     */
    private void copySelectedRow() {
        int row = getSelectedRow();
        if (row >= 0) {
            StringBuilder rowData = new StringBuilder();
            for (int col = 0; col < getColumnCount(); col++) {
                if (col > 0) rowData.append("\t");
                Object value = getValueAt(row, col);
                rowData.append(value != null ? value.toString() : "");
            }
            copyToClipboard(rowData.toString());
            callbacks.printOutput("已复制行 " + (row + 1));
        }
    }
    
    /**
     * 复制选中的列
     */
    private void copySelectedColumn() {
        int column = getSelectedColumn();
        if (column >= 0) {
            StringBuilder columnData = new StringBuilder();
            for (int row = 0; row < getRowCount(); row++) {
                if (row > 0) columnData.append("\n");
                Object value = getValueAt(row, column);
                columnData.append(value != null ? value.toString() : "");
            }
            copyToClipboard(columnData.toString());
            String columnLetter = ExcelStyleUtils.numberToExcelColumn(column);
            callbacks.printOutput("已复制列 " + columnLetter);
        }
    }
    
    /**
     * 复制全部数据
     */
    private void copyAllData() {
        StringBuilder allData = new StringBuilder();
        for (int row = 0; row < getRowCount(); row++) {
            if (row > 0) allData.append("\n");
            for (int col = 0; col < getColumnCount(); col++) {
                if (col > 0) allData.append("\t");
                Object value = getValueAt(row, col);
                allData.append(value != null ? value.toString() : "");
            }
        }
        copyToClipboard(allData.toString());
        callbacks.printOutput("已复制全部数据 (" + getRowCount() + " 行, " + (getColumnCount() - 1) + " 列)");
    }
    
    /**
     * 复制文本到剪贴板
     * 
     * @param text 要复制的文本
     */
    private void copyToClipboard(String text) {
        try {
            StringSelection stringSelection = new StringSelection(text);
            Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
            clipboard.setContents(stringSelection, null);
        } catch (Exception e) {
            callbacks.printError("复制到剪贴板失败: " + e.getMessage());
        }
    }
    
    /**
     * 获取Excel风格的单元格引用
     * 
     * @param row 行索引
     * @param column 列索引
     * @return Excel风格的单元格引用
     */
    public String getExcelCellReference(int row, int column) {
        return excelTableModel.getExcelCellReference(row, column);
    }
    
    /**
     * 获取表格模型
     * 
     * @return Excel表格模型
     */
    public ExcelTableModel getExcelTableModel() {
        return excelTableModel;
    }
}