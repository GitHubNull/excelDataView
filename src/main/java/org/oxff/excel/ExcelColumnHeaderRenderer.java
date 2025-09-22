package org.oxff.excel;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Excel风格列头渲染器，显示Excel风格的列标题（A, B, C...）
 */
public class ExcelColumnHeaderRenderer extends DefaultTableCellRenderer {
    
    private final Font font;
    private final Color backgroundColor;
    private final Color textColor;
    private final Color borderColor;
    private final int firstDataColumn;
    
    /**
     * 构造函数
     * 
     * @param firstDataColumn 第一个数据列的索引（跳过行号列）
     */
    public ExcelColumnHeaderRenderer(int firstDataColumn) {
        this.firstDataColumn = firstDataColumn;
        
        // 使用ExcelStyleUtils中定义的样式
        this.font = ExcelStyleUtils.createExcelHeaderFont();
        this.backgroundColor = ExcelStyleUtils.getExcelHeaderBackgroundColor();
        this.textColor = ExcelStyleUtils.getExcelHeaderTextColor();
        this.borderColor = ExcelStyleUtils.getExcelBorderColor();
        
        // 设置渲染器属性
        setHorizontalAlignment(SwingConstants.CENTER);
        setVerticalAlignment(SwingConstants.CENTER);
        setOpaque(true);
        setFont(font);
        setBackground(backgroundColor);
        setForeground(textColor);
        setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, borderColor));
    }
    
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, 
                                                 boolean isSelected, boolean hasFocus, 
                                                 int row, int column) {
        
        // 调用父类方法获取基础组件
        JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        // 计算Excel风格的列标题
        String columnTitle;
        if (column == 0) {
            // 第一列是行号列
            columnTitle = "";
        } else {
            // 数据列从A开始
            int excelColumnNumber = column - firstDataColumn + 1;
            columnTitle = ExcelStyleUtils.numberToExcelColumn(excelColumnNumber);
        }
        
        label.setText(columnTitle);
        
        // 设置工具提示
        if (!columnTitle.isEmpty()) {
            label.setToolTipText("列 " + columnTitle);
        }
        
        // 列头总是使用表头样式，不受选择状态影响
        label.setBackground(backgroundColor);
        label.setForeground(textColor);
        
        // 设置边框
        if (column == 0) {
            // 行号列的边框
            label.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 1, borderColor));
        } else {
            // 数据列的边框
            label.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, borderColor));
        }
        
        // 禁用焦点边框
        if (hasFocus) {
            if (column == 0) {
                label.setBorder(BorderFactory.createMatteBorder(1, 1, 1, 1, borderColor));
            } else {
                label.setBorder(BorderFactory.createMatteBorder(1, 0, 1, 1, borderColor));
            }
        }
        
        return label;
    }
    
    /**
     * 获取Excel风格的列标题
     * 
     * @param column 列索引
     * @return Excel风格的列标题
     */
    public String getExcelColumnTitle(int column) {
        if (column == 0) {
            return "";
        }
        int excelColumnNumber = column - firstDataColumn + 1;
        return ExcelStyleUtils.numberToExcelColumn(excelColumnNumber);
    }
    
    /**
     * 计算列宽（基于Excel列标题的宽度）
     * 
     * @param column 列索引
     * @return 推荐的列宽
     */
    public int getPreferredColumnWidth(int column) {
        if (column == 0) {
            return RowNumberRenderer.getPreferredWidth(100); // 预估行数
        } else {
            String columnTitle = getExcelColumnTitle(column);
            return columnTitle.length() * 12 + 30; // 基于字符长度的估算
        }
    }
}