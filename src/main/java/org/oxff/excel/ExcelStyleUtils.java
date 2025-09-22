package org.oxff.excel;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import java.awt.*;

/**
 * Excel样式工具类，提供Excel风格的样式和转换功能
 */
public class ExcelStyleUtils {
    
    /**
     * 将数字转换为Excel风格的列标题（1->A, 2->B, 27->AA, 28->AB等）
     * 
     * @param columnNumber 列号（从1开始）
     * @return Excel风格的列标题
     */
    public static String numberToExcelColumn(int columnNumber) {
        if (columnNumber < 1) {
            return "";
        }
        
        StringBuilder columnName = new StringBuilder();
        while (columnNumber > 0) {
            int remainder = (columnNumber - 1) % 26;
            columnName.insert(0, (char) ('A' + remainder));
            columnNumber = (columnNumber - 1) / 26;
        }
        
        return columnName.toString();
    }
    
    /**
     * 将Excel风格的列标题转换为数字（A->1, B->2, AA->27, AB->28等）
     * 
     * @param columnName Excel风格的列标题
     * @return 列号（从1开始）
     */
    public static int excelColumnToNumber(String columnName) {
        if (columnName == null || columnName.isEmpty()) {
            return 0;
        }
        
        columnName = columnName.toUpperCase();
        int columnNumber = 0;
        
        for (int i = 0; i < columnName.length(); i++) {
            char c = columnName.charAt(i);
            if (c >= 'A' && c <= 'Z') {
                columnNumber = columnNumber * 26 + (c - 'A' + 1);
            }
        }
        
        return columnNumber;
    }
    
    /**
     * 创建Excel风格的表格字体
     * 
     * @return Excel风格的字体
     */
    public static Font createExcelFont() {
        return new Font("Arial", Font.PLAIN, 12);
    }
    
    /**
     * 创建Excel风格的表头字体
     * 
     * @return Excel风格的表头字体
     */
    public static Font createExcelHeaderFont() {
        return new Font("Arial", Font.BOLD, 12);
    }
    
    /**
     * 获取Excel风格的表头背景色
     * 
     * @return 表头背景色
     */
    public static Color getExcelHeaderBackgroundColor() {
        return new Color(240, 240, 240);
    }
    
    /**
     * 获取Excel风格的表头文本颜色
     * 
     * @return 表头文本颜色
     */
    public static Color getExcelHeaderTextColor() {
        return Color.BLACK;
    }
    
    /**
     * 获取Excel风格的边框颜色
     * 
     * @return 边框颜色
     */
    public static Color getExcelBorderColor() {
        return new Color(217, 217, 217);
    }
    
    /**
     * 获取Excel风格的交替行背景色
     * 
     * @param rowIndex 行索引
     * @return 交替行背景色
     */
    public static Color getExcelRowBackgroundColor(int rowIndex) {
        return rowIndex % 2 == 0 ? Color.WHITE : new Color(249, 249, 249);
    }
    
    /**
     * 获取Excel风格的选中行背景色
     * 
     * @return 选中行背景色
     */
    public static Color getExcelSelectionBackgroundColor() {
        return new Color(173, 216, 230);
    }
    
    /**
     * 配置表格为Excel风格
     * 
     * @param table 要配置的表格
     */
    public static void configureExcelStyle(JTable table) {
        // 设置字体
        table.setFont(createExcelFont());
        table.setRowHeight(22);
        
        // 设置网格线
        table.setShowGrid(true);
        table.setGridColor(getExcelBorderColor());
        
        // 设置选择模式
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setCellSelectionEnabled(true);
        
        // 设置自动调整
        table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        table.setFillsViewportHeight(true);
        
        // 配置表头
        JTableHeader header = table.getTableHeader();
        header.setFont(createExcelHeaderFont());
        header.setBackground(getExcelHeaderBackgroundColor());
        header.setForeground(getExcelHeaderTextColor());
        header.setReorderingAllowed(false);
        header.setResizingAllowed(true);
    }
    
    /**
     * 计算列宽（基于字符数量的估算）
     * 
     * @param data 表格数据
     * @param columnIndex 列索引
     * @return 推荐的列宽
     */
    public static int calculateColumnWidth(java.util.List<java.util.List<String>> data, int columnIndex) {
        if (data == null || data.isEmpty()) {
            return 100;
        }
        
        int maxWidth = 80; // 最小宽度
        int headerWidth = numberToExcelColumn(columnIndex + 1).length() * 10 + 20;
        maxWidth = Math.max(maxWidth, headerWidth);
        
        for (java.util.List<String> row : data) {
            if (columnIndex < row.size() && row.get(columnIndex) != null) {
                int cellWidth = row.get(columnIndex).length() * 8 + 20;
                maxWidth = Math.max(maxWidth, Math.min(cellWidth, 300)); // 限制最大宽度
            }
        }
        
        return maxWidth;
    }
    
    /**
     * 获取行号显示的宽度
     * 
     * @param rowCount 总行数
     * @return 行号列宽度
     */
    public static int getRowNumberWidth(int rowCount) {
        int digitCount = String.valueOf(rowCount).length();
        return digitCount * 10 + 20;
    }
}