package org.oxff.excel;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Excel风格行号渲染器，显示行号（1, 2, 3...）
 */
public class RowNumberRenderer extends DefaultTableCellRenderer {
    
    private final Font font;
    private final Color backgroundColor;
    private final Color textColor;
    private final Color borderColor;
    
    public RowNumberRenderer() {
        // 使用ExcelStyleUtils中定义的样式
        this.font = ExcelStyleUtils.createExcelFont();
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
        setBorder(BorderFactory.createMatteBorder(0, 1, 1, 1, borderColor));
    }
    
    @Override
    public Component getTableCellRendererComponent(JTable table, Object value, 
                                                 boolean isSelected, boolean hasFocus, 
                                                 int row, int column) {
        
        // 调用父类方法获取基础组件
        JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
        
        // 设置行号文本（从1开始）
        String rowNumber = String.valueOf(row + 1);
        label.setText(rowNumber);
        
        // 设置工具提示
        label.setToolTipText("行 " + rowNumber);
        
        // 如果选中，使用选中样式
        if (isSelected) {
            label.setBackground(ExcelStyleUtils.getExcelSelectionBackgroundColor());
            label.setForeground(Color.BLACK);
        } else {
            // 行号列总是使用表头背景色
            label.setBackground(backgroundColor);
            label.setForeground(textColor);
        }
        
        // 设置边框
        label.setBorder(BorderFactory.createMatteBorder(0, 1, 1, 1, borderColor));
        
        // 禁用焦点边框
        if (hasFocus) {
            label.setBorder(BorderFactory.createMatteBorder(0, 1, 1, 1, borderColor));
        }
        
        return label;
    }
    
    /**
     * 获取行号列的推荐宽度
     * 
     * @param rowCount 总行数
     * @return 行号列宽度
     */
    public static int getPreferredWidth(int rowCount) {
        return ExcelStyleUtils.getRowNumberWidth(rowCount);
    }
}