package org.oxff.excel;

import javax.swing.table.DefaultTableModel;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;

/**
 * Excel风格表格模型，支持行号和Excel风格列标题
 */
public class ExcelTableModel extends DefaultTableModel {
    
    private final List<List<String>> excelData;
    private final int dataColumnCount;
    
    /**
     * 构造函数
     * 
     * @param excelData Excel数据列表
     */
    public ExcelTableModel(List<List<String>> excelData) {
        this.excelData = excelData;
        
        // 计算数据列数
        this.dataColumnCount = calculateMaxColumns(excelData);
        
        // 初始化表格数据
        initializeData();
    }
    
    /**
     * 计算最大列数
     * 
     * @param data Excel数据
     * @return 最大列数
     */
    private int calculateMaxColumns(List<List<String>> data) {
        if (data == null || data.isEmpty()) {
            return 0;
        }
        
        int maxColumns = 0;
        for (List<String> row : data) {
            if (row != null) {
                maxColumns = Math.max(maxColumns, row.size());
            }
        }
        
        return maxColumns;
    }
    
    /**
     * 初始化表格数据
     */
    private void initializeData() {
        try {
            // 清空现有数据
            setDataVector(new Vector<Vector<Object>>(), new Vector<Object>());
            
            if (excelData == null || excelData.isEmpty()) {
                // 创建空数据时的默认行
                createEmptyDataRow();
                return;
            }
            
            // 验证和预处理数据
            List<List<String>> validatedData = validateAndPreprocessData(excelData);
            
            // 添加Excel数据行
            for (int i = 0; i < validatedData.size(); i++) {
                List<String> rowData = validatedData.get(i);
                Vector<Object> rowVector = new Vector<>();
                
                // 第一列是行号占位符
                rowVector.add("");
                
                // 添加数据列
                if (rowData != null) {
                    for (int j = 0; j < dataColumnCount; j++) {
                        if (j < rowData.size() && rowData.get(j) != null) {
                            // 处理中文编码
                            String cellValue = ExcelProcessor.fixChineseEncoding(rowData.get(j));
                            rowVector.add(cellValue);
                        } else {
                            rowVector.add("");
                        }
                    }
                } else {
                    // 空行
                    for (int j = 0; j < dataColumnCount; j++) {
                        rowVector.add("");
                    }
                }
                
                addRow(rowVector);
            }
        } catch (Exception e) {
            // 如果初始化失败，创建错误行
            createErrorDataRow("初始化数据失败: " + e.getMessage());
        }
    }
    
    /**
     * 创建空数据行
     */
    private void createEmptyDataRow() {
        Vector<Object> emptyRow = new Vector<>();
        emptyRow.add("");
        for (int i = 0; i < dataColumnCount; i++) {
            emptyRow.add("");
        }
        addRow(emptyRow);
    }
    
    /**
     * 创建错误数据行
     * 
     * @param errorMessage 错误信息
     */
    private void createErrorDataRow(String errorMessage) {
        Vector<Object> errorRow = new Vector<>();
        errorRow.add("");
        errorRow.add(errorMessage);
        for (int i = 1; i < dataColumnCount; i++) {
            errorRow.add("");
        }
        addRow(errorRow);
    }
    
    /**
     * 验证和预处理数据
     * 
     * @param rawData 原始数据
     * @return 验证后的数据
     */
    private List<List<String>> validateAndPreprocessData(List<List<String>> rawData) {
        if (rawData == null || rawData.isEmpty()) {
            return rawData;
        }
        
        List<List<String>> processedData = new ArrayList<>();
        
        for (List<String> row : rawData) {
            if (row == null) {
                // 处理空行
                List<String> emptyRow = new ArrayList<>();
                for (int i = 0; i < dataColumnCount; i++) {
                    emptyRow.add("");
                }
                processedData.add(emptyRow);
            } else {
                // 处理正常行，确保长度一致
                List<String> processedRow = new ArrayList<>(row);
                while (processedRow.size() < dataColumnCount) {
                    processedRow.add("");
                }
                processedData.add(processedRow);
            }
        }
        
        return processedData;
    }
    
    @Override
    public int getColumnCount() {
        // 总列数 = 行号列 + 数据列
        return 1 + dataColumnCount;
    }
    
    @Override
    public int getRowCount() {
        if (excelData == null || excelData.isEmpty()) {
            return 1; // 至少显示一行空数据
        }
        return excelData.size();
    }
    
    @Override
    public String getColumnName(int column) {
        if (column == 0) {
            return ""; // 行号列
        } else {
            // 返回Excel风格的列标题
            return ExcelStyleUtils.numberToExcelColumn(column);
        }
    }
    
    @Override
    public Object getValueAt(int row, int column) {
        if (row < 0 || row >= getRowCount() || column < 0 || column >= getColumnCount()) {
            return null;
        }
        
        if (column == 0) {
            // 行号列
            return String.valueOf(row + 1);
        } else {
            // 数据列
            return super.getValueAt(row, column);
        }
    }
    
    @Override
    public boolean isCellEditable(int row, int column) {
        // 所有单元格都不可编辑
        return false;
    }
    
    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }
    
    /**
     * 获取Excel风格的单元格引用（如A1, B2, C3等）
     * 
     * @param row 行索引（从0开始）
     * @param column 列索引（从0开始）
     * @return Excel风格的单元格引用
     */
    public String getExcelCellReference(int row, int column) {
        if (column == 0) {
            return "行" + (row + 1);
        } else {
            String columnLetter = ExcelStyleUtils.numberToExcelColumn(column);
            return columnLetter + (row + 1);
        }
    }
    
    /**
     * 获取数据列数量（不包括行号列）
     * 
     * @return 数据列数量
     */
    public int getDataColumnCount() {
        return dataColumnCount;
    }
    
    /**
     * 获取指定单元格的工具提示
     * 
     * @param row 行索引
     * @param column 列索引
     * @return 工具提示文本
     */
    public String getCellToolTip(int row, int column) {
        if (column == 0) {
            return "行 " + (row + 1);
        } else {
            String columnLetter = ExcelStyleUtils.numberToExcelColumn(column);
            return "单元格 " + columnLetter + (row + 1);
        }
    }
    
    /**
     * 检查是否为空数据模型
     * 
     * @return 是否为空数据模型
     */
    public boolean isEmpty() {
        return excelData == null || excelData.isEmpty();
    }
    
    /**
     * 获取原始Excel数据
     * 
     * @return 原始Excel数据
     */
    public List<List<String>> getExcelData() {
        return excelData;
    }
}