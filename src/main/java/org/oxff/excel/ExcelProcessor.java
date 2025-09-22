package org.oxff.excel;

import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExcelProcessor {

    // 常见的Excel文件MIME类型
    private static final String[] EXCEL_CONTENT_TYPES = {
        "application/vnd.ms-excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/octet-stream"
    };
    
    // Excel文件头标识
    private static final byte[] XLSX_HEADER = {(byte) 0x50, (byte) 0x4B, (byte) 0x03, (byte) 0x04}; // ZIP文件头
    private static final byte[] XLS_HEADER = {(byte) 0xD0, (byte) 0xCF, (byte) 0x11, (byte) 0xE0}; // OLE文件头
    
    /**
     * 检查响应是否为Excel格式
     */
    public static boolean isExcelResponse(byte[] response) {
        if (response == null || response.length < 4) {
            return false;
        }
        
        // 检查是否为HTTP响应
        byte[] actualData = response;
        if (isHttpResponse(response)) {
            actualData = extractResponseBody(response);
        }
        
        if (actualData == null || actualData.length < 4) {
            return false;
        }
        
        // 检查文件头
        if (isXLSXHeader(actualData) || isXLSHeader(actualData)) {
            return true;
        }
        
        // 检查Content-Type（如果可以从响应中提取）
        String contentType = extractContentType(response);
        if (contentType != null) {
            for (String excelType : EXCEL_CONTENT_TYPES) {
                if (contentType.toLowerCase().contains(excelType.toLowerCase())) {
                    System.out.println("ExcelProcessor: 通过Content-Type检测到Excel格式: " + contentType);
                    return true;
                }
            }
        }
        
        // 调试信息
        String hexDump = String.format("%02X %02X %02X %02X", 
            actualData[0] & 0xFF, actualData[1] & 0xFF, 
            actualData[2] & 0xFF, actualData[3] & 0xFF);
        System.out.println("ExcelProcessor: 未检测到Excel格式，数据头部: " + hexDump);
        
        return false;
    }
    
    /**
     * 处理Excel数据
     */
    public static Map<String, List<List<String>>> processExcelData(byte[] excelData) throws IOException {
        Map<String, List<List<String>>> result = new LinkedHashMap<>();
        
        if (excelData == null || excelData.length < 4) {
            System.out.println("ExcelProcessor: 数据为空或太小，数据长度=" + (excelData != null ? excelData.length : 0));
            return result;
        }
        
        // 检查是否为HTTP响应
        byte[] actualData = excelData;
        if (isHttpResponse(excelData)) {
            System.out.println("ExcelProcessor: 检测到HTTP响应，提取响应体");
            actualData = extractResponseBody(excelData);
        }
        
        if (actualData == null || actualData.length < 4) {
            System.out.println("ExcelProcessor: 提取后的数据为空或太小，数据长度=" + (actualData != null ? actualData.length : 0));
            return result;
        }
        
        // 调试信息
        System.out.println("ExcelProcessor: 开始处理Excel数据，数据长度=" + actualData.length);
        if (actualData.length >= 4) {
            String hexDump = String.format("%02X %02X %02X %02X", 
                actualData[0] & 0xFF, actualData[1] & 0xFF, 
                actualData[2] & 0xFF, actualData[3] & 0xFF);
            System.out.println("ExcelProcessor: 数据头部 (hex): " + hexDump);
        }
        
        Workbook workbook = null;
        try (ByteArrayInputStream bis = new ByteArrayInputStream(actualData)) {
            if (isXLSXHeader(actualData)) {
                System.out.println("ExcelProcessor: 检测到XLSX格式");
                workbook = new XSSFWorkbook(bis);
            } else if (isXLSHeader(actualData)) {
                System.out.println("ExcelProcessor: 检测到XLS格式");
                workbook = new HSSFWorkbook(bis);
            } else {
                String errorMsg = "不支持的Excel格式。数据头部: " + 
                    (actualData.length >= 4 ? String.format("%02X %02X %02X %02X", 
                        actualData[0] & 0xFF, actualData[1] & 0xFF, 
                        actualData[2] & 0xFF, actualData[3] & 0xFF) : "数据不足");
                System.err.println("ExcelProcessor: " + errorMsg);
                throw new IOException(errorMsg);
            }
            
            // 处理每个工作表
            for (int i = 0; i < workbook.getNumberOfSheets(); i++) {
                Sheet sheet = workbook.getSheetAt(i);
                String sheetName = sheet.getSheetName();
                
                if (sheetName == null || sheetName.trim().isEmpty()) {
                    sheetName = "工作表 " + (i + 1);
                }
                
                List<List<String>> sheetData = extractSheetData(sheet);
                if (!sheetData.isEmpty()) {
                    result.put(sheetName, sheetData);
                }
            }
            
        } catch (Exception e) {
            throw new IOException("解析Excel文件失败: " + e.getMessage(), e);
        } finally {
            if (workbook != null) {
                try {
                    workbook.close();
                } catch (IOException e) {
                    // 忽略关闭异常
                }
            }
        }
        
        return result;
    }
    
    /**
     * 提取工作表数据
     */
    private static List<List<String>> extractSheetData(Sheet sheet) {
        List<List<String>> sheetData = new ArrayList<>();
        
        // 确定数据范围
        int firstRow = sheet.getFirstRowNum();
        int lastRow = sheet.getLastRowNum();
        
        if (firstRow < 0 || lastRow < 0 || lastRow < firstRow) {
            return sheetData;
        }
        
        // 遍历所有行
        for (int rowNum = firstRow; rowNum <= lastRow; rowNum++) {
            Row row = sheet.getRow(rowNum);
            if (row == null) {
                continue; // 跳过空行
            }
            
            List<String> rowData = extractRowData(row);
            if (!rowData.isEmpty()) {
                sheetData.add(rowData);
            }
        }
        
        return sheetData;
    }
    
    /**
     * 提取行数据
     */
    private static List<String> extractRowData(Row row) {
        List<String> rowData = new ArrayList<>();
        
        int firstCell = row.getFirstCellNum();
        int lastCell = row.getLastCellNum();
        
        if (firstCell < 0 || lastCell < 0 || lastCell < firstCell) {
            return rowData;
        }
        
        // 遍历所有单元格
        for (int cellNum = firstCell; cellNum < lastCell; cellNum++) {
            Cell cell = row.getCell(cellNum);
            if (cell == null) {
                rowData.add("");
                continue;
            }
            
            String cellValue = getCellValueAsString(cell);
            rowData.add(cellValue);
        }
        
        return rowData;
    }
    
    /**
     * 获取单元格值作为字符串
     */
    private static String getCellValueAsString(Cell cell) {
        if (cell == null) {
            return "";
        }
        
        CellType cellType = cell.getCellType();
        
        switch (cellType) {
            case STRING:
                return cell.getStringCellValue().trim();
            case NUMERIC:
                if (DateUtil.isCellDateFormatted(cell)) {
                    return cell.getDateCellValue().toString();
                } else {
                    // 避免科学计数法
                    double numValue = cell.getNumericCellValue();
                    if (numValue == (long) numValue) {
                        return String.valueOf((long) numValue);
                    } else {
                        return String.valueOf(numValue);
                    }
                }
            case BOOLEAN:
                return String.valueOf(cell.getBooleanCellValue());
            case FORMULA:
                try {
                    return getCellValueAsString(cell.getCachedFormulaResultType());
                } catch (Exception e) {
                    return cell.getCellFormula();
                }
            case BLANK:
                return "";
            default:
                return "";
        }
    }
    
    /**
     * 修复中文编码问题
     */
    public static String fixChineseEncoding(String text) {
        if (text == null) {
            return "";
        }
        
        // 尝试检测并修复常见的编码问题
        try {
            // 如果文本看起来已经正常，直接返回
            if (text.matches("^[\\x00-\\x7F\\u4E00-\\u9FA5\\u3000-\\u303F\\uFF00-\\uFFEF]*$")) {
                return text;
            }
            
            // 尝试从ISO-8859-1转换
            byte[] bytes = text.getBytes(StandardCharsets.ISO_8859_1);
            String converted = new String(bytes, StandardCharsets.UTF_8);
            
            // 检查转换后是否包含中文字符
            if (converted.matches(".*[\\u4E00-\\u9FA5].*")) {
                return converted;
            }
            
            // 尝试从GBK转换
            try {
                converted = new String(bytes, "GBK");
                if (converted.matches(".*[\\u4E00-\\u9FA5].*")) {
                    return converted;
                }
            } catch (Exception e) {
                // 忽略编码转换异常
            }
            
        } catch (Exception e) {
            // 忽略编码处理异常，返回原始文本
        }
        
        return text;
    }
    
    /**
     * 检查是否为XLSX格式
     */
    private static boolean isXLSXHeader(byte[] data) {
        if (data.length < 4) return false;
        return data[0] == XLSX_HEADER[0] && data[1] == XLSX_HEADER[1] &&
               data[2] == XLSX_HEADER[2] && data[3] == XLSX_HEADER[3];
    }
    
    /**
     * 检查是否为XLS格式
     */
    private static boolean isXLSHeader(byte[] data) {
        if (data.length < 4) return false;
        return data[0] == XLS_HEADER[0] && data[1] == XLS_HEADER[1] &&
               data[2] == XLS_HEADER[2] && data[3] == XLS_HEADER[3];
    }
    
    /**
     * 从HTTP响应中提取响应体
     */
    private static byte[] extractResponseBody(byte[] response) {
        try {
            // 查找header结束位置
            int headerEnd = -1;
            for (int i = 0; i < response.length - 3; i++) {
                if (response[i] == '\r' && response[i + 1] == '\n' && 
                    response[i + 2] == '\r' && response[i + 3] == '\n') {
                    headerEnd = i + 4; // 跳过 \r\n\r\n
                    break;
                }
            }
            
            if (headerEnd == -1 || headerEnd >= response.length) {
                // 没有找到HTTP头部，可能是直接的数据
                System.out.println("ExcelProcessor: 未找到HTTP头部，假设为原始数据");
                return response;
            }
            
            // 提取响应体
            byte[] body = new byte[response.length - headerEnd];
            System.arraycopy(response, headerEnd, body, 0, body.length);
            
            System.out.println("ExcelProcessor: 提取响应体，头部大小=" + headerEnd + "，响应体大小=" + body.length);
            return body;
            
        } catch (Exception e) {
            System.err.println("ExcelProcessor: 提取响应体时出错: " + e.getMessage());
            return response; // 出错时返回原始数据
        }
    }
    
    /**
     * 检查是否为HTTP响应
     */
    private static boolean isHttpResponse(byte[] data) {
        if (data == null || data.length < 4) return false;
        
        // 检查是否以 "HTTP" 开头
        return data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P';
    }
    
    /**
     * 从HTTP响应中提取Content-Type
     */
    private static String extractContentType(byte[] response) {
        try {
            // 查找header结束位置
            int headerEnd = -1;
            for (int i = 0; i < response.length - 3; i++) {
                if (response[i] == '\r' && response[i + 1] == '\n' && 
                    response[i + 2] == '\r' && response[i + 3] == '\n') {
                    headerEnd = i;
                    break;
                }
            }
            
            if (headerEnd == -1) {
                return null;
            }
            
            // 提取header部分
            String header = new String(response, 0, headerEnd, StandardCharsets.ISO_8859_1);
            
            // 查找Content-Type
            String[] lines = header.split("\r\n");
            for (String line : lines) {
                line = line.trim();
                if (line.toLowerCase().startsWith("content-type:")) {
                    return line.substring("content-type:".length()).trim();
                }
            }
            
        } catch (Exception e) {
            // 忽略解析异常
        }
        
        return null;
    }
    
    /**
     * 获取公式单元格的值
     */
    private static String getCellValueAsString(CellType cellType) {
        switch (cellType) {
            case NUMERIC:
                return "数值结果";
            case STRING:
                return "文本结果";
            case BOOLEAN:
                return "布尔结果";
            case ERROR:
                return "错误结果";
            default:
                return "";
        }
    }
}