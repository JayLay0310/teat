package com.bistu.tools.service;

import org.springframework.web.multipart.MultipartFile;
import java.util.List;
import java.util.Map;

/**
 * 证书分析服务接口
 */
public interface CertificateAnalysisService {

    /**
     * 分析证书文件
     */
    Map<String, Object> analyzeCertificate(MultipartFile file) throws Exception;

    /**
     * 分析文本形式的证书（Base64/PEM/Hex）
     */
    Map<String, Object> analyzeTextCertificate(String certContent, String format) throws Exception;

    /**
     * 验证证书链
     */
    Map<String, Object> validateCertificateChain(List<MultipartFile> files) throws Exception;

    /**
     * 解析ASN.1结构
     */
    Map<String, Object> parseAsn1Structure(MultipartFile file) throws Exception;
}