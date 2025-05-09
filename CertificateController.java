package com.bistu.tools.controller;

import com.bistu.tools.service.CertificateAnalysisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/certificate")
public class CertificateController {

    @Autowired
    private CertificateAnalysisService certificateAnalysisService;

    /**
     * 分析证书
     */
    @PostMapping("/analyze")
    public ResponseEntity<Map<String, Object>> analyzeCertificate(
            @RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = certificateAnalysisService.analyzeCertificate(file);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("code", 400);
            error.put("message", "证书分析失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 验证证书链
     */
    @PostMapping("/validate-chain")
    public ResponseEntity<Map<String, Object>> validateCertificateChain(
            @RequestParam("files") List<MultipartFile> files) {
        try {
            Map<String, Object> result = certificateAnalysisService.validateCertificateChain(files);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("code", 400);
            error.put("message", "证书链验证失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 解析ASN.1结构
     */
    @PostMapping("/parse-asn1")
    public ResponseEntity<Map<String, Object>> parseAsn1Structure(
            @RequestParam("file") MultipartFile file) {
        try {
            Map<String, Object> result = certificateAnalysisService.parseAsn1Structure(file);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("code", 400);
            error.put("message", "ASN.1解析失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 直接分析Base64、PEM或Hex格式的证书
     */
    @PostMapping("/analyze-text")
    public ResponseEntity<Map<String, Object>> analyzeTextCertificate(
            @RequestParam("certContent") String certContent,
            @RequestParam("format") String format) {
        try {
            Map<String, Object> result = certificateAnalysisService.analyzeTextCertificate(certContent, format);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("code", 400);
            error.put("message", "证书分析失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}