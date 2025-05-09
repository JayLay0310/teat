package com.bistu.tools.service.impl;

import com.bistu.tools.service.CertificateAnalysisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
public class CertificateAnalysisServiceImpl implements CertificateAnalysisService {

    private final Logger logger = LoggerFactory.getLogger(CertificateAnalysisServiceImpl.class);

    /**
     * 分析证书文件
     */
    @Override
    public Map<String, Object> analyzeCertificate(MultipartFile file) throws Exception {
        // 读取证书数据
        byte[] certificateData = file.getBytes();
        return analyzeCertificateData(certificateData, file.getOriginalFilename());
    }

    /**
     * 分析文本形式的证书
     */
    @Override
    public Map<String, Object> analyzeTextCertificate(String certContent, String format) throws Exception {
        byte[] certificateData;

        if ("BASE64".equalsIgnoreCase(format) || "PEM".equalsIgnoreCase(format)) {
            // 处理BASE64/PEM格式
            String normalized = certContent
                    .replaceAll("-----BEGIN CERTIFICATE-----", "")
                    .replaceAll("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            try {
                certificateData = Base64.getDecoder().decode(normalized);
            } catch (IllegalArgumentException e) {
                throw new Exception("无效的BASE64编码: " + e.getMessage());
            }
        } else if ("HEX".equalsIgnoreCase(format)) {
            // 处理十六进制格式
            certificateData = hexToBytes(certContent.replaceAll("\\s", ""));
        } else {
            throw new Exception("不支持的格式: " + format);
        }

        return analyzeCertificateData(certificateData, "certificate." + format.toLowerCase());
    }

    /**
     * 分析证书数据
     */
    private Map<String, Object> analyzeCertificateData(byte[] certificateData, String filename) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            // 解析证书
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            ByteArrayInputStream bais = new ByteArrayInputStream(certificateData);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);

            // 基本证书信息
            result.put("subject", cert.getSubjectX500Principal().getName());
            result.put("issuer", cert.getIssuerX500Principal().getName());
            result.put("serialNumber", cert.getSerialNumber().toString(16).toUpperCase());

            // 有效期
            Map<String, String> validity = new HashMap<String, String>();
            validity.put("notBefore", cert.getNotBefore().toString());
            validity.put("notAfter", cert.getNotAfter().toString());
            result.put("validity", validity);

            result.put("version", cert.getVersion());
            result.put("algorithm", cert.getSigAlgName());
            result.put("filename", filename);

            // 公钥信息
            result.put("publicKey", cert.getPublicKey().getAlgorithm());
            result.put("keyLength", getKeyLength(cert));

            // 扩展信息
            Map<String, Object> extensions = getExtensions(cert);
            if (!extensions.isEmpty()) {
                result.put("extensions", extensions);
            }

            // 指纹信息
            Map<String, String> fingerprints = getFingerprints(certificateData);
            result.put("fingerprints", fingerprints);

            // ASN.1结构
            result.put("asn1Structure", parseAsn1Structure(certificateData));

            return result;
        } catch (CertificateException e) {
            logger.error("证书解析错误", e);
            throw new Exception("无法解析证书: " + e.getMessage());
        }
    }

    /**
     * 验证证书链
     */
    @Override
    public Map<String, Object> validateCertificateChain(List<MultipartFile> files) throws Exception {
        Map<String, Object> result = new HashMap<String, Object>();
        List<Map<String, Object>> certificatesInfo = new ArrayList<Map<String, Object>>();

        try {
            // 解析所有证书
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certChain = new ArrayList<X509Certificate>();

            for (MultipartFile file : files) {
                ByteArrayInputStream bais = new ByteArrayInputStream(file.getBytes());
                X509Certificate cert = (X509Certificate) cf.generateCertificate(bais);
                certChain.add(cert);

                // 收集证书信息
                Map<String, Object> certInfo = new HashMap<String, Object>();
                certInfo.put("subject", cert.getSubjectX500Principal().getName());
                certInfo.put("issuer", cert.getIssuerX500Principal().getName());
                certInfo.put("serialNumber", cert.getSerialNumber().toString(16).toUpperCase());
                certInfo.put("filename", file.getOriginalFilename());

                certificatesInfo.add(certInfo);
            }

            // 排序证书链
            List<X509Certificate> orderedChain = orderCertificateChain(certChain);

            // 验证证书链
            boolean chainValid = validateChain(orderedChain);

            // 生成结果
            result.put("valid", chainValid);
            result.put("certificates", certificatesInfo);
            result.put("chainOrdered", formatOrderedChain(orderedChain));

            return result;
        } catch (Exception e) {
            logger.error("证书链验证错误", e);
            throw new Exception("验证证书链失败: " + e.getMessage());
        }
    }

    /**
     * 格式化排序后的证书链
     */
    private List<Map<String, String>> formatOrderedChain(List<X509Certificate> chain) {
        List<Map<String, String>> result = new ArrayList<Map<String, String>>();

        for (int i = 0; i < chain.size(); i++) {
            X509Certificate cert = chain.get(i);
            Map<String, String> certInfo = new HashMap<String, String>();

            certInfo.put("position", String.valueOf(i + 1));
            certInfo.put("subject", cert.getSubjectX500Principal().getName());
            certInfo.put("issuer", cert.getIssuerX500Principal().getName());

            String type;
            if (i == 0) {
                type = "终端实体证书";
            } else if (i == chain.size() - 1) {
                type = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal()) ?
                        "根CA证书" : "最高级中间CA证书";
            } else {
                type = "中间CA证书";
            }
            certInfo.put("type", type);

            result.add(certInfo);
        }

        return result;
    }

    /**
     * 解析ASN.1结构
     */
    @Override
    public Map<String, Object> parseAsn1Structure(MultipartFile file) throws Exception {
        byte[] data = file.getBytes();
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            // 解析ASN.1结构
            ASN1ParserSimple parser = new ASN1ParserSimple();
            List<Map<String, Object>> asn1Structure = parser.parseData(data);

            result.put("filename", file.getOriginalFilename());
            result.put("fileSize", data.length);
            result.put("asn1Structure", asn1Structure);

            return result;
        } catch (Exception e) {
            logger.error("ASN.1解析错误", e);
            throw new Exception("ASN.1解析失败: " + e.getMessage());
        }
    }

    /**
     * 解析证书数据的ASN.1结构
     */
    private List<Map<String, Object>> parseAsn1Structure(byte[] data) {
        try {
            ASN1ParserSimple parser = new ASN1ParserSimple();
            return parser.parseData(data);
        } catch (Exception e) {
            logger.warn("解析ASN.1结构失败", e);
            List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
            Map<String, Object> errorInfo = new HashMap<String, Object>();
            errorInfo.put("error", "解析ASN.1结构失败: " + e.getMessage());
            result.add(errorInfo);
            return result;
        }
    }

    /**
     * 获取密钥长度
     */
    private int getKeyLength(X509Certificate cert) {
        try {
            if ("RSA".equals(cert.getPublicKey().getAlgorithm())) {
                java.security.interfaces.RSAPublicKey rsaKey =
                        (java.security.interfaces.RSAPublicKey) cert.getPublicKey();
                return rsaKey.getModulus().bitLength();
            } else if ("DSA".equals(cert.getPublicKey().getAlgorithm())) {
                java.security.interfaces.DSAPublicKey dsaKey =
                        (java.security.interfaces.DSAPublicKey) cert.getPublicKey();
                return dsaKey.getParams().getP().bitLength();
            } else if ("EC".equals(cert.getPublicKey().getAlgorithm())) {
                java.security.interfaces.ECPublicKey ecKey =
                        (java.security.interfaces.ECPublicKey) cert.getPublicKey();
                return ecKey.getParams().getCurve().getField().getFieldSize();
            }
        } catch (Exception e) {
            logger.warn("获取密钥长度失败", e);
        }
        return 0;
    }

    /**
     * 获取证书扩展信息
     */
    private Map<String, Object> getExtensions(X509Certificate cert) {
        Map<String, Object> extensions = new HashMap<String, Object>();

        try {
            // 基本约束
            int pathLen = cert.getBasicConstraints();
            if (pathLen >= -1) {
                Map<String, Object> basicConstraints = new HashMap<String, Object>();
                basicConstraints.put("ca", pathLen != -1);
                basicConstraints.put("pathLength", pathLen == -1 ? "Not a CA" : pathLen);
                extensions.put("basicConstraints", basicConstraints);
            }

            // 密钥用法
            boolean[] keyUsage = cert.getKeyUsage();
            if (keyUsage != null) {
                List<String> usages = new ArrayList<String>();
                String[] keyUsageNames = {
                        "digitalSignature", "nonRepudiation", "keyEncipherment",
                        "dataEncipherment", "keyAgreement", "keyCertSign",
                        "cRLSign", "encipherOnly", "decipherOnly"
                };

                for (int i = 0; i < keyUsage.length && i < keyUsageNames.length; i++) {
                    if (keyUsage[i]) {
                        usages.add(keyUsageNames[i]);
                    }
                }
                extensions.put("keyUsage", usages);
            }

            // 扩展密钥用法
            List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage != null) {
                extensions.put("extendedKeyUsage", extendedKeyUsage);
            }

            // 使用者可选名称
            Collection<List<?>> subjectAltNames = cert.getSubjectAlternativeNames();
            if (subjectAltNames != null) {
                List<String> sans = new ArrayList<String>();
                for (List<?> san : subjectAltNames) {
                    if (san.size() >= 2) {
                        Integer type = (Integer) san.get(0);
                        String value = san.get(1).toString();
                        String typeStr;
                        switch (type) {
                            case 0: typeStr = "otherName"; break;
                            case 1: typeStr = "rfc822Name"; break;
                            case 2: typeStr = "dNSName"; break;
                            case 6: typeStr = "URI"; break;
                            case 7: typeStr = "iPAddress"; break;
                            default: typeStr = "type-" + type; break;
                        }
                        sans.add(typeStr + ": " + value);
                    }
                }
                extensions.put("subjectAltName", sans);
            }
        } catch (Exception e) {
            logger.warn("获取证书扩展信息失败", e);
        }

        return extensions;
    }

    /**
     * 获取证书指纹
     */
    private Map<String, String> getFingerprints(byte[] certificateData) {
        Map<String, String> fingerprints = new HashMap<String, String>();

        try {
            MessageDigest md5Digest = MessageDigest.getInstance("MD5");
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            MessageDigest sha256Digest = MessageDigest.getInstance("SHA-256");

            fingerprints.put("MD5", bytesToHexColons(md5Digest.digest(certificateData)));
            fingerprints.put("SHA1", bytesToHexColons(sha1Digest.digest(certificateData)));
            fingerprints.put("SHA256", bytesToHexColons(sha256Digest.digest(certificateData)));
        } catch (Exception e) {
            logger.warn("计算证书指纹失败", e);
            fingerprints.put("error", "计算指纹失败: " + e.getMessage());
        }

        return fingerprints;
    }

    /**
     * 字节数组转带冒号的十六进制字符串
     */
    private String bytesToHexColons(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i < bytes.length - 1) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    /**
     * 字节数组转十六进制字符串
     */
    private String bytesToHex(byte[] bytes, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }

    /**
     * 十六进制字符串转字节数组
     */
    private byte[] hexToBytes(String hex) throws Exception {
        if (hex.length() % 2 != 0) {
            throw new Exception("十六进制字符串长度必须为偶数");
        }

        byte[] result = new byte[hex.length() / 2];

        for (int i = 0; i < hex.length(); i += 2) {
            try {
                result[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
            } catch (NumberFormatException e) {
                throw new Exception("无效的十六进制字符串");
            }
        }

        return result;
    }

    /**
     * 对证书链排序
     */
    private List<X509Certificate> orderCertificateChain(List<X509Certificate> certs) {
        List<X509Certificate> orderedChain = new ArrayList<X509Certificate>();
        Map<String, X509Certificate> certMap = new HashMap<String, X509Certificate>();

        // 创建从主题到证书的映射
        for (X509Certificate cert : certs) {
            String subject = cert.getSubjectX500Principal().getName();
            certMap.put(subject, cert);
        }

        // 找到可能的终端实体证书
        X509Certificate currentCert = findEndEntityCert(certs);
        orderedChain.add(currentCert);

        // 按照从终端实体到根CA的顺序构建链
        for (int i = 0; i < 10 && currentCert != null; i++) {  // 限制链长，避免循环
            String issuerName = currentCert.getIssuerX500Principal().getName();
            X509Certificate issuer = certMap.get(issuerName);

            // 找到了颁发者证书，但不是自签名证书
            if (issuer != null && !issuer.equals(currentCert)) {
                orderedChain.add(issuer);
                currentCert = issuer;
            } else {
                break;
            }
        }

        return orderedChain;
    }

    /**
     * 查找可能的终端实体证书
     */
    private X509Certificate findEndEntityCert(List<X509Certificate> certs) {
        for (X509Certificate cert : certs) {
            // 检查基本约束
            int basicConstraints = cert.getBasicConstraints();
            if (basicConstraints == -1) {  // 不是CA
                return cert;
            }
        }

        // 如果所有证书都是CA，返回第一个
        return certs.isEmpty() ? null : certs.get(0);
    }

    /**
     * 验证证书链
     */
    private boolean validateChain(List<X509Certificate> chain) {
        if (chain.isEmpty()) {
            return false;
        }

        try {
            // 创建证书路径
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            CertPath certPath = cf.generateCertPath(chain);

            // 创建信任锚
            X509Certificate rootCert = chain.get(chain.size() - 1);
            TrustAnchor trustAnchor = new TrustAnchor(rootCert, null);
            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            trustAnchors.add(trustAnchor);

            // 创建验证参数
            PKIXParameters params = new PKIXParameters(trustAnchors);
            params.setRevocationEnabled(false);  // 禁用吊销检查

            // 验证证书路径
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            validator.validate(certPath, params);

            return true;
        } catch (Exception e) {
            logger.warn("证书链验证失败", e);
            return false;
        }
    }

    /**
     * ASN.1解析器（简化版）
     */
    private class ASN1ParserSimple {
        // ASN.1标签常量
        private final int TAG_SEQUENCE = 0x30;
        private final int TAG_SET = 0x31;
        private final int TAG_INTEGER = 0x02;
        private final int TAG_OBJECT_IDENTIFIER = 0x06;
        private final int TAG_OCTET_STRING = 0x04;
        private final int TAG_BIT_STRING = 0x03;
        private final int TAG_PRINTABLE_STRING = 0x13;
        private final int TAG_UTC_TIME = 0x17;
        private final int TAG_GENERALIZED_TIME = 0x18;

        /**
         * 解析ASN.1数据
         */
        public List<Map<String, Object>> parseData(byte[] data) throws IOException {
            List<Map<String, Object>> result = new ArrayList<Map<String, Object>>();
            ByteArrayInputStream inputStream = null;

            try {
                inputStream = new ByteArrayInputStream(data);
                Map<String, Object> overview = new HashMap<String, Object>();
                overview.put("type", "ASN.1 Overview");
                overview.put("totalLength", data.length);
                overview.put("hexPreview", bytesToHex(data, 0, Math.min(20, data.length)) +
                        (data.length > 20 ? "..." : ""));
                result.add(overview);

                // 简化版解析，只解析顶层结构
                while (inputStream.available() > 0) {
                    Map<String, Object> item = parseNextTag(inputStream, 0);
                    if (item != null) {
                        result.add(item);
                    }
                }
            } finally {
                if (inputStream != null) {
                    inputStream.close();
                }
            }

            return result;
        }

        /**
         * 解析下一个ASN.1标签
         */
        private Map<String, Object> parseNextTag(InputStream is, int depth) throws IOException {
            Map<String, Object> result = new HashMap<String, Object>();

            // 读取标签
            int tag = is.read();
            if (tag == -1) {
                return null;
            }

            // 解析标签类别
            int tagClass = tag & 0xC0;
            boolean constructed = (tag & 0x20) != 0;
            int tagNumber = tag & 0x1F;

            // 读取长度
            int length = readLength(is);

            // 返回标签基本信息
            String tagType = getTagType(tagNumber);

            result.put("tag", "0x" + Integer.toHexString(tag));
            result.put("type", tagType);
            result.put("length", length);
            result.put("constructed", constructed);

            // 读取内容
            byte[] content = new byte[length];
            int bytesRead = is.read(content);
            if (bytesRead != length) {
                throw new IOException("读取字节数不足: 期望 " + length + ", 实际 " + bytesRead);
            }

            // 添加内容预览
            if (length > 0) {
                String contentPreview = bytesToHex(content, 0, Math.min(20, content.length));
                if (content.length > 20) {
                    contentPreview += "...";
                }
                result.put("contentPreview", contentPreview);
            }

            return result;
        }

        /**
         * 读取ASN.1长度
         */
        private int readLength(InputStream is) throws IOException {
            int length = is.read();
            if (length == -1) {
                throw new IOException("意外的流结束");
            }

            if (length < 128) {
                return length;
            }

            // 长形式长度
            int bytesCount = length & 0x7F;
            length = 0;

            for (int i = 0; i < bytesCount; i++) {
                int nextByte = is.read();
                if (nextByte == -1) {
                    throw new IOException("意外的流结束");
                }
                length = (length << 8) | nextByte;
            }

            return length;
        }

        /**
         * 获取标签类型名称
         */
        private String getTagType(int tagNumber) {
            switch (tagNumber) {
                case 0x02: return "INTEGER";
                case 0x03: return "BIT STRING";
                case 0x04: return "OCTET STRING";
                case 0x05: return "NULL";
                case 0x06: return "OBJECT IDENTIFIER";
                case 0x13: return "PRINTABLE STRING";
                case 0x17: return "UTC TIME";
                case 0x18: return "GENERALIZED TIME";
                case 0x30: return "SEQUENCE";
                case 0x31: return "SET";
                default: return "TAG:0x" + Integer.toHexString(tagNumber);
            }
        }
    }
}