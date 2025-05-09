package com.bistu.tools.service;

import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Map;

/**
 * 统一密码学验证服务接口
 * 提供对哈希算法、对称加密、非对称加密等多种密码算法的验证功能
 */
public interface CryptoVerificationService {

    /**
     * 获取支持的算法信息
     * @return 支持的算法、模式、填充方式等信息
     */
    Map<String, Object> getSupportedAlgorithms();

    /**
     * 生成密钥
     * @param algorithm 算法类型(如RSA、SM2、AES、DES等)
     * @param params 密钥生成参数(如密钥长度、曲线类型等)
     * @return 密钥信息(对称算法返回密钥，非对称算法返回公私钥对)
     */
    Map<String, Object> generateKey(String algorithm, Map<String, Object> params);

    /**
     * 验证哈希值
     * @param algorithm 哈希算法(如MD5、SHA-256、SM3等)
     * @param input 输入数据
     * @param inputFormat 输入格式(TEXT/HEX/BASE64)
     * @param hmacKey HMAC密钥(如果需要)
     * @param salt 盐值(如果需要)
     * @param saltPosition 盐值位置(PREFIX/SUFFIX/BOTH/CUSTOM)
     * @param customPosition 自定义盐值位置(当saltPosition为CUSTOM时使用)
     * @param iterations 迭代次数(默认为1)
     * @param expectedHash 预期哈希值
     * @param hashFormat 哈希值格式(HEX/BASE64)
     * @return 验证结果
     */
    Map<String, Object> verifyHash(
            String algorithm,
            String input,
            String inputFormat,
            String hmacKey,
            String salt,
            String saltPosition,
            Integer customPosition,
            Integer iterations,
            String expectedHash,
            String hashFormat);

    /**
     * 验证对称加密算法
     * @param algorithm 算法类型(如AES、DES、3DES、SM4、RC4、ChaCha20、ZUC等)
     * @param operation 操作(ENCRYPT/DECRYPT)
     * @param input 输入数据
     * @param inputFormat 输入格式(TEXT/HEX/BASE64)
     * @param key 密钥(HEX格式)
     * @param iv 初始向量(HEX格式，如需要)
     * @param mode 加密模式(如ECB、CBC、CTR等，如需要)
     * @param padding 填充方式(如NoPadding、PKCS5Padding等，如需要)
     * @param expectedOutput 预期输出(用于验证，可选)
     * @param expectedOutputFormat 预期输出格式(HEX/BASE64/TEXT)
     * @return 验证结果
     */
    Map<String, Object> verifySymmetricCipher(
            String algorithm,
            String operation,
            String input,
            String inputFormat,
            String key,
            String iv,
            String mode,
            String padding,
            String expectedOutput,
            String expectedOutputFormat);

    /**
     * 验证非对称加密算法
     * @param algorithm 算法类型(如RSA、SM2、SM9)
     * @param operation 操作(ENCRYPT/DECRYPT)
     * @param input 输入数据
     * @param inputFormat 输入格式(TEXT/HEX/BASE64)
     * @param publicKey 公钥(Base64格式，加密时使用)
     * @param privateKey 私钥(Base64格式，解密时使用)
     * @param padding 填充方式(如需要)
     * @param params 其他参数(SM9身份等)
     * @param expectedOutput 预期输出(用于验证，可选)
     * @param expectedOutputFormat 预期输出格式(HEX/BASE64/TEXT)
     * @return 验证结果
     */
    Map<String, Object> verifyAsymmetricCipher(
            String algorithm,
            String operation,
            String input,
            String inputFormat,
            String publicKey,
            String privateKey,
            String padding,
            Map<String, Object> params,
            String expectedOutput,
            String expectedOutputFormat);

    /**
     * 验证数字签名
     * @param algorithm 算法类型(如RSA、ECDSA、SM2、SM9)
     * @param operation 操作(SIGN/VERIFY)
     * @param input 输入数据
     * @param inputFormat 输入格式(TEXT/HEX/BASE64)
     * @param publicKey 公钥(Base64格式，验签时使用)
     * @param privateKey 私钥(Base64格式，签名时使用)
     * @param signAlgorithm 签名算法(如SHA256withRSA、SM3withSM2等)
     * @param signature 签名值(验签时使用)
     * @param signatureFormat 签名格式(HEX/BASE64)
     * @param params 其他参数
     * @return 验证结果
     */
    Map<String, Object> verifySignature(
            String algorithm,
            String operation,
            String input,
            String inputFormat,
            String publicKey,
            String privateKey,
            String signAlgorithm,
            String signature,
            String signatureFormat,
            Map<String, Object> params);

    /**
     * 验证文件操作(哈希/加解密/签名验签)
     * @param operation 操作类型(HASH/ENCRYPT/DECRYPT/SIGN/VERIFY)
     * @param algorithm 算法类型
     * @param file 文件
     * @param fileFormat 文件格式(BINARY/HEX/BASE64)
     * @param params 参数Map(包含密钥、IV、填充方式等)
     * @return 验证结果
     * @throws IOException 文件读取异常
     */
    Map<String, Object> verifyFile(
            String operation,
            String algorithm,
            MultipartFile file,
            String fileFormat,
            Map<String, Object> params) throws IOException;
}