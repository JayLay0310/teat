package com.bistu.tools.service;

import org.springframework.web.multipart.MultipartFile;
import java.util.Map;

/**
 * 随机性检测服务接口
 * 实现《GM/T 0005-2021 随机性检测规范》中的检测方法
 */
public interface RandomnessTestService {

    /**
     * 对比特流文本进行随机性检测
     * @param inputText 输入文本（0和1组成的字符串）
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    Map<String, Object> testRandomness(String inputText, String testTypes) throws Exception;

    /**
     * 对十六进制文本进行随机性检测
     * @param hexText 十六进制文本
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    Map<String, Object> testRandomnessByHex(String hexText, String testTypes) throws Exception;

    /**
     * 对Base64编码文本进行随机性检测
     * @param base64Text Base64编码文本
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    Map<String, Object> testRandomnessByBase64(String base64Text, String testTypes) throws Exception;

    /**
     * 对上传的文件进行随机性检测
     * @param file 上传的文件
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    Map<String, Object> testRandomnessByFile(MultipartFile file, String testTypes) throws Exception;

    /**
     * 获取指定测试ID的详细结果
     * @param testId 测试ID
     * @return 测试结果
     */
    Map<String, Object> getTestResults(String testId) throws Exception;
}
