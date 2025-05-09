package com.bistu.tools.controller;

import com.bistu.tools.service.RandomnessTestService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/randomness")
public class RandomnessTestController {

    @Autowired
    private RandomnessTestService randomnessTestService;

    /**
     * 通过文本输入进行随机性检测
     * @param inputText 输入的比特流文本（0和1组成）
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    @PostMapping("/test-by-text")
    public ResponseEntity<Map<String, Object>> testRandomnessByText(
            @RequestParam("inputText") String inputText,
            @RequestParam(value = "testTypes", defaultValue = "all") String testTypes) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomness(inputText, testTypes);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "测试失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 通过十六进制文本进行随机性检测
     * @param hexText 十六进制文本
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    @PostMapping("/test-by-hex")
    public ResponseEntity<Map<String, Object>> testRandomnessByHex(
            @RequestParam("hexText") String hexText,
            @RequestParam(value = "testTypes", defaultValue = "all") String testTypes) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomnessByHex(hexText, testTypes);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "测试失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 通过Base64文本进行随机性检测
     * @param base64Text Base64编码的文本
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    @PostMapping("/test-by-base64")
    public ResponseEntity<Map<String, Object>> testRandomnessByBase64(
            @RequestParam("base64Text") String base64Text,
            @RequestParam(value = "testTypes", defaultValue = "all") String testTypes) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomnessByBase64(base64Text, testTypes);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "测试失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 通过文件进行随机性检测
     * @param file 上传的二进制文件
     * @param testTypes 要执行的测试类型，用逗号分隔
     * @return 测试结果
     */
    @PostMapping("/test-by-file")
    public ResponseEntity<Map<String, Object>> testRandomnessByFile(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "testTypes", defaultValue = "all") String testTypes) {
        try {
            Map<String, Object> results = randomnessTestService.testRandomnessByFile(file, testTypes);
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "测试失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    /**
     * 获取测试结果详情
     * @param testId 测试ID
     * @return 详细测试结果
     */
    @GetMapping("/results/{testId}")
    public ResponseEntity<Map<String, Object>> getTestResults(@PathVariable String testId) {
        try {
            Map<String, Object> results = randomnessTestService.getTestResults(testId);
            if (results == null) {
                Map<String, Object> error = new HashMap<String, Object>();
                error.put("error", "找不到测试结果");
                return ResponseEntity.notFound().build();
            }
            return ResponseEntity.ok(results);
        } catch (Exception e) {
            Map<String, Object> error = new HashMap<String, Object>();
            error.put("error", "获取结果失败: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
}