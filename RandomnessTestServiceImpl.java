package com.bistu.tools.service.impl;

import com.bistu.tools.service.RandomnessTestService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RandomnessTestServiceImpl implements RandomnessTestService {

    private static final Logger logger = LoggerFactory.getLogger(RandomnessTestServiceImpl.class);
    private static final Map<String, Map<String, Object>> testResultsCache = new ConcurrentHashMap<String, Map<String, Object>>();

    // 最小推荐样本长度
    private static final int MIN_RECOMMENDED_LENGTH = 1000000; // 1,000,000 bits

    // 统计检验的显著性水平（α值）
    private static final double SIGNIFICANCE_LEVEL = 0.01; // 1%，即99%置信水平

    // 密钥长度
    private static final int KEY_LENGTH = 128; // 128位

    // 最大游程长度，超过此长度的游程合并为一类
    private static final int MAX_RUN_LENGTH = 34;

    @Override
    public Map<String, Object> testRandomness(String inputText, String testTypes) throws Exception {
        // 验证输入
        if (inputText == null || inputText.isEmpty()) {
            throw new IllegalArgumentException("输入数据不能为空");
        }

        // 转换成比特序列
        boolean[] bits = convertToBitArray(inputText);

        // 检查数据长度是否符合推荐
        if (bits.length < MIN_RECOMMENDED_LENGTH) {
            logger.warn("输入数据长度({})小于推荐长度({})", bits.length, MIN_RECOMMENDED_LENGTH);
        }

        return performTests(bits, testTypes);
    }

    @Override
    public Map<String, Object> testRandomnessByHex(String hexText, String testTypes) throws Exception {
        // 验证输入
        if (hexText == null || hexText.isEmpty()) {
            throw new IllegalArgumentException("十六进制输入不能为空");
        }

        hexText = hexText.replaceAll("\\s", "");

        // 将十六进制转换为位数组
        boolean[] bits = hexToBitArray(hexText);

        // 检查数据长度是否符合推荐
        if (bits.length < MIN_RECOMMENDED_LENGTH) {
            logger.warn("输入数据长度({})小于推荐长度({})", bits.length, MIN_RECOMMENDED_LENGTH);
        }

        return performTests(bits, testTypes);
    }

    @Override
    public Map<String, Object> testRandomnessByBase64(String base64Text, String testTypes) throws Exception {
        // 验证输入
        if (base64Text == null || base64Text.isEmpty()) {
            throw new IllegalArgumentException("Base64输入不能为空");
        }

        // 将Base64转换为字节数组，然后转换为位数组
        byte[] bytes;
        try {
            bytes = Base64.getDecoder().decode(base64Text);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("无效的Base64编码: " + e.getMessage());
        }

        boolean[] bits = bytesToBitArray(bytes);

        // 检查数据长度是否符合推荐
        if (bits.length < MIN_RECOMMENDED_LENGTH) {
            logger.warn("输入数据长度({})小于推荐长度({})", bits.length, MIN_RECOMMENDED_LENGTH);
        }

        return performTests(bits, testTypes);
    }

    @Override
    public Map<String, Object> testRandomnessByFile(MultipartFile file, String testTypes) throws Exception {
        // 验证输入
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("文件不能为空");
        }

        // 读取文件内容
        byte[] fileBytes = file.getBytes();
        boolean[] bits = bytesToBitArray(fileBytes);

        // 检查数据长度是否符合推荐
        if (bits.length < MIN_RECOMMENDED_LENGTH) {
            logger.warn("输入数据长度({})小于推荐长度({})", bits.length, MIN_RECOMMENDED_LENGTH);
        }

        // 执行测试
        Map<String, Object> results = performTests(bits, testTypes);

        // 添加文件信息
        results.put("fileName", file.getOriginalFilename());
        results.put("fileSize", file.getSize());

        return results;
    }

    @Override
    public Map<String, Object> getTestResults(String testId) throws Exception {
        return testResultsCache.get(testId);
    }

    /**
     * 执行随机性检测测试
     */
    private Map<String, Object> performTests(boolean[] bits, String testTypes) throws Exception {
        Map<String, Object> results = new HashMap<String, Object>();

        // 生成唯一测试ID
        String testId = UUID.randomUUID().toString();
        results.put("testId", testId);
        results.put("dataLength", bits.length);
        results.put("timestamp", new Date().toString());

        // 确定要执行的测试类型
        List<String> testsToRun = parseTestTypes(testTypes);
        results.put("testsExecuted", testsToRun);

        // 运行所有请求的测试
        Map<String, Object> testResults = new HashMap<String, Object>();

        for (String test : testsToRun) {
            Map<String, Object> testResult;

            switch (test) {
                case "poker":
                    testResult = performPokerTest(bits);
                    break;
                case "runsTotal":
                    testResult = performRunsTotalTest(bits);
                    break;
                case "runsDist":
                    testResult = performRunsDistributionTest(bits);
                    break;
                case "overlapping":
                    testResult = performOverlappingTest(bits);
                    break;
                case "autocorrelation":
                    testResult = performAutocorrelationTest(bits);
                    break;
                case "frequency":
                    testResult = performFrequencyTest(bits);
                    break;
                default:
                    testResult = new HashMap<String, Object>();
                    testResult.put("error", "未知测试类型: " + test);
                    break;
            }

            testResults.put(test, testResult);
        }

        results.put("results", testResults);

        // 评估总体结论
        boolean allPassed = true;
        for (String test : testsToRun) {
            Map<String, Object> testResult = (Map<String, Object>) testResults.get(test);
            Boolean passed = (Boolean) testResult.get("passed");
            if (passed != null && !passed) {
                allPassed = false;
                break;
            }
        }

        results.put("overallPassed", allPassed);

        // 缓存结果
        testResultsCache.put(testId, results);

        return results;
    }

    /**
     * 解析测试类型参数
     */
    private List<String> parseTestTypes(String testTypes) {
        if (testTypes == null || testTypes.isEmpty() || "all".equalsIgnoreCase(testTypes)) {
            // 运行所有测试
            return Arrays.asList("poker", "runsTotal", "runsDist",
                    "overlapping", "autocorrelation", "frequency");
        }

        // 解析逗号分隔的测试类型
        String[] types = testTypes.split(",");
        List<String> result = new ArrayList<String>();

        for (String type : types) {
            String trimmed = type.trim();
            if (!trimmed.isEmpty()) {
                result.add(trimmed);
            }
        }

        return result;
    }

    // ===== 数据转换方法 =====

    /**
     * 将字符串转换为位数组
     */
    private boolean[] convertToBitArray(String input) throws IllegalArgumentException {
        // 移除所有空格
        input = input.replaceAll("\\s", "");

        boolean[] bits = new boolean[input.length()];

        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);

            if (c == '0') {
                bits[i] = false;
            } else if (c == '1') {
                bits[i] = true;
            } else {
                throw new IllegalArgumentException("输入应仅包含0和1，遇到: " + c);
            }
        }

        return bits;
    }

    /**
     * 将十六进制字符串转换为位数组
     */
    private boolean[] hexToBitArray(String hex) throws IllegalArgumentException {
        // 验证十六进制格式
        if (!hex.matches("[0-9A-Fa-f]+")) {
            throw new IllegalArgumentException("无效的十六进制字符串");
        }

        boolean[] bits = new boolean[hex.length() * 4];

        for (int i = 0; i < hex.length(); i++) {
            int value = Character.digit(hex.charAt(i), 16);

            // 转换为4位二进制
            for (int j = 0; j < 4; j++) {
                bits[i * 4 + j] = ((value >> (3 - j)) & 1) == 1;
            }
        }

        return bits;
    }

    /**
     * 将字节数组转换为位数组
     */
    private boolean[] bytesToBitArray(byte[] bytes) {
        boolean[] bits = new boolean[bytes.length * 8];

        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                bits[i * 8 + j] = ((bytes[i] >> (7 - j)) & 1) == 1;
            }
        }

        return bits;
    }

    /**
     * 将字节数组转换为十六进制字符串
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    // ===== 实用统计功能，替代Apache Commons Math3库 =====

    /**
     * 计算标准正态分布的累积分布函数(CDF)值
     * @param z 标准正态分布的z值
     * @return 累积概率
     */
    private double normalCDF(double z) {
        // 使用误差函数近似标准正态分布的CDF
        double t = 1.0 / (1.0 + 0.2316419 * Math.abs(z));
        double d = 0.3989423 * Math.exp(-z * z / 2.0);
        double p = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));

        if (z > 0) {
            return 1.0 - p;
        } else {
            return p;
        }
    }

    /**
     * 计算卡方分布的累积分布函数(CDF)值
     * @param chi2 卡方值
     * @param df 自由度
     * @return 累积概率
     */
    private double chiSquareCDF(double chi2, int df) {
        if (chi2 <= 0.0) {
            return 0.0;
        }

        // 对于低自由度，使用精确计算
        if (df <= 2) {
            if (df == 1) {
                // 自由度为1的卡方分布特例
                return 2.0 * normalCDF(Math.sqrt(chi2)) - 1.0;
            } else { // df == 2
                // 自由度为2的卡方分布特例
                return 1.0 - Math.exp(-chi2 / 2.0);
            }
        }

        // 对于大自由度，使用Wilson–Hilferty变换的近似值
        double z = Math.pow(chi2 / df, 1.0/3.0) - (1 - 2.0/(9*df)) / Math.sqrt(2.0/(9*df));
        return normalCDF(z);
    }

    /**
     * 计算卡方分布的反累积分布函数(逆CDF)
     * @param p 概率值(0,1)
     * @param df 自由度
     * @return 卡方临界值
     */
    private double chiSquareInvCDF(double p, int df) {
        // 使用二分法近似求逆CDF
        double precision = 0.0001;
        double min = 0.0;
        double max = 100.0 * df; // 保守估计上限

        while (max - min > precision) {
            double mid = (min + max) / 2.0;
            double cdf = chiSquareCDF(mid, df);

            if (cdf < p) {
                min = mid;
            } else {
                max = mid;
            }
        }

        return (min + max) / 2.0;
    }

    /**
     * 计算p值(双侧检验)
     * @param z 标准正态分布的z值
     * @return p值
     */
    private double calculatePValueFromZ(double z) {
        return 2.0 * (1.0 - normalCDF(Math.abs(z)));
    }

    // ===== 随机性测试实现 =====

    /**
     * 扑克检测（块频率检测）
     * 根据《GM/T 0005-2021》规范实现
     */
    private Map<String, Object> performPokerTest(boolean[] bits) {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            // 计算扑克检测的m值（推荐为序列长度的对数）
            int n = bits.length;
            int m = (int) Math.max(Math.min(Math.log(n) / Math.log(2), 16), 4);

            // m应至少为4，至多为16
            m = Math.min(Math.max(m, 4), 16);

            int k = n / m; // 总区块数

            if (k < 5) {
                throw new IllegalArgumentException("序列太短，无法进行扑克测试, 至少需要" + (5 * m) + "比特");
            }

            // 统计每种m比特模式出现的次数
            int maxPattern = 1 << m; // 2^m
            int[] counts = new int[maxPattern];

            for (int i = 0; i < k; i++) {
                int pattern = 0;
                for (int j = 0; j < m; j++) {
                    int bitIndex = i * m + j;
                    if (bitIndex < bits.length && bits[bitIndex]) {
                        pattern |= (1 << (m - 1 - j));
                    }
                }
                counts[pattern]++;
            }

            // 计算统计量
            double expectedCount = (double) k / maxPattern;
            double sum = 0;

            for (int count : counts) {
                sum += Math.pow(count - expectedCount, 2);
            }

            double X = (maxPattern / (double) k) * sum;

            // 计算自由度和p-值
            int degreesOfFreedom = maxPattern - 1;
            double pValue = 1.0 - chiSquareCDF(X, degreesOfFreedom);

            // 判断是否通过测试
            boolean passed = pValue >= SIGNIFICANCE_LEVEL;

            // 构建结果
            result.put("testName", "扑克检测");
            result.put("m", m);
            result.put("blockCount", k);
            result.put("possiblePatterns", maxPattern);
            result.put("statistic", X);
            result.put("degreesOfFreedom", degreesOfFreedom);
            result.put("pValue", pValue);
            result.put("threshold", SIGNIFICANCE_LEVEL);
            result.put("passed", passed);
            result.put("conclusion", passed ?
                    "通过：序列具有良好的块频率分布特性" :
                    "失败：序列的块频率分布不满足随机性要求");

            // 添加分布详情（可选）
            if (m <= 8) { // 对于较小的m值，添加分布详情
                Map<String, Integer> patternDistribution = new HashMap<String, Integer>();
                for (int i = 0; i < maxPattern; i++) {
                    if (counts[i] > 0) {
                        patternDistribution.put(Integer.toBinaryString(i), counts[i]);
                    }
                }
                result.put("patternDistribution", patternDistribution);
            }

        } catch (Exception e) {
            result.put("error", "扑克检测失败: " + e.getMessage());
            result.put("passed", false);
        }

        return result;
    }

    /**
     * 游程总数检测
     * 根据《GM/T 0005-2021》规范实现
     */
    private Map<String, Object> performRunsTotalTest(boolean[] bits) {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            int n = bits.length;

            if (n < 100) {
                throw new IllegalArgumentException("序列太短，无法进行游程总数检测，至少需要100比特");
            }

            // 计算0和1的数量
            int n0 = 0;
            int n1 = 0;
            for (boolean bit : bits) {
                if (bit) {
                    n1++;
                } else {
                    n0++;
                }
            }

            // 检查序列的0和1比例是否满足前置条件
            double proportion1 = (double) n1 / n;

            // 依据GM/T 0005-2021，0和1的比例应在合理范围内
            if (Math.abs(proportion1 - 0.5) > 0.1) {
                result.put("testName", "游程总数检测");
                result.put("warning", "序列中0和1的比例不平衡，可能影响测试结果");
                result.put("proportion1", proportion1);
                result.put("passed", false);
                result.put("conclusion", "失败：前置条件不满足，0和1的比例不平衡");
                return result;
            }

            // 计算游程总数
            int r = 1; // 至少有一个游程
            for (int i = 1; i < n; i++) {
                if (bits[i] != bits[i - 1]) {
                    r++;
                }
            }

            // 计算期望值和方差
            double expectedR = 1 + 2.0 * n0 * n1 / n;
            double varianceR = 2.0 * n0 * n1 * (2.0 * n0 * n1 - n) / (Math.pow(n, 2) * (n - 1));

            // 计算标准化统计量Z
            double Z = Math.abs((r - expectedR) / Math.sqrt(varianceR));

            // 计算p值
            double pValue = calculatePValueFromZ(Z);

            // 判断是否通过测试
            boolean passed = pValue >= SIGNIFICANCE_LEVEL;

            // 构建结果
            result.put("testName", "游程总数检测");
            result.put("sequenceLength", n);
            result.put("runsCount", r);
            result.put("expected", expectedR);
            result.put("variance", varianceR);
            result.put("statistic", Z);
            result.put("pValue", pValue);
            result.put("threshold", SIGNIFICANCE_LEVEL);
            result.put("passed", passed);
            result.put("conclusion", passed ?
                    "通过：序列中0和1交替的频率符合随机性要求" :
                    "失败：序列中0和1交替的频率不符合随机性要求");

        } catch (Exception e) {
            result.put("error", "游程总数检测失败: " + e.getMessage());
            result.put("passed", false);
        }

        return result;
    }

    /**
     * 游程分布检测
     * 根据《GM/T 0005-2021》规范实现
     */
    private Map<String, Object> performRunsDistributionTest(boolean[] bits) {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            int n = bits.length;

            if (n < 100) {
                throw new IllegalArgumentException("序列太短，无法进行游程分布检测，至少需要100比特");
            }

            // 初始化游程长度统计数组（分开统计0和1的游程）
            // 按照GM/T 0005-2021标准，游程长度超过34的统一计为34
            int[] runs0 = new int[MAX_RUN_LENGTH + 1]; // 0对应的游程
            int[] runs1 = new int[MAX_RUN_LENGTH + 1]; // 1对应的游程

            // 统计游程长度
            int currentRun = 1;
            boolean currentBit = bits[0];

            for (int i = 1; i < n; i++) {
                if (bits[i] == currentBit) {
                    currentRun++;
                } else {
                    // 记录前一个游程的长度
                    int runIndex = Math.min(currentRun, MAX_RUN_LENGTH);
                    if (currentBit) {
                        runs1[runIndex]++;
                    } else {
                        runs0[runIndex]++;
                    }

                    // 开始一个新游程
                    currentRun = 1;
                    currentBit = bits[i];
                }
            }

            // 记录最后一个游程
            int runIndex = Math.min(currentRun, MAX_RUN_LENGTH);
            if (currentBit) {
                runs1[runIndex]++;
            } else {
                runs0[runIndex]++;
            }

            // 计算游程长度的理论分布（概率）
            double[] probabilities = new double[MAX_RUN_LENGTH + 1];
            for (int i = 1; i <= MAX_RUN_LENGTH; i++) {
                if (i < MAX_RUN_LENGTH) {
                    probabilities[i] = Math.pow(0.5, i);
                } else {
                    // 计算长度>=MAX_RUN_LENGTH的理论概率
                    probabilities[i] = Math.pow(0.5, i - 1);
                }
            }

            // 计算0和1的游程总数
            int total0 = 0;
            int total1 = 0;
            for (int i = 1; i <= MAX_RUN_LENGTH; i++) {
                total0 += runs0[i];
                total1 += runs1[i];
            }

            // 合并游程长度以确保每个类别的期望频数至少为5
            List<Integer> observed0 = new ArrayList<Integer>();
            List<Double> expected0 = new ArrayList<Double>();
            List<Integer> observed1 = new ArrayList<Integer>();
            List<Double> expected1 = new ArrayList<Double>();

            // 处理0的游程
            int current0 = 0;
            double currentExp0 = 0;
            for (int i = 1; i <= MAX_RUN_LENGTH; i++) {
                double exp = total0 * probabilities[i];
                current0 += runs0[i];
                currentExp0 += exp;

                if (currentExp0 >= 5.0 || i == MAX_RUN_LENGTH) {
                    observed0.add(current0);
                    expected0.add(currentExp0);
                    current0 = 0;
                    currentExp0 = 0;
                }
            }

            // 处理1的游程
            int current1 = 0;
            double currentExp1 = 0;
            for (int i = 1; i <= MAX_RUN_LENGTH; i++) {
                double exp = total1 * probabilities[i];
                current1 += runs1[i];
                currentExp1 += exp;

                if (currentExp1 >= 5.0 || i == MAX_RUN_LENGTH) {
                    observed1.add(current1);
                    expected1.add(currentExp1);
                    current1 = 0;
                    currentExp1 = 0;
                }
            }

            // 计算卡方统计量
            double chi0 = 0;
            for (int i = 0; i < observed0.size(); i++) {
                chi0 += Math.pow(observed0.get(i) - expected0.get(i), 2) / expected0.get(i);
            }

            double chi1 = 0;
            for (int i = 0; i < observed1.size(); i++) {
                chi1 += Math.pow(observed1.get(i) - expected1.get(i), 2) / expected1.get(i);
            }

            // 计算自由度和p值
            int df0 = observed0.size() - 1; // 自由度
            int df1 = observed1.size() - 1; // 自由度

            double pValue0 = 1.0 - chiSquareCDF(chi0, df0);
            double pValue1 = 1.0 - chiSquareCDF(chi1, df1);

            // 判断是否通过测试
            boolean passed0 = pValue0 >= SIGNIFICANCE_LEVEL;
            boolean passed1 = pValue1 >= SIGNIFICANCE_LEVEL;
            boolean passed = passed0 && passed1;

            // 构建结果
            result.put("testName", "游程分布检测");

            Map<String, Object> result0 = new HashMap<String, Object>();
            result0.put("runsTotal", total0);
            result0.put("statistic", chi0);
            result0.put("degreesOfFreedom", df0);
            result0.put("pValue", pValue0);
            result0.put("passed", passed0);

            Map<String, Object> result1 = new HashMap<String, Object>();
            result1.put("runsTotal", total1);
            result1.put("statistic", chi1);
            result1.put("degreesOfFreedom", df1);
            result1.put("pValue", pValue1);
            result1.put("passed", passed1);

            result.put("runs0", result0);
            result.put("runs1", result1);
            result.put("passed", passed);
            result.put("conclusion", passed ?
                    "通过：序列中0和1的游程长度分布符合随机性要求" :
                    "失败：序列中0和1的游程长度分布不符合随机性要求");

            // 添加详细的游程分布数据
            Map<String, Integer> distribution0 = new HashMap<String, Integer>();
            Map<String, Integer> distribution1 = new HashMap<String, Integer>();

            for (int i = 1; i <= MAX_RUN_LENGTH; i++) {
                if (i < MAX_RUN_LENGTH) {
                    distribution0.put(String.valueOf(i), runs0[i]);
                    distribution1.put(String.valueOf(i), runs1[i]);
                } else {
                    distribution0.put(">=" + i, runs0[i]);
                    distribution1.put(">=" + i, runs1[i]);
                }
            }

            result.put("distribution0", distribution0);
            result.put("distribution1", distribution1);

        } catch (Exception e) {
            result.put("error", "游程分布检测失败: " + e.getMessage());
            result.put("passed", false);
        }

        return result;
    }

    /**
     * 重叠子序列检测
     * 根据《GM/T 0005-2021》规范实现
     */
    private Map<String, Object> performOverlappingTest(boolean[] bits) {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            int n = bits.length;

            if (n < 100) {
                throw new IllegalArgumentException("序列太短，无法进行重叠子序列检测，至少需要100比特");
            }

            // 根据GM/T 0005-2021标准，确定子序列长度m和区块长度N
            // m在[2, 10]之间，N≥2^m
            int m = Math.min((int)Math.log(n) / 2, 10);
            m = Math.max(2, Math.min(m, 10));

            int blockSize = 1 << m; // 2^m
            int blockCount = n / blockSize;

            if (blockCount < 5) {
                throw new IllegalArgumentException("序列太短，无法进行重叠子序列检测，至少需要" + (5 * blockSize) + "比特");
            }

            // 初始化统计数组
            int[] W = new int[blockCount]; // 每个区块中1的计数

            // 统计每个区块中的所有m-bit重叠子序列中1的数量
            for (int i = 0; i < blockCount; i++) {
                int blockStart = i * blockSize;
                int onesCount = 0;

                for (int j = 0; j < blockSize - m + 1; j++) {
                    boolean allOnes = true;
                    for (int k = 0; k < m; k++) {
                        if (!bits[blockStart + j + k]) {
                            allOnes = false;
                            break;
                        }
                    }

                    if (allOnes) {
                        onesCount++;
                    }
                }

                W[i] = onesCount;
            }

            // 计算期望值和方差
            double mu = (blockSize - m + 1) / Math.pow(2, m); // 期望值
            double variance = blockSize * (1.0 / Math.pow(2, m)) * (1 - 1.0 / Math.pow(2, m)); // 方差

            // 根据区块中重叠模式的出现频率定义K+1个类别
            int K = 5; // 定义K个间隔
            double[] intervals = new double[K + 1];

            // 计算类别边界
            double step = 5.0 * Math.sqrt(variance) / K;
            for (int i = 0; i <= K; i++) {
                intervals[i] = mu - 2.5 * Math.sqrt(variance) + i * step;
            }
            intervals[0] = Double.NEGATIVE_INFINITY;
            intervals[K] = Double.POSITIVE_INFINITY;

            // 统计每个区间的区块数
            int[] counts = new int[K];
            for (int i = 0; i < blockCount; i++) {
                for (int j = 0; j < K; j++) {
                    if (W[i] >= intervals[j] && W[i] < intervals[j + 1]) {
                        counts[j]++;
                        break;
                    }
                }
            }

            // 计算每个类别的理论概率
            double[] pi = new double[K];
            for (int i = 0; i < K; i++) {
                double lower = (intervals[i] - mu) / Math.sqrt(variance);
                double upper = (intervals[i+1] - mu) / Math.sqrt(variance);
                pi[i] = normalCDF(upper) - normalCDF(lower);
            }

            // 计算期望频数
            double[] expected = new double[K];
            for (int i = 0; i < K; i++) {
                expected[i] = blockCount * pi[i];
            }

            // 计算卡方统计量
            double chi2 = 0;
            for (int i = 0; i < K; i++) {
                // 避免除以零或非常小的值
                if (expected[i] >= 1.0) {
                    chi2 += Math.pow(counts[i] - expected[i], 2) / expected[i];
                }
            }

            // 计算p值
            int degreesOfFreedom = K - 1;
            double pValue = 1.0 - chiSquareCDF(chi2, degreesOfFreedom);

            // 判断是否通过测试
            boolean passed = pValue >= SIGNIFICANCE_LEVEL;

            // 构建结果
            result.put("testName", "重叠子序列检测");
            result.put("sequenceLength", n);
            result.put("blockCount", blockCount);
            result.put("blockSize", blockSize);
            result.put("subSequenceLength", m);
            result.put("mu", mu);
            result.put("variance", variance);
            result.put("statistic", chi2);
            result.put("degreesOfFreedom", degreesOfFreedom);
            result.put("pValue", pValue);
            result.put("threshold", SIGNIFICANCE_LEVEL);
            result.put("passed", passed);
            result.put("conclusion", passed ?
                    "通过：序列中重叠子序列的分布符合随机性要求" :
                    "失败：序列中重叠子序列的分布不符合随机性要求");

            // 添加详细分布信息
            Map<String, Object> distribution = new HashMap<String, Object>();
            for (int i = 0; i < K; i++) {
                Map<String, Object> category = new HashMap<String, Object>();
                category.put("observed", counts[i]);
                category.put("expected", expected[i]);
                category.put("probability", pi[i]);

                // 区间范围
                String range;
                if (i == 0) {
                    range = "< " + String.format("%.2f", intervals[i+1]);
                } else if (i == K-1) {
                    range = ">= " + String.format("%.2f", intervals[i]);
                } else {
                    range = String.format("[%.2f, %.2f)", intervals[i], intervals[i+1]);
                }

                distribution.put(range, category);
            }
            result.put("distribution", distribution);

        } catch (Exception e) {
            result.put("error", "重叠子序列检测失败: " + e.getMessage());
            result.put("passed", false);
        }

        return result;
    }

    /**
     * 自相关检测
     * 根据《GM/T 0005-2021》规范实现
     */
    private Map<String, Object> performAutocorrelationTest(boolean[] bits) {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            int n = bits.length;

            if (n < 100) {
                throw new IllegalArgumentException("序列太短，无法进行自相关检测，至少需要100比特");
            }

            List<Map<String, Object>> correlationResults = new ArrayList<Map<String, Object>>();
            boolean allPassed = true;

            // 根据GM/T 0005-2021，选择多个d值进行测试
            int[] dValues = new int[] {1, 2, 8, 16, 32};
            for (int d : dValues) {
                if (d >= n) {
                    continue; // 跳过不合适的d值
                }

                Map<String, Object> dResult = new HashMap<String, Object>();

                // 计算自相关值A(d)
                int count = 0;
                for (int i = 0; i < n - d; i++) {
                    if (bits[i] != bits[i + d]) {
                        count++;
                    }
                }

                double A = (2.0 * count) / (n - d) - 1.0;

                // 计算标准差
                double sigma = Math.sqrt((n - d)) / (n - d);

                // 计算标准化统计量
                double Z = Math.abs(A) / (Math.sqrt(2.0) * sigma);

                // 计算p值
                double pValue = calculatePValueFromZ(Z);

                // 判断是否通过测试
                boolean passed = pValue >= SIGNIFICANCE_LEVEL;
                if (!passed) {
                    allPassed = false;
                }

                dResult.put("d", d);
                dResult.put("count", count);
                dResult.put("autocorrelation", A);
                dResult.put("sigma", sigma);
                dResult.put("statistic", Z);
                dResult.put("pValue", pValue);
                dResult.put("passed", passed);

                correlationResults.add(dResult);
            }

            result.put("testName", "自相关检测");
            result.put("results", correlationResults);
            result.put("passed", allPassed);
            result.put("conclusion", allPassed ?
                    "通过：序列的自相关分布符合随机性要求" :
                    "失败：序列的自相关分布不符合随机性要求");

        } catch (Exception e) {
            result.put("error", "自相关检测失败: " + e.getMessage());
            result.put("passed", false);
        }

        return result;
    }

    /**
     * 单比特频数检测
     * 根据《GM/T 0005-2021》规范实现
     */
    private Map<String, Object> performFrequencyTest(boolean[] bits) {
        Map<String, Object> result = new HashMap<String, Object>();

        try {
            int n = bits.length;

            if (n < 100) {
                throw new IllegalArgumentException("序列太短，无法进行单比特频数检测，至少需要100比特");
            }

            // 计算序列中1的数量
            int ones = 0;
            for (int i = 0; i < n; i++) {
                if (bits[i]) {
                    ones++;
                }
            }

            // 计算0的数量
            int zeros = n - ones;

            // 计算1的比例
            double p = (double) ones / n;

            // 计算统计量Sn和标准化统计量S
            int Sn = 2 * ones - n; // +1对应1，-1对应0的求和
            double S = Math.abs(Sn) / Math.sqrt(n);

            // 计算p值
            double pValue = calculatePValueFromZ(S);

            // 判断是否通过测试
            boolean passed = pValue >= SIGNIFICANCE_LEVEL;

            // 构建结果
            result.put("testName", "单比特频数检测");
            result.put("sequenceLength", n);
            result.put("ones", ones);
            result.put("zeros", zeros);
            result.put("proportion", p);
            result.put("statistic", S);
            result.put("pValue", pValue);
            result.put("threshold", SIGNIFICANCE_LEVEL);
            result.put("passed", passed);
            result.put("conclusion", passed ?
                    "通过：序列中0和1的比例符合随机性要求" :
                    "失败：序列中0和1的比例不符合随机性要求");

        } catch (Exception e) {
            result.put("error", "单比特频数检测失败: " + e.getMessage());
            result.put("passed", false);
        }

        return result;
    }
}