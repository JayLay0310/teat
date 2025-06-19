/**
 * @brief  SDF Standard Header
 */

#pragma once
#ifndef _NDSEC_SDF_HEADER_H_
#define _NDSEC_SDF_HEADER_H_

#if defined(_WIN32) || defined(__CYGWIN__) || defined(__MINGW32__) ||          \
    defined(__MINGW64__)
#ifdef SDF_EXPORT_API
#ifdef __GNUC__
#define SDF_EXPORT __attribute__((dllexport))
#else
#define SDF_EXPORT __declspec(dllexport)
#endif
#else
#ifdef __GNUC__
#define SDF_EXPORT __attribute__((dllimport))
#else
#define SDF_EXPORT __declspec(dllimport)
#endif
#endif
#else
#define SDF_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SGD_API_VERSION 0x01000000 ///< api version

///数据类型定义
typedef char sdf_char;
typedef char sdf_int8_t;
typedef short sdf_int16_t;
typedef int sdf_int32_t;
typedef long long sdf_int64_t;
typedef unsigned char sdf_uint8_t;
typedef unsigned short sdf_uint16_t;
typedef unsigned int sdf_uint32_t;
typedef unsigned long long sdf_uint64_t;
typedef unsigned int sdf_return_t;
typedef void *sdf_handle_t;

/**
 * @brief 设备信息数据结构定义
 */
typedef struct DeviceInfo_st {
  unsigned char IssuerName[40];   ///<设备生产厂商名称
  unsigned char DeviceName[16];   ///<设备型号
  unsigned char DeviceSerial[16]; ///<设备编号
  unsigned int DeviceVersion;     ///<密码设备内部软件的版本号
  unsigned int StandardVersion;   ///<密码设备支持的接口规范版本号
  unsigned int AsymAlgAbility[2]; ///<支持的非对称算法及模长
  unsigned int SymAlgAbility;     ///<所有支持的对称算法
  unsigned int HashAlgAbility;    ///<所有支持的杂凑算法
  unsigned int BufferSize;        ///<支持的最大文件存储空间
} DEVICEINFO;

/// RSA密钥
#define RSAref_MAX_BITS 2048
#define RSAref_MAX_LEN ((RSAref_MAX_BITS + 7) / 8)
#define RSAref_MAX_PBITS ((RSAref_MAX_BITS + 1) / 2)
#define RSAref_MAX_PLEN ((RSAref_MAX_PBITS + 7) / 8)

/**
 * @brief RSA公钥数据结构定义
 */
typedef struct RSArefPublicKey_st {
  unsigned int bits;               ///<模长
  unsigned char m[RSAref_MAX_LEN]; ///<模N
  unsigned char e[RSAref_MAX_LEN]; ///<公钥指数
} RSArefPublicKey;

/**
 * @brief RSA私钥数据结构定义
 */
typedef struct RSArefPrivateKey_st {
  unsigned int bits;                       ///<模长
  unsigned char m[RSAref_MAX_LEN];         ///<模N
  unsigned char e[RSAref_MAX_LEN];         ///<公钥指数
  unsigned char d[RSAref_MAX_LEN];         ///<私钥指数
  unsigned char prime[2][RSAref_MAX_PLEN]; ///<素数p和q
  unsigned char pexp[2][RSAref_MAX_PLEN];  ///< Dp和Dq
  unsigned char coef[RSAref_MAX_PLEN];     ///<系数i
} RSArefPrivateKey;

/// ECC密钥
#define ECCref_MAX_BITS 512
#define ECCref_MAX_LEN ((ECCref_MAX_BITS + 7) / 8)
#define ECCref_MAX_CIPHER_LEN 136

/**
 * @brief ECC密钥数据结构
 */
typedef struct {
  unsigned char p[ECCref_MAX_LEN]; ///<素数p
  unsigned char a[ECCref_MAX_LEN]; ///<参数a
  unsigned char b[ECCref_MAX_LEN]; ///<参数b
  unsigned char gx[ECCref_MAX_LEN]; ///<参数Gx: x coordinate of the base point G
  unsigned char gy[ECCref_MAX_LEN]; ///<参数Gy: y coordinate of the base point G
  unsigned char n[ECCref_MAX_LEN]; ///<阶N: order n of the base point G
  unsigned int len; ///<参数位长Len，Len必须为160、192、224或256
} ECCrefCurveParam;

/**
 * @brief ECC公钥数据结构定义
 */
typedef struct ECCrefPublicKey_st {
  unsigned int bits;               ///<密钥位长
  unsigned char x[ECCref_MAX_LEN]; ///<公钥x坐标
  unsigned char y[ECCref_MAX_LEN]; ///<公钥y坐标
} ECCrefPublicKey;

/**
 * @brief ECC私钥数据结构定义
 */
typedef struct ECCrefPrivateKey_st {
  unsigned int bits;               ///<密钥位长
  unsigned char D[ECCref_MAX_LEN]; ///<私钥
} ECCrefPrivateKey;

/**
 * @brief ECC密文数据结构定义
 */
typedef struct ECCCipher_st {
  unsigned char x[ECCref_MAX_LEN];
  unsigned char y[ECCref_MAX_LEN];
  unsigned char M[32];
  unsigned int L;
  unsigned char C[1];
} ECCCipher;

/**
 * @brief ECC 签名结构体定义
 */
typedef struct ECCSignature_st {
  unsigned char r[ECCref_MAX_LEN];
  unsigned char s[ECCref_MAX_LEN];
} ECCSignature;

// 算法标识

// 对称算法标识
#define SGD_SM1_ECB 0x00000101 ///< SM1 算法 ECB 加密模式
#define SGD_SM1_CBC 0x00000102 ///< SM1 算法 CBC 加密模式
#define SGD_SM1_CFB 0x00000104 ///< SM1 算法 CFB 加密模式
#define SGD_SM1_OFB 0x00000108 ///< SM1 算法 OFB 加密模式
#define SGD_SM1_MAC 0x00000110 ///< SM1 算法 MAC 加密模式

#define SGD_SSF33_ECB 0x00000201 ///< SSF33 算法 ECB 加密模式
#define SGD_SSF33_CBC 0x00000202 ///< SSF33 算法 CBC 加密模式
#define SGD_SSF33_CFB 0x00000204 ///< SSF33 算法 CFB 加密模式
#define SGD_SSF33_OFB 0x00000208 ///< SSF33 算法 OFB 加密模式
#define SGD_SSF33_MAC 0x00000210 ///< SSF33 算法 MAC 加密模式

#define SGD_SM4_ECB 0x00000401 ///< SMS4 算法 ECB 加密模式
#define SGD_SM4_CBC 0x00000402 ///< SMS4 算法 CBC 加密模式
#define SGD_SM4_CFB 0x00000404 ///< SMS4 算法 CFB 加密模式
#define SGD_SM4_OFB 0x00000408 ///< SMS4 算法 OFB 加密模式
#define SGD_SM4_MAC 0x00000410 ///< SMS4 算法 MAC 加密模式

#define SGD_ZUC_EEA3 0x00000801 ///< ZUC祖冲之机密性算法 128-EEA3算法
#define SGD_ZUC_EIA3 0x00000802 ///< ZUC祖冲之完整性算法 128-EIA3算法

// 非对称算法标识
#define SGD_RSA 0x00010000   ///< RSA 算法
#define SGD_SM2 0x00020100   ///< SM2 算法
#define SGD_SM2_1 0x00020200 ///< SM2_1 算法
#define SGD_SM2_2 0x00020400 ///< SM2_2 算法
#define SGD_SM2_3 0x00020800 ///< SM2_3 算法

// 杂凑算法标识
#define SGD_SM3 0x00000001    ///< SM3 算法
#define SGD_SHA1 0x00000002   ///< SHA1 算法
#define SGD_SHA256 0x00000004 ///< SHA256 算法
#define SGD_SHA512 0x00000008 ///< SHA512 算法
#define SGD_SHA384 0x00000010 ///< SHA384 算法
#define SGD_SHA224 0x00000020 ///< SHA224 算法
#define SGD_MD5 0x00000080    ///< MD5 算法

#define SGD_SM3_RSA 0x00010001
#define SGD_SHA1_RSA 0x00010002
#define SGD_SHA256_RSA 0x00010004
#define SGD_SM3_SM2 0x00020201

//标准错误码定义
#define SDR_OK 0x0                             ///< 成功
#define SDR_BASE 0x01000000                    ///< 错误码基础值
#define SDR_UNKNOWERR (SDR_BASE + 0x00000001)  ///< 未知错误
#define SDR_NOTSUPPORT (SDR_BASE + 0x00000002) ///< 不支持的接口调用
#define SDR_COMMFAIL (SDR_BASE + 0x00000003)   ///< 通信错误
#define SDR_HARDFAIL (SDR_BASE + 0x00000004) ///< 硬件错误，运算模块无响应
#define SDR_OPENDEVICE (SDR_BASE + 0x00000005)    ///< 打开设备错误
#define SDR_OPENSESSION (SDR_BASE + 0x00000006)   ///< 打开会话句柄错误
#define SDR_PARDENY (SDR_BASE + 0x00000007)       ///< 权限不满足
#define SDR_KEYNOTEXIST (SDR_BASE + 0x00000008)   ///< 密钥不存在
#define SDR_ALGNOTSUPPORT (SDR_BASE + 0x00000009) ///< 不支持的算法
#define SDR_ALGMODNOTSUPPORT (SDR_BASE + 0x0000000A) ///< 不支持的算法模式
#define SDR_PKOPERR (SDR_BASE + 0x0000000B)          ///< 公钥运算错误
#define SDR_SKOPERR (SDR_BASE + 0x0000000C)          ///< 私钥运算错误
#define SDR_SIGNERR (SDR_BASE + 0x0000000D)          ///< 签名错误
#define SDR_VERIFYERR (SDR_BASE + 0x0000000E)        ///< 验证错误
#define SDR_SYMOPERR (SDR_BASE + 0x0000000F)         ///< 对称运算错误
#define SDR_STEPERR (SDR_BASE + 0x00000010)          ///< 步骤错误
#define SDR_FILESIZEERR                                                        \
  (SDR_BASE + 0x00000011) ///< 文件大小错误或输入数据长度非法
#define SDR_FILENOEXIST (SDR_BASE + 0x00000012) ///< 文件不存在
#define SDR_FILEOFSERR (SDR_BASE + 0x00000013)  ///< 文件操作偏移量错误
#define SDR_KEYTYPEERR (SDR_BASE + 0x00000014)  ///< 密钥类型错误
#define SDR_KEYERR (SDR_BASE + 0x00000015)      ///< 密钥错误
#define SDR_ENCDATAERR (SDR_BASE + 0x00000016)
#define SDR_RANDERR (SDR_BASE + 0x00000017)
#define SDR_PRKRERR (SDR_BASE + 0x00000018)
#define SDR_MACERR (SDR_BASE + 0x00000019)
#define SDR_FILEEXSITS (SDR_BASE + 0x0000001A)
#define SDR_FILEWERR (SDR_BASE + 0x0000001B)
#define SDR_NOBUFFER (SDR_BASE + 0x0000001C)
#define SDR_INARGERR (SDR_BASE + 0x0000001D)
#define SDR_OUTARGERR (SDR_BASE + 0x0000001E)

//设备管理类函数

/**
 * @brief 打开设备：打开密码设备
 * @param phDeviceHandle 返回设备句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_OpenDevice(sdf_handle_t *phDeviceHandle);

/**
 * @brief 打开设备：打开密码设备
 * @param phDeviceHandle 返回设备句柄
 * @param pcDeviceConfig device specific config
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_OpenDeviceWithConfig(
    sdf_handle_t *phDeviceHandle, const sdf_uint8_t *pcDeviceConfig,
    sdf_uint32_t pcDeviceConfigLength);

/**
 * @brief 关闭设备：关闭密码设备，并释放相关资源
 * @param hDeviceHandle 已打开的设备句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_CloseDevice(sdf_handle_t hDeviceHandle);

/**
 * @brief 创建会话:创建与密码设备的会话
 * @param hDeviceHandle 已打开的设备句柄
 * @param phSessionHandle 返回与密码设备建立的新会话句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_OpenSession(sdf_handle_t hDeviceHandle,
                                        sdf_handle_t *phSessionHandle);

/**
 * @brief 关闭会话:关闭与密码设备已建立的会话，并释放相关资源
 * @param hSessionHandle 与密码设备建立的会话句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_CloseSession(sdf_handle_t hSessionHandle);

/**
 * @brief 获取设备信息:获取密码设备能力描述
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pstDeviceInfo 设备能力描述信息，内容及格式见设备信息定义
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GetDeviceInfo(sdf_handle_t hSessionHandle,
                                          DEVICEINFO *pstDeviceInfo);

/**
 * @brief 产生随机数:获取指定长度的随机数
 * @param hSessionHandle 欲获取的随机数长度
 * @param uiLength 欲获取的随机数长度
 * @param pucRandom 缓冲区指针，用于存放获取的随机数
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateRandom(sdf_handle_t hSessionHandle,
                                           sdf_uint32_t uiLength,
                                           sdf_uint8_t *pucRandom);

/**
 * @brief 获取私钥使用权限:获取密码设备内部存储的指定索引私钥的使用权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 * @param pucPassword 使用私钥权限的标识码
 * @param uiPwdLength
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GetPrivateKeyAccessRight(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    sdf_uint8_t *pucPassword, sdf_uint32_t uiPwdLength);

/**
 * @brief 释放私钥使用权限:释放密码设备存储的指定索引私钥的使用授权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ReleasePrivateKeyAccessRight(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex);

/**
 * @brief 获取私钥使用权限:获取密码设备内部存储的指定索引私钥的使用权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 * @param pucPassword 使用私钥权限的标识码
 * @param uiPwdLength
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GetPrivateKeyAccessRight_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    sdf_uint8_t *pucPassword, sdf_uint32_t uiPwdLength);

/**
 * @brief 释放私钥使用权限:释放密码设备存储的指定索引私钥的使用授权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ReleasePrivateKeyAccessRight_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex);

/**
 * @brief 获取加密私钥使用权限:获取密码设备内部存储的指定索引私钥的使用权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 * @param pucPassword 使用私钥权限的标识码
 * @param uiPwdLength
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GetEncPrivateKeyAccessRight_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    sdf_uint8_t *pucPassword, sdf_uint32_t uiPwdLength);

/**
 * @brief 获取签名私钥使用权限:获取密码设备内部存储的指定索引私钥的使用权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 * @param pucPassword 使用私钥权限的标识码
 * @param uiPwdLength
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GetSignPrivateKeyAccessRight_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    sdf_uint8_t *pucPassword, sdf_uint32_t uiPwdLength);

/**
 * @brief 释放私钥使用权限:释放密码设备存储的指定索引私钥的使用授权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ReleaseEncPrivateKeyAccessRight_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex);

/**
 * @brief 释放私钥使用权限:释放密码设备存储的指定索引私钥的使用授权
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储私钥的索引值
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ReleaseSignPrivateKeyAccessRight_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex);

// 密钥管理类函数

/**
 * @brief 产生RSA密钥对并输出:请求密码设备产生指定模长的RSA密钥对
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyBits 指定密钥模长
 * @param pucPublicKey RSA公钥结构
 * @param pucPrivateKey RSA私钥结构
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyPair_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyBits,
    RSArefPublicKey *pucPublicKey, RSArefPrivateKey *pucPrivateKey);

/**
 * @brief 导出RSA签名公钥:导出密码设备内部存储的指定索引位置的签名公钥
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储的RSA密钥对索引值
 * @param pucPublicKey RSA公钥结构
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExportSignPublicKey_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    RSArefPublicKey *pucPublicKey);

/**
 * @brief 导出RSA加密公钥:导出密码设备内部存储的指定索引位置的加密公钥
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储的RSA密钥对索引值
 * @param pucPublicKey  RSA公钥结构
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t
SDF_ExportEncPublicKey_RSA(sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
                           RSArefPublicKey *pucPublicKey);

/**
 * @brief
 * 生成会话密钥并用内部RSA公钥加密输出:生成会话密钥并用指定索引的内部加密公钥加密输出，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiIPKIndex 密码设备内部存储加密公钥的索引值
 * @param uiKeyBits 指定产生的会话密钥长度
 * @param pucKey 缓冲区指针，用于存放返回的密钥密文
 * @param puiKeyLength 返回的密钥密文长度
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyWithIPK_RSA(sdf_handle_t hSessionHandle,
                                                   sdf_uint32_t uiIPKIndex,
                                                   sdf_uint32_t uiKeyBits,
                                                   sdf_uint8_t *pucKey,
                                                   sdf_uint32_t *puiKeyLength,
                                                   sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 生成会话密钥并用外部RSA公钥加密输出:生成会话密钥并用外部公钥加密输出，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyBits 指定产生的会话密钥长度
 * @param pucPublicKey 输入的外部RSA公钥结构
 * @param pucKey 缓冲区指针，用于存放返回的密钥密文
 * @param puiKeyLength 返回的密钥密文长度
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyWithEPK_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyBits,
    RSArefPublicKey *pucPublicKey, sdf_uint8_t *pucKey,
    sdf_uint32_t *puiKeyLength, sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 导入会话密钥并用内部RSA私钥解密:导入会话密钥并用内部私钥解密，同时返回密钥句柄
 * @param hSessionHandle  与设备建立的会话句柄
 * @param uiISKIndex 密码设备内部存储加密私钥的索引值，对应于加密时的公钥
 * @param pucKey 缓冲区指针，用于存放输入的密钥密文
 * @param uiKeyLength 输入的密钥密文长度
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ImportKeyWithISK_RSA(sdf_handle_t hSessionHandle,
                                                 sdf_uint32_t uiISKIndex,
                                                 sdf_uint8_t *pucKey,
                                                 sdf_uint32_t uiKeyLength,
                                                 sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 基于RSA算法的数字信封转换:将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储的内部RSA加密密钥对索引值
 * @param pucPublicKey 外部RSA公钥结构
 * @param pucDEInput 缓冲区指针，用于存放输入的会话密钥密文
 * @param uiDELength 输入的会话密钥密文长度
 * @param pucDEOutput 缓冲区指针，用于存放输出的会话密钥密文
 * @param puiDELength 输出的会话密钥密文长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExchangeDigitEnvelopeBaseOnRSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    RSArefPublicKey *pucPublicKey, sdf_uint8_t *pucDEInput,
    sdf_uint32_t uiDELength, sdf_uint8_t *pucDEOutput,
    sdf_uint32_t *puiDELength);

/**
 * @brief 导入明文会话密钥:与设备建立的会话句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucKey 缓冲区指针，用于存放输入的密钥明文
 * @param uiKeyLength 输入的密钥明文长度
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ImportKey(sdf_handle_t hSessionHandle,
                                      sdf_uint8_t *pucKey,
                                      sdf_uint32_t uiKeyLength,
                                      sdf_handle_t *phKeyHandle);

/**
 * @brief 销毁会话密钥:销毁会话密钥，并释放为密钥句柄分配的内存等资源
 * @param hSessionHandle 与设备建立的会话句柄
 * @param hKeyHandle 输入的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_DestroyKey(sdf_handle_t hSessionHandle,
                                       sdf_handle_t hKeyHandle);

/**
 * @brief
 * 生成会话密钥并用密钥加密密钥加密输出:生成会话密钥并用密钥加密密钥加密输出，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyBits 指定产生的会话密钥长度
 * @param uiAlgID 算法标识，指定对称加密算法
 * @param uiKEKIndex 密码设备内部存储的密钥加密密钥的 索引值
 * @param pucKey 缓冲区指针，用于存放返回的会话密钥密文
 * @param puiKeyLength 返回的密钥密文长度
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyWithKEK(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyBits, sdf_uint32_t uiAlgID,
    sdf_uint32_t uiKEKIndex, sdf_uint8_t *pucKey, sdf_uint32_t *puiKeyLength,
    sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 导入会话密钥并用密钥加密密钥解密:导入会话密钥并用密钥加密密钥解密，同时返回会话密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 算法标识，指定对称加密算法
 * @param uiKEKIndex 密码设备内部存储的密钥加密密钥的 索引值
 * @param pucKey 缓冲区指针，用于存放返回的会话密钥密文
 * @param uiKeyLength 输入的密钥密文长度
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ImportKeyWithKEK(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiAlgID, sdf_uint32_t uiKEKIndex,
    sdf_uint8_t *pucKey, sdf_uint32_t uiKeyLength, sdf_handle_t *phKeyHandle);

/**
 * @brief 产生ECC密钥对并输出:请求密码设备产生指定类型和模长的ECC密钥对
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 指定算法标识
 * @param uiKeyBits 指定密钥长度
 * @param pucPublicKey ECC公钥结构
 * @param pucPrivateKey ECC私钥结构
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyPair_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiAlgID, sdf_uint32_t uiKeyBits,
    ECCrefPublicKey *pucPublicKey, ECCrefPrivateKey *pucPrivateKey);

/**
 * @brief 导出ECC签名公钥:导出密码设备内部存储的指定索引位置的签名公钥
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储的ECC密钥对索引值
 * @param pucPublicKey ECC公钥结构
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExportSignPublicKey_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    ECCrefPublicKey *pucPublicKey);

/**
 * @brief 导出ECC加密公钥:导出密码设备内部存储的指定索引位置的加密公钥
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储的ECC密钥对索引值
 * @param pucPublicKey ECC公钥结构
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t
SDF_ExportEncPublicKey_ECC(sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
                           ECCrefPublicKey *pucPublicKey);

/**
 * @brief
 * 生成密钥协商参数并输出:使用ECC密钥协商算法，为计算会话密钥而产生协商参数，同时返回指定索引位置的ECC公钥、临时ECC密钥对的公钥及协商句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiISKIndex 密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
 * @param uiKeyBits 要求协商的密钥长度
 * @param pucSponsorID 参与密钥协商的发起方ID值
 * @param uiSponsorIDLength 发起方ID长度
 * @param pucSponsorPublicKey 返回的发起方ECC公钥结构
 * @param pucSponsorTmpPublicKey 返回的发起方临时ECC公钥结构
 * @param phAgreementHandle 返回的密钥协商句柄，用于计算协商密钥
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateAgreementDataWithECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiISKIndex,
    sdf_uint32_t uiKeyBits, sdf_uint8_t *pucSponsorID,
    sdf_uint32_t uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey, sdf_handle_t *phAgreementHandle);

/**
 * @brief
 * 计算会话密钥:生成密钥协商参数并输出使用ECC密钥协商算法，使用自身协商句柄和响应方的协商参数计算会话密钥，同时返回会话密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucResponseID 外部输入的响应方ID值
 * @param uiResponseIDLength 外部输入的响应方ID长度
 * @param pucResponsePublicKey 外部输入的响应方ECC公钥结构
 * @param pucResponseTmpPublicKey 外部输入的响应方临时ECC公钥结构
 * @param hAgreementHandle 协商句柄，用于计算协商密钥
 * @param phKeyHandle 返回密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyWithECC(
    sdf_handle_t hSessionHandle, sdf_uint8_t *pucResponseID,
    sdf_uint32_t uiResponseIDLength, ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey, sdf_handle_t hAgreementHandle,
    sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 产生协商数据并计算会话密钥:使用ECC密钥协商算法，产生协商参数并计算会话密钥，同时返回产生的协商参数和会话密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiISKIndex 密码设备内部存储加密私钥的索引值，该私钥用于参与密钥协商
 * @param uiKeyBits 协商后要求输出的密钥长度
 * @param pucResponseID 响应方ID值
 * @param uiResponseIDLength 响应方ID长度
 * @param pucSponsorID 发起方ID值
 * @param uiSponsorIDLength 发起方ID长度
 * @param pucSponsorPublicKey 外部输入的发起方ECC公钥结构
 * @param pucSponsorTmpPublicKey 外部输入的发起方临时ECC公钥结构
 * @param pucResponsePublicKey 返回的响应方ECC公钥结构
 * @param pucResponseTmpPublicKey 返回的响应方临时ECC公钥结构
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateAgreementDataAndKeyWithECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiISKIndex,
    sdf_uint32_t uiKeyBits, sdf_uint8_t *pucResponseID,
    sdf_uint32_t uiResponseIDLength, sdf_uint8_t *pucSponsorID,
    sdf_uint32_t uiSponsorIDLength, ECCrefPublicKey *pucSponsorPublicKey,
    ECCrefPublicKey *pucSponsorTmpPublicKey,
    ECCrefPublicKey *pucResponsePublicKey,
    ECCrefPublicKey *pucResponseTmpPublicKey, sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 生成会话密钥并用内部ECC公钥加密输出:生成会话密钥并用指定索引的内部ECC加密公钥加密输出，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiIPKIndex 密码设备内部存储加密公钥的索引值
 * @param uiKeyBits 指定产生的会话密钥长度
 * @param pucKey 缓冲区指针，用于存放返回的密钥密文
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GenerateKeyWithIPK_ECC(sdf_handle_t hSessionHandle,
                                                   sdf_uint32_t uiIPKIndex,
                                                   sdf_uint32_t uiKeyBits,
                                                   ECCCipher *pucKey,
                                                   sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 生成会话密钥并用外部ECC公钥加密输出:生成会话密钥并用外部公钥加密输出，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyBits 指定产生的会话密钥长度
 * @param uiAlgID 外部ECC公钥的算法标识
 * @param pucPublicKey 输入的外部ECC公钥结构
 * @param pucKey 缓冲区指针，用于存放返回的密钥密文
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t
SDF_GenerateKeyWithEPK_ECC(sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyBits,
                           sdf_uint32_t uiAlgID, ECCrefPublicKey *pucPublicKey,
                           ECCCipher *pucKey, sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 导入会话密钥并用内部ECC私钥解密:导入会话密钥并用内部ECC加密私钥解密，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiISKIndex 密码设备内部存储加密私钥的索引值，对应于加密时的公钥
 * @param pucKey 缓冲区指针，用于存放输入的密钥密文
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ImportKeyWithISK_ECC(sdf_handle_t hSessionHandle,
                                                 sdf_uint32_t uiISKIndex,
                                                 ECCCipher *pucKey,
                                                 sdf_handle_t *phKeyHandle);

/**
 * @brief
 * 基于ECC算法的数字信封转换:将由内部加密公钥加密的会话密钥转换为由外部指定的公钥加密，可用于数字信封转换
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备存储的内部ECC密钥对索引值
 * @param uiAlgID 外部ECC公钥的算法标识
 * @param pucPublicKey 外部ECC公钥结构
 * @param pucEncDataIn 缓冲区指针，用于存放输入的会话密钥密文
 * @param pucEncDataOut 缓冲区指针，用于存放输出的会话密钥密文
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExchangeDigitEnvelopeBaseOnECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex, sdf_uint32_t uiAlgID,
    ECCrefPublicKey *pucPublicKey, ECCCipher *pucEncDataIn,
    ECCCipher *pucEncDataOut);

//非对称密码运算函数

/**
 * @brief 外部公钥RSA运算:指定使用外部公钥对数据进行运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucPublicKey 外部RSA公钥结构
 * @param pucDataInput 缓冲区指针，用于存放输入的数据
 * @param uiInputLength 输入的数据长度
 * @param pucDataOutput 缓冲区指针，用于存放输出的数据
 * @param puiOutputLength 输出的数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExternalPublicKeyOperation_RSA(
    sdf_handle_t hSessionHandle, RSArefPublicKey *pucPublicKey,
    sdf_uint8_t *pucDataInput, sdf_uint32_t uiInputLength,
    sdf_uint8_t *pucDataOutput, sdf_uint32_t *puiOutputLength);

/**
 * @brief 外部私钥RSA运算:指定使用外部私钥对数据进行运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucPrivateKey 外部RSA私钥结构
 * @param pucDataInput 缓冲区指针，用于存放外部输入的数据
 * @param uiInputLength 输入的数据长度
 * @param pucDataOutput 缓冲区指针，用于存放输出的数据
 * @param puiOutputLength 输出的数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExternalPrivateKeyOperation_RSA(
    sdf_handle_t hSessionHandle, RSArefPrivateKey *pucPrivateKey,
    sdf_uint8_t *pucDataInput, sdf_uint32_t uiInputLength,
    sdf_uint8_t *pucDataOutput, sdf_uint32_t *puiOutputLength);

/**
 * @brief 内部公钥RSA运算:使用内部指定索引的RSA公钥对数据进行运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备内部存储公钥的索引值
 * @param pucDataInput 缓冲区指针，用于存放外部输入的数据
 * @param uiInputLength 输入的数据长度
 * @param pucDataOutput 缓冲区指针，用于存放输出的数据
 * @param puiOutputLength 输出的数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_InternalPublicKeyOperation_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    sdf_uint8_t *pucDataInput, sdf_uint32_t uiInputLength,
    sdf_uint8_t *pucDataOutput, sdf_uint32_t *puiOutputLength);

/**
 * @brief 内部私钥RSA运算:使用内部指定索引的RSA私钥对数据进行运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiKeyIndex 密码设备内部存储私钥的索引值
 * @param pucDataInput 缓冲区指针，用于存放外部输入的数据
 * @param uiInputLength 输入的数据长度
 * @param pucDataOutput 缓冲区指针，用于存放输出的数据
 * @param puiOutputLength 输出的数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_InternalPrivateKeyOperation_RSA(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiKeyIndex,
    sdf_uint8_t *pucDataInput, sdf_uint32_t uiInputLength,
    sdf_uint8_t *pucDataOutput, sdf_uint32_t *puiOutputLength);

/**
 * @brief 外部密钥ECC签名:使用外部ECC私钥对数据进行签名运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 算法标识，指定使用的ECC算法
 * @param pucPrivateKey 外部ECC私钥结构
 * @param pucData 缓冲区指针，用于存放外部输入的数据
 * @param uiDataLength 输入的数据长度
 * @param pucSignature 缓冲区指针，用于存放输出的签名值数据
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExternalSign_ECC(sdf_handle_t hSessionHandle,
                                             sdf_uint32_t uiAlgID,
                                             ECCrefPrivateKey *pucPrivateKey,
                                             sdf_uint8_t *pucData,
                                             sdf_uint32_t uiDataLength,
                                             ECCSignature *pucSignature);

/**
 * @brief 外部密钥ECC验证:使用外部ECC公钥对ECC签名值进行验证运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 算法标识，指定使用的ECC算法
 * @param pucPublicKey 外部ECC公钥结构
 * @param pucDataInput 缓冲区指针，用于存放外部输入的数据
 * @param uiInputLength 输入的数据长度
 * @param pucSignature 缓冲区指针，用于存放输入的签名值数据
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExternalVerify_ECC(sdf_handle_t hSessionHandle,
                                               sdf_uint32_t uiAlgID,
                                               ECCrefPublicKey *pucPublicKey,
                                               sdf_uint8_t *pucDataInput,
                                               sdf_uint32_t uiInputLength,
                                               ECCSignature *pucSignature);

/**
 * @brief 内部密钥ECC签名:使用内部ECC私钥对数据进行签名运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiISKIndex 密码设备内部存储的ECC签名私钥的索引值
 * @param pucData 缓冲区指针，用于存放外部输入的数据
 * @param uiDataLength 输入的数据长度
 * @param pucSignature 缓冲区指针，用于存放输出的签名值数据
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_InternalSign_ECC(sdf_handle_t hSessionHandle,
                                             sdf_uint32_t uiISKIndex,
                                             sdf_uint8_t *pucData,
                                             sdf_uint32_t uiDataLength,
                                             ECCSignature *pucSignature);

/**
 * @brief 内部密钥ECC验证:使用内部ECC公钥对ECC签名值进行验证运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiISKIndex 密码设备内部存储的ECC签名公钥的索引值
 * @param pucData 缓冲区指针，用于存放外部输入的数据
 * @param uiDataLength 输入的数据长度
 * @param pucSignature 缓冲区指针，用于存放输入的签名值数据
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_InternalVerify_ECC(sdf_handle_t hSessionHandle,
                                               sdf_uint32_t uiISKIndex,
                                               sdf_uint8_t *pucData,
                                               sdf_uint32_t uiDataLength,
                                               ECCSignature *pucSignature);

/**
 * @brief 外部密钥ECC公钥加密:使用外部ECC公钥对数据进行加密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 算法标识，指定使用的ECC算法
 * @param pucPublicKey 外部ECC公钥结构
 * @param pucData 缓冲区指针，用于存放外部输入的数据
 * @param uiDataLength 输入的数据长度
 * @param pucEncData 缓冲区指针，用于存放输出的数据密文
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExternalEncrypt_ECC(sdf_handle_t hSessionHandle,
                                                sdf_uint32_t uiAlgID,
                                                ECCrefPublicKey *pucPublicKey,
                                                sdf_uint8_t *pucData,
                                                sdf_uint32_t uiDataLength,
                                                ECCCipher *pucEncData);

/**
 * @brief 外部密钥ECC私钥解密:使用外部ECC私钥对数据进行解密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 算法标识，指定使用的ECC算法
 * @param pucPrivateKey 外部ECC私钥结构
 * @param pucEncData ECC加密数据密文结构
 * @param pucData 缓冲区指针，用于存放输出的数据
 * @param puiDataLength 输出的数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ExternalDecrypt_ECC(sdf_handle_t hSessionHandle,
                                                sdf_uint32_t uiAlgID,
                                                ECCrefPrivateKey *pucPrivateKey,
                                                ECCCipher *pucEncData,
                                                sdf_uint8_t *pucData,
                                                sdf_uint32_t *puiDataLength);

/**
 * @brief 内部密钥ECC公钥加密:使用内部ECC公钥对数据进行加密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiIPKIndex 内部公钥索引
 * @param uiAlgID 算法标识，指定使用的ECC算法
 * @param pucData 缓冲区指针，用于存放外部输入的数据
 * @param uiDataLength 输入的数据长度
 * @param pucEncData 缓冲区指针，用于存放输出的数据密文
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_InternalEncrypt_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiIPKIndex, sdf_uint32_t uiAlgID,
    sdf_uint8_t *pucData, sdf_uint32_t uiDataLength, ECCCipher *pucEncData);

/**
 * @brief 内部密钥ECC私钥解密:使用内部ECC私钥对数据进行解密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiISKIndex 内部私钥索引
 * @param uiAlgID 算法标识，指定使用的ECC算法
 * @param pucEncData ECC加密数据密文结构
 * @param pucData 缓冲区指针，用于存放输出的数据
 * @param puiDataLength 输出的数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_InternalDecrypt_ECC(
    sdf_handle_t hSessionHandle, sdf_uint32_t uiISKIndex, sdf_uint32_t uiAlgID,
    ECCCipher *pucEncData, sdf_uint8_t *pucData, sdf_uint32_t *puiDataLength);

// 对称密码运算函数

/**
 * @brief 对称加密:使用指定的密钥句柄和IV对数据进行对称加密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param hKeyHandle 指定的密钥句柄
 * @param uiAlgID 算法标识，指定对称加密算法
 * @param pucIV 缓冲区指针，用于存放输入和返回的IV数据
 * @param pucData 缓冲区指针，用于存放输入的数据明文
 * @param uiDataLength 输入的数据长度
 * @param pucEncData 缓冲区指针，用于存放输出的数据密文
 * @param puiEncDataLength 输出的数据密文长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_Encrypt(
    sdf_handle_t hSessionHandle, sdf_handle_t hKeyHandle, sdf_uint32_t uiAlgID,
    sdf_uint8_t *pucIV, sdf_uint8_t *pucData, sdf_uint32_t uiDataLength,
    sdf_uint8_t *pucEncData, sdf_uint32_t *puiEncDataLength);

/**
 * @brief 对称加密:使用指定的密钥句柄和IV对数据进行对称加密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param rawKey 密钥内容缓冲区指针
 * @param uiAlgID 算法标识，指定对称加密算法
 * @param pucIV 缓冲区指针，用于存放输入和返回的IV数据
 * @param pucData 缓冲区指针，用于存放输入的数据明文
 * @param uiDataLength 输入的数据长度
 * @param pucEncData 缓冲区指针，用于存放输出的数据密文
 * @param puiEncDataLength 输出的数据密文长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_EncryptWithRawKey(
    sdf_handle_t hSessionHandle, sdf_uint8_t *rawKey, sdf_uint32_t uiAlgID,
    sdf_uint8_t *pucIV, sdf_uint8_t *pucData, sdf_uint32_t uiDataLength,
    sdf_uint8_t *pucEncData, sdf_uint32_t *puiEncDataLength);

/**
 * @brief 对称解密:使用指定的密钥句柄和IV对数据进行对称解密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param hKeyHandle 指定的密钥句柄
 * @param uiAlgID 算法标识，指定对称解密算法
 * @param pucIV 缓冲区指针，用于存放输入和返回的IV数据
 * @param pucEncData 缓冲区指针，用于存放输入的数据密文
 * @param uiEncDataLength 输入的数据密文长度
 * @param pucData 缓冲区指针，用于存放输出的数据明文
 * @param puiDataLength 输出的数据明文长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_Decrypt(
    sdf_handle_t hSessionHandle, sdf_handle_t hKeyHandle, sdf_uint32_t uiAlgID,
    sdf_uint8_t *pucIV, sdf_uint8_t *pucEncData, sdf_uint32_t uiEncDataLength,
    sdf_uint8_t *pucData, sdf_uint32_t *puiDataLength);

/**
 * @brief 对称解密:使用指定的密钥句柄和IV对数据进行对称解密运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param rawKey 密钥内容缓冲区指针
 * @param uiAlgID 算法标识，指定对称解密算法
 * @param pucIV 缓冲区指针，用于存放输入和返回的IV数据
 * @param pucEncData 缓冲区指针，用于存放输入的数据密文
 * @param uiEncDataLength 输入的数据密文长度
 * @param pucData 缓冲区指针，用于存放输出的数据明文
 * @param puiDataLength 输出的数据明文长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_DecryptWithRawKey(
    sdf_handle_t hSessionHandle, sdf_uint8_t *rawKey, sdf_uint32_t uiAlgID,
    sdf_uint8_t *pucIV, sdf_uint8_t *pucEncData, sdf_uint32_t uiEncDataLength,
    sdf_uint8_t *pucData, sdf_uint32_t *puiDataLength);

/**
 * @brief 计算MAC:使用指定的密钥句柄和IV对数据进行MAC运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param hKeyHandle 指定的密钥句柄
 * @param uiAlgID 算法标识，指定MAC加密算法
 * @param pucIV 缓冲区指针，用于存放输入和返回的IV数据
 * @param pucData 缓冲区指针，用于存放输入的数据明文
 * @param uiDataLength 输入的数据明文长度
 * @param pucMAC 缓冲区指针，用于存放输出的MAC值
 * @param puiMACLength  输出的MAC值长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_CalculateMAC(
    sdf_handle_t hSessionHandle, sdf_handle_t hKeyHandle, sdf_uint32_t uiAlgID,
    sdf_uint8_t *pucIV, sdf_uint8_t *pucData, sdf_uint32_t uiDataLength,
    sdf_uint8_t *pucMAC, sdf_uint32_t *puiMACLength);

// 杂凑运算函数

/**
 * @brief 杂凑运算初始化:三步式数据杂凑运算第一步
 * @param hSessionHandle 与设备建立的会话句柄
 * @param uiAlgID 指定杂凑算法标识
 * @param pucPublicKey 签名者公钥，当uiAlgID为SGD_SM3时有效
 * @param pucID 签名者的ID值，当uiAlgID为SGD_SM3时有效
 * @param uiIDLength 签名者的ID的长度，当uiAlgID为SGD_SM3时有效
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_HashInit(sdf_handle_t hSessionHandle,
                                     sdf_uint32_t uiAlgID,
                                     ECCrefPublicKey *pucPublicKey,
                                     sdf_uint8_t *pucID,
                                     sdf_uint32_t uiIDLength);

/**
 * @brief 多包杂凑运算:三步式数据杂凑运算第二步，对输入的明文进行杂凑运算
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucData 缓冲区指针，用于存放输入的数据明文
 * @param uiDataLength 输入的数据明文长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_HashUpdate(sdf_handle_t hSessionHandle,
                                       sdf_uint8_t *pucData,
                                       sdf_uint32_t uiDataLength);

/**
 * @brief
 * 杂凑运算结束:三步式数据杂凑运算第三步，杂凑运算结束返回杂凑数据并清除中间数据
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucHash 缓冲区指针，用于存放输出的杂凑数据
 * @param puiHashLength 输出的杂凑数据长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_HashFinal(sdf_handle_t hSessionHandle,
                                      sdf_uint8_t *pucHash,
                                      sdf_uint32_t *puiHashLength);

//用户文件操作函数

/**
 * @brief 创建文件:在密码设备内部创建用于存储用户数据的文件
 * @param hSessionHandle
 * @param pucFileName
 * @param uiNameLen
 * @param uiFileSize
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_CreateFile(sdf_handle_t hSessionHandle,
                                       sdf_uint8_t *pucFileName,
                                       sdf_uint32_t uiNameLen,
                                       sdf_uint32_t uiFileSize);

/**
 * @brief 读取文件:读取密码设备内部存储的用户数据文件的内容
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucFileName 缓冲区指针，用于存放输入的文件名，最大长度128字节
 * @param uiNameLen 文件名长度
 * @param uiOffset 指定读取文件时的偏移值
 * @param puiReadLength
 * 入参时指定读取文件内容的长度；出参时返回实际读取文件内容的长度
 * @param pucBuffer 缓冲区指针，用于存放读取的文件数据
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_ReadFile(sdf_handle_t hSessionHandle,
                                     sdf_uint8_t *pucFileName,
                                     sdf_uint32_t uiNameLen,
                                     sdf_uint32_t uiOffset,
                                     sdf_uint32_t *puiReadLength,
                                     sdf_uint8_t *pucBuffer);

/**
 * @brief 写入文件：向密码设备内部存储用户数据的文件中写入内容
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucFileName 缓冲区指针，用于存放输入的文件名，最大长度128字节
 * @param uiNameLen 文件名长度
 * @param uiOffset 指定写入文件时的偏移值
 * @param uiWriteLength 指定写入文件内容的长度
 * @param pucBuffer 缓冲区指针，用于存放输入的写文件数据
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_WriteFile(sdf_handle_t hSessionHandle,
                                      sdf_uint8_t *pucFileName,
                                      sdf_uint32_t uiNameLen,
                                      sdf_uint32_t uiOffset,
                                      sdf_uint32_t uiWriteLength,
                                      sdf_uint8_t *pucBuffer);

/**
 * @brief 删除文件：删除指定文件名的密码设备内部存储用户数据的文件
 * @param hSessionHandle 与设备建立的会话句柄
 * @param pucFileName 缓冲区指针，用于存放输入的文件名，最大长度128字节
 * @param uiNameLen 文件名长度
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_DeleteFile(sdf_handle_t hSessionHandle,
                                       sdf_uint8_t *pucFileName,
                                       sdf_uint32_t uiNameLen);
/**
 * @brief
 * 生成会话密钥并用内部RSA公钥加密输出:生成会话密钥并用指定索引的内部加密公钥加密输出，同时返回密钥句柄
 * @param hSessionHandle 与设备建立的会话句柄
 * @param keyIndex 内部密钥索引
 * @param phKeyHandle 返回的密钥句柄
 *  @return 程序执行成功与否
 *      @retval 0 成功
 *      @retval 非0 失败，返回错误码
 */
SDF_EXPORT sdf_return_t SDF_GetSymmetricKeyHandle(sdf_handle_t hSessionHandle,
                                                  sdf_uint32_t keyIndex,
                                                  sdf_handle_t *phKeyHandle);

SDF_EXPORT void ndsec_sdf_context_release();

#ifdef __cplusplus
}
#endif

#endif // _NDSEC_SDF_HEADER_H_

