
# 加密类说明

## 1.RSA 类说明

### 参数说明

|字段              |描述      |类型     |是否必传        |
|:----------------|:--------|:-------|:-------------|
|publicKey        |公钥      |String  |加密必传        |
|privateKey       |私钥      |String  |解密必传        |
|encryptAlgorithm |加密算法   |枚举    |加密、解密必传    |
|signAlgorithm    |加签算法   |枚举    |加签、验签必传    |

### 使用示例

``` Java
RSA build = RSA.builder()
	    .cipherAlgorithm(EncryptEnum.AlgorithmEnum.RSA) 
	    .publicKey(传入你的公钥) 
	    .privateKey(传入你的私钥) 
	    .build();
String encryptResult = build.encrypt("这是一段需要加密的内容"); // 加密
String decryptResult = build.decrypt("这是一段需要解密的内容"); // 解密
```

### 加密解密结果输出

需`加密`内容的类型支持 `字符串` 和 `byte数组` 两种类型 返回内容为`base64`格式字符串

需`解密`内容的类型支持 `字符串` 和` byte数组` 两种类型 返回内容为字符串

### 加签验签使用示例

``` Java
RSA build = RSA.builder()
    .signAlgorithm(EncryptEnum.SignAlgorithmEnum.SHA256WithRSA)
    .privateKey(传入你的私钥)
    .build();
String signResult = build.sign(需签名内容); // 加签
boolean verifyResult = build.verify(需验签内容, 签名); // 验签
```

### 加签验签结果输出

需`签名`内容的类型支持 `字符串` 和` byte数组` 两种类型 返回内容为`base64`格式字符串

需`解密`内容的类型支持 `字符串` 和 `byte数组` 两种类型 返回内容为 `boolean` 类型

### 生成密钥使用示例

参数说明：

|            字段       |描述         |类型    |是否必传  |
|:---------------------|:------------|:------|:-------|
|keySize               |密钥长度       |int    |必传    |
|seed                  |密钥seed      |String |非必传   |
|RandomAlgorithmEnum   |随机数生成算法  |枚举    |非必传   |

keySize: 在 `512bits`和 `16384bits`之间

seed: String类型，指定 seed 会使每次生成的密钥都一致

RandomAlgorithmEnum : 生成随机数的算法，具体可看实现的枚举

使用方法：

``` Java
Map<String, String> stringStringMap = rsaUtil.generateKey(512, "123", "SHA1PRNG");
System.out.println(stringStringMap.get("publicKey"));
System.out.println(stringStringMap.get("privateKey"));
```

## 2.AesDesEncryption 说明

### 参数说明

|字段        |描述        |类型   |是否必传         |
|:----------|:-----------|:-----|:---------------|
|key        |对称加密key  |String |必传            |
|keyFormat  |key的类型    |枚举   |必传             |
|algorithm  |加密算法     |枚举    |必传            |
|ivKey      |对称加密ivKey|String |非必传           |
|ivKeyFormat|ivKet的类型  |枚举   |非必传           |

### 使用示例

``` Java
AesDesEncryption build = AesDesEncryption.builder()
    .key(传入你的密钥)
    .keyFormat(EncryptEnum.KeyFormatEnum.Base64)
    .ivKey(传入你的偏移量)
    .ivKeyFormat(EncryptEnum.IvKeyFormatEnum.Base64)
    .cipherAlgorithm(EncryptEnum.AlgorithmEnum.DES_EBC_PKCS5Padding)    
    .build();
String encryptResult = build.encrypt("这是一段需要加密的内容"); // 加密
String decryptResult = build.decrypt("这是一段需要解密的内容"); // 解密
```

### 加密解密结果输出

需`加密`内容的类型支持 `字符串` 和` byte数组` 两种类型 返回内容为【base64】格式字符串

需`解密`内容的类型支持 `字符串` 和 `byte数组` 两种类型 返回内容为字符串

## 3.Hmac 说明

### 参数说明

|字段          |描述         |类型    |是否必传|
|:------------|:------------|:------|:-----|
|key          |对称加密key   |String  |必传   |
|keyFormat    |key的类型     |枚举    |必传   |
|algorithm    |加密算法      |枚举    |必传   |
|encryptFormat|输出格式      |枚举    |必传   |

### 使用示例

``` Java
Hmac build = Hmac.builder()
    .key("chechechangjiang")
    .keyFormat(EncryptEnum.KeyFormatEnum.Base64)
    .algorithm(EncryptEnum.HmacAlgorithmEnum.HMAC_MD5)
    .encryptFormat(EncryptEnum.KeyFormatEnum.Base64)
    .build();
String encryptResult = build.encode("这是一段需要加密的内容"); // 加密
```

### 结果输出

需`加密`内容的类型仅支持 `字符串`格式

返回内容支持 `Hex`和 `Base64`

## 4.MD5 说明

### MD5 支持两种格式，`Base64` 和 `Hex`

### 使用示例

```
String md5Result = MD5.toHex("这是一段测试的文本。 This is a test text");
String md5Result = MD5.toBase64("这是一段测试的文本。 This is a test text");
```

两个方法均为静态方法，可以使用类名直接访问

###输出结果

`MD5.toHex()`输出结果为`16进制字符串`

`MD5.toBase64()`输出结果为`Base64格式字符串`

## 5.Hex 说明

### Hex 类提供`加密`和`解密`两种方法

加密支持`byte数组`和`String`类型

输出类型为`String`

解密仅支持`String`类型

输出类型为`byte数组`

###使用示例

``` Java
String hexResult = Hex.encodeToString("这是一段测试文本");

byte[] bytes = "这是一段测试文本".getBytes(StandardCharsets.UTF_8);
String hexResult = Hex.encodeToString(bytes);

byte[] decodeResult = Hex.decode("e8bf99e698afe4b880e6aeb5e6b58be8af95e69687e69cac");
```

## 6.EncryptEnum 枚举类说明

|枚举名            |描述         |
|:----------------|:-----------|
|KeyFormatEnum    |  key类型    |
|IvKeyFormatEnum  |  ivKey类型  |
|AlgorithmEnum    |  加密算法    |
|SignAlgorithmEnum|  加签算法    |
|HmacAlgorithmEnum|  加密算法    |

其中

key类型分为 `十六进制(Hex)`、`base64`和`明文类型`

ivKey同理

`AlgorithmEnum` 为 `对称加密` 和 `非对称加密` 的枚举，加密解密必传

`SignAlgorithmEnum` 为`加签`、`验签`枚举，加签及验签必传

`HmacAlgorithmEnum` 为`摘要算法`枚举