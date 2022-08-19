package encrypt;

/**
 * @author cheche
 */
public class EncryptEnum {

    public enum AlgorithmEnum {

        /**
         * 加密算法枚举
         */
        RSA("RSA"),
        RSA_ECB_PKCS1PADDING("RSA/ECB/PKCS1Padding"),

        DES("DES"),
        DES_EBC_PKCS7Padding("DES/ECB/PKCS7Padding"),
        DES_EBC_PKCS5Padding("DES/ECB/PKCS5Padding"),
        DES_CBC_PKCS5Padding("DES/CBC/PKCS5Padding"),
        DES_CBC_PKCS7Padding("DES/CBC/PKCS7Padding"),
        DESEDE_CBC_PKCS5Padding("DESEDE/CBC/PKCS5Padding"),

        AES("AES"),
        AES_CBC_PKCS5Padding("AES/CBC/PKCS5Padding"),
        AES_CBC_PKCS7Padding("AES/CBC/PKCS7Padding");

        String algorithm;

        AlgorithmEnum(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }

    public enum KeyFormatEnum {

        /**
         *  Key类型
         */
        UTF_8("UTF-8"),
        Base64("Base64"),
        Hex("Hex");

        String keyFormat;

        KeyFormatEnum(String keyFormat) {
            this.keyFormat = keyFormat;
        }

        public String getKeyFormat() {
            return keyFormat;
        }
    }

    public enum IvKeyFormatEnum {

        /**
         *  IvKey类型
         */
        UTF_8("UTF-8"),
        Base64("Base64"),
        Hex("Hex");

        String ivKeyFormat;

        IvKeyFormatEnum(String ivKeyFormat) {
            this.ivKeyFormat = ivKeyFormat;
        }

        public String getIvKeyFormat() {
            return ivKeyFormat;
        }

    }

    public enum SignAlgorithmEnum {

        /**
         * 签名算法枚举
         */
        MD5withRSA("MD5withRSA"),
        SHA1WithRSA("SHA1WithRSA"),
        SHA256WithRSA("SHA256WithRSA");

        private final String value;

        SignAlgorithmEnum(String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }

    public enum HmacAlgorithmEnum {

        /**
         * Hmac加密算法枚举
         */
        HMAC_MD5("HmacMd5"),
        HMAC_SHA256("HmacSHA256"),
        HMAC_SHA1("HmacSHA1");
        String algorithm;

        HmacAlgorithmEnum(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getAlgorithm() {
            return algorithm;
        }
    }

    public enum RandomAlgorithmEnum {

        /**
         * 密钥算法
         */
        SHA1PRNG("SHA1PRNG"),
        WINDOWS_PRNG("Windows-PRNG"),
        DEFAULT("DEFAULT"),
        NATIVEPRNG("nativePRNG"),
        NONCEANDIV("NONCEANDIV");

        String secureRandomAlgorithm;

        RandomAlgorithmEnum(String randomAlgorithmEnum) {
            this.secureRandomAlgorithm = randomAlgorithmEnum;
        }

        public String getRandomAlgorithm() {
            return secureRandomAlgorithm;
        }
    }
}
