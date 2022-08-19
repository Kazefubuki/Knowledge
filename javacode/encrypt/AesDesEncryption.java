package encrypt;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Provider;
import java.security.Security;
import java.util.Base64;

/**
 * @author cheche
 */
public class AesDesEncryption {

    public static Builder builder() {
        return new Builder();
    }

    /**
     * key 对称加密密钥
     */
    private final String key;

    /**
     * keyType 密钥类型
     */
    private final String keyFormat;

    /**
     * ivKey 偏移量
     */
    private final String ivKey;

    /**
     * ivKeyFormat 偏移量类型
     */
    private final EncryptEnum.IvKeyFormatEnum ivKeyFormat;

    /**
     * algorithm 加密算法
     */
    private final String cipherAlgorithm;

    /**
     * algorithmMethod 加密类型
     */
    private final String keyAlgorithm;


    /**
     * 内部类
     */
    public static class Builder {

        /**
         * 加密key
         */
        private String key;

        /**
         * keyFormat 密钥类型
         */
        private EncryptEnum.KeyFormatEnum keyFormat;

        /**
         * 加密ivKey
         */
        private String ivKey;

        /**
         * ivKeyFormat 偏移量类型
         */
        private EncryptEnum.IvKeyFormatEnum ivKeyFormat;

        /**
         * cipherAlgorithm加密算法
         */
        private String cipherAlgorithm;


        private Builder() {}

        public Builder key(String key) {
            this.key = key;
            return this;
        }

        public Builder keyFormat(EncryptEnum.KeyFormatEnum keyFormat) {
            this.keyFormat = keyFormat;
            return this;
        }

        public Builder ivKey(String ivKey) {
            this.ivKey = ivKey;
            return this;
        }

        public Builder ivKeyFormat(EncryptEnum.IvKeyFormatEnum ivKeyFormat) {
            this.ivKeyFormat = ivKeyFormat;
            return this;
        }

        public Builder cipherAlgorithm(EncryptEnum.AlgorithmEnum cipherAlgorithm) {
            this.cipherAlgorithm = cipherAlgorithm.getAlgorithm();
            return this;
        }

        public AesDesEncryption build() throws Exception {
            if (key == null || key.isEmpty() || keyFormat == null || cipherAlgorithm == null || cipherAlgorithm.isEmpty()) {
                throw new Exception("KEY、密钥类型(keyFormat)、加密算法(cipherAlgorithm)、不允许为空");
            }

            if (ivKey != null && !ivKey.isEmpty() && ivKey.length() < 8) {
                throw new Exception("ivKey长度小于8");
            }

            if (ivKey != null && !ivKey.isEmpty() && ivKeyFormat == null) {
                throw new Exception("ivKey存在时, ivKeyFormat不能为空");
            }

            if (ivKeyFormat != null && (ivKey == null || ivKey.isEmpty())) {
                throw new Exception("ivKeyFormat存在时, ivKey不能为空");
            }

            String[] algorithmSplit = cipherAlgorithm.split("/");
            if (algorithmSplit.length > 1 && "CBC".equals(algorithmSplit[1]) && ivKey == null) {
                throw new Exception("加密模式选择CBC时， ivKey不允许为空");
            }

            if (algorithmSplit.length > 1 && "PKCS7Padding".equals(algorithmSplit[2])) {
                Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
                if (provider == null) {
                    Security.addProvider(new BouncyCastleProvider());
                }
            }
            return new AesDesEncryption(key, keyFormat, ivKey, ivKeyFormat, cipherAlgorithm);
        }
    }

    AesDesEncryption(String key, EncryptEnum.KeyFormatEnum keyFormat,
                     String ivKey, EncryptEnum.IvKeyFormatEnum ivKeyFormat, String algorithm) {
        this.key = key;
        this.keyFormat = keyFormat.getKeyFormat();
        this.ivKey = ivKey;
        this.ivKeyFormat = ivKeyFormat;
        this.cipherAlgorithm = algorithm;
        this.keyAlgorithm = algorithm.split("/")[0];
    }

    public String encrypt(byte[] bytes) throws Exception {
        Cipher cipher = initCipher(Cipher.ENCRYPT_MODE, key, ivKey, cipherAlgorithm, keyAlgorithm);
        return Base64.getEncoder().encodeToString(cipher.doFinal(bytes));
    }

    public String encrypt(String input) throws Exception {
        return encrypt(input.getBytes(StandardCharsets.UTF_8));
    }

    public String decrypt(String input) throws Exception {
        return decrypt(Base64.getDecoder().decode(input));
    }

    public String decrypt(byte[] bytes) throws Exception {
        Cipher cipher = initCipher(Cipher.DECRYPT_MODE, key, ivKey,cipherAlgorithm, keyAlgorithm);
        return new String(cipher.doFinal(bytes), StandardCharsets.UTF_8);
    }

    private Cipher initCipher(int type, String key, String ivKey, String algorithm, String algorithmMethod) throws Exception {

        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec secretKeySpec = new SecretKeySpec(getBytes(key, keyFormat), algorithmMethod);

        if (null == ivKey || ivKey.isEmpty()) {
            cipher.init(type, secretKeySpec);
        } else {
            IvParameterSpec iv = new IvParameterSpec(getBytes(ivKey, ivKeyFormat.getIvKeyFormat()));
            cipher.init(type, secretKeySpec, iv);
        }

        return cipher;
    }

    private byte[] getBytes(String key, String type) throws Exception {
        byte[] keyBytes;
        switch (type) {
            case "Hex":
                keyBytes = Hex.decode(key);
                break;
            case "Base64":
                keyBytes = Base64.getDecoder().decode(key);
                break;
            default:
                keyBytes = key.getBytes(StandardCharsets.UTF_8);
                break;
        }
        return keyBytes;
    }
}




