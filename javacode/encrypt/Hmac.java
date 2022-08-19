package encrypt;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Objects;

public class Hmac {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private EncryptEnum.HmacAlgorithmEnum algorithm;

        private String key;

        private EncryptEnum.KeyFormatEnum keyFormat;

        private EncryptEnum.KeyFormatEnum encryptFormat;

        private Builder() {}

        public Builder algorithm(EncryptEnum.HmacAlgorithmEnum algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder key(String key) {
            this.key = key;
            return this;
        }

        public Builder keyFormat(EncryptEnum.KeyFormatEnum keyFormat) {
            this.keyFormat = keyFormat;
            return this;
        }

        public Builder encryptFormat(EncryptEnum.KeyFormatEnum encryptFormat) {
            this.encryptFormat = encryptFormat;
            return this;
        }

        public Hmac build() throws Exception {
            return new Hmac(algorithm, key, keyFormat, encryptFormat);
        }
    }

    private final String algorithm;

    private final String key;

    private final EncryptEnum.KeyFormatEnum keyFormat;

    private final EncryptEnum.KeyFormatEnum encodeFormat;

    public Hmac(EncryptEnum.HmacAlgorithmEnum algorithm, String key, EncryptEnum.KeyFormatEnum keyFormat, EncryptEnum.KeyFormatEnum encryptFormat) throws Exception {

        if (Objects.isNull(algorithm)) {
            throw new Exception("Hmac 加密算法不能为空");
        }

        this.algorithm = algorithm.getAlgorithm();
        if (Objects.isNull(key) || key.isEmpty()) {
            throw new Exception("密钥 key 不能为空");
        }

        this.key = key;
        this.keyFormat = keyFormat;
        this.encodeFormat = encryptFormat;
    }

    /**
     * 加密
     *
     * @param src 待加密字符串
     * @return 加密后的字符串
     */
    public String encode(String src) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec(getKeyBytes(key), algorithm);
        Mac hmacMd5 = Mac.getInstance(algorithm);
        hmacMd5.init(secretKeySpec);
        hmacMd5.update(src.getBytes(StandardCharsets.UTF_8));
        byte[] encodedBytes = hmacMd5.doFinal();
        switch (encodeFormat) {
            case Hex:
                return Hex.encodeToString(encodedBytes);
            case Base64:
            default:
                return Base64.getEncoder().encodeToString(encodedBytes);
        }
    }

    private byte[] getKeyBytes(String key) throws Exception {
        byte[] keyBytes;
        switch (keyFormat) {
            case Hex:
                keyBytes = Hex.decode(key);
                break;
            case Base64:
                keyBytes = Base64.getDecoder().decode(key);
                break;
            default:
                keyBytes = key.getBytes(StandardCharsets.UTF_8);
                break;
        }

        return keyBytes;
    }

}
