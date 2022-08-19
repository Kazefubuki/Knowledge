package encrypt;

import com.google.common.collect.Maps;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

/**
 * @author cheche
 */
public class RSA {

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private EncryptEnum.AlgorithmEnum cipherAlgorithm;

        private String publicKey;

        private String privateKey;

        private EncryptEnum.SignAlgorithmEnum signAlgorithm;

        private Builder() {
        }

        public Builder publicKey(String publicKey) {
            this.publicKey = publicKey;
            return this;
        }

        public Builder privateKey(String privateKey) {
            this.privateKey = privateKey;
            return this;
        }

        public Builder cipherAlgorithm(EncryptEnum.AlgorithmEnum cipherAlgorithm) {
            this.cipherAlgorithm = cipherAlgorithm;
            return this;
        }

        public Builder signAlgorithm(EncryptEnum.SignAlgorithmEnum signAlgorithm) {
            this.signAlgorithm = signAlgorithm;
            return this;
        }

        public RSA build() throws Exception {
            return new RSA(cipherAlgorithm, publicKey, privateKey, signAlgorithm);
        }
    }

    /**
     * 加密算法
     */
    private final String cipherAlgorithm;

    /**
     * 公钥
     */
    private final String publicKey;

    /**
     * 私钥
     */
    private final String privateKey;

    /**
     * KeyFactory 算法
     */
    private final String keyAlgorithm;

    /**
     * 签名算法
     */
    private String signAlgorithm;


    private RSA(EncryptEnum.AlgorithmEnum encryptAlgorithm, String publicKey, String privateKey,
                EncryptEnum.SignAlgorithmEnum signAlgorithm) throws Exception {
        if (null == encryptAlgorithm) {
            throw new Exception("加密算法不能为空");
        }

        String algorithm = encryptAlgorithm.getAlgorithm();
        this.keyAlgorithm = algorithm.split("/")[0];
        this.cipherAlgorithm = algorithm;
        this.publicKey = publicKey;
        this.privateKey = privateKey;
        if (null != signAlgorithm) {
            this.signAlgorithm = signAlgorithm.getValue();
        }
    }

    /**
     * 加密
     *
     * @param srcBytes 待加密字节数组
     * @return 加密后的字符串
     */
    public String encrypt(byte[] srcBytes) throws Exception {
        PublicKey key = getPublicKey();
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        int maxEncryptBlock = ((RSAPublicKey) key).getModulus().bitLength() / 8 - 11;
        byte[] encryptBytes = doFinal(srcBytes, cipher, maxEncryptBlock);
        return Base64.getEncoder().encodeToString(encryptBytes);
    }

    /**
     * 加密
     *
     * @param src 待加密字符串
     * @return 加密后的字符串
     */
    public String encrypt(String src) throws Exception {
        return encrypt(src.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 解密
     *
     * @param srcBytes 待解密字节数组
     * @return 解密后的字符串
     */
    public String decrypt(byte[] srcBytes) throws Exception {
        PrivateKey key = getPrivateKey();
        Cipher cipher = Cipher.getInstance(cipherAlgorithm);
        cipher.init(Cipher.DECRYPT_MODE, key);

        int maxDecryptBlock = ((RSAPrivateKey) key).getModulus().bitLength() / 8;
        return new String(doFinal(srcBytes, cipher, maxDecryptBlock));
    }

    /**
     * 解密
     *
     * @param src 待解密字符串
     * @return 解密后的字符串
     */
    public String decrypt(String src) throws Exception {
        return decrypt(Base64.getDecoder().decode(src));
    }

    private byte[] doFinal(byte[] bytes, Cipher cipher, int maxBlockSize) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buffer;
        int blockSize;
        while ((blockSize = bytes.length - offSet) > 0) {
            buffer = cipher.doFinal(bytes, offSet, Math.min(blockSize, maxBlockSize));
            offSet += maxBlockSize;
            baos.write(buffer, 0, buffer.length);
        }

        return baos.toByteArray();
    }

    /**
     * 加签
     *
     * @param srcBytes 待签名字节数组
     * @return 签名字符串
     */
    public String sign(byte[] srcBytes) throws Exception {
        PrivateKey sk = getPrivateKey();
        Signature signature = Signature.getInstance(signAlgorithm);
        signature.initSign(sk);
        signature.update(srcBytes);
        byte[] signBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signBytes);
    }

    /**
     * 加签
     *
     * @param src 待签名字符串
     * @return 签名
     */
    public String sign(String src) throws Exception {
        return sign(src.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 验签
     *
     * @param srcBytes  待验签字节数组
     * @param signBytes 签名字节数组
     * @return boolean 是否通过验证
     */
    public boolean verify(byte[] srcBytes, byte[] signBytes) throws Exception {
        if (null == signAlgorithm || signAlgorithm.isEmpty()) {
            throw new Exception("签名算法不能为空");
        }

        PublicKey pk = getPublicKey();
        Signature signature = Signature.getInstance(signAlgorithm);
        signature.initVerify(pk);
        signature.update(srcBytes);
        return signature.verify(signBytes);
    }

    /**
     * 验签
     *
     * @param src  待验签内容
     * @param sign 签名
     * @return boolean 是否验证通过
     */
    public boolean verify(String src, String sign) throws Exception {
        byte[] srcBytes = src.getBytes(StandardCharsets.UTF_8);
        byte[] signBytes = Base64.getDecoder().decode(sign);
        return verify(srcBytes, signBytes);
    }

    private PublicKey getPublicKey() throws Exception {
        if (null == publicKey || publicKey.isEmpty()) {
            throw new Exception("公钥不能为空");
        }

        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    private PrivateKey getPrivateKey() throws Exception {
        if (null == privateKey || privateKey.isEmpty()) {
            throw new Exception("私钥不能为空");
        }

        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 生成密钥
     *
     * @param keySize 密钥生成长度
     * @return [ PK='...', SK='...']
     */
    public Map<String, String> generateKey(int keySize, String seed, EncryptEnum.RandomAlgorithmEnum randomAlgorithm)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(keyAlgorithm);
        SecureRandom secureRandom = new SecureRandom();
        if (null != randomAlgorithm) {
            secureRandom = SecureRandom.getInstance(randomAlgorithm.getRandomAlgorithm());
        }

        if (StringUtils.isNotBlank(seed)) {
            secureRandom.setSeed(seed.getBytes(StandardCharsets.UTF_8));
        }

        generator.initialize(keySize, secureRandom);
        KeyPair keyPair = generator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        Map<String, String> keyMap = Maps.newHashMap();
        keyMap.put("publicKey", Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        keyMap.put("privateKey", Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        return keyMap;
    }

}
