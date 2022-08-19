package encrypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class MD5 {

    public static String toBase64(String src) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] digest = md5.digest(src.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(digest);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    public static String toHex(String src) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            byte[] digest = md5.digest(src.getBytes(StandardCharsets.UTF_8));
            return Hex.encodeToString(digest);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

}
