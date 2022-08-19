package encrypt;

import java.nio.charset.StandardCharsets;

public class Hex {

    public static String encodeToString(byte[] src) {
        StringBuilder sb = new StringBuilder();
        for (byte b : src) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    public static String encodeToString(String src) {
        return encodeToString(src.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] decode(String src) throws Exception {
        char[] charArray = src.toCharArray();
        int len = src.length();
        byte[] bytes = new byte[len >> 1];
        for (int i = 0, j = 0; j < len; i++) {
            int f = toDigit(charArray[j], j) << 4;
            j++;
            f = f | toDigit(charArray[j], j);
            j++;
            bytes[i] = (byte) (f & 0xFF);
        }

        return bytes;
    }

    private static int toDigit(final char ch, final int index) throws Exception {
        final int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new Exception("Illegal hexadecimal character " + ch + " at index " + index);
        }

        return digit;
    }

}
