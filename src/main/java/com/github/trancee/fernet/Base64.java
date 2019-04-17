package com.github.trancee.fernet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/**
 * Base64 implementation based on Emil Hernvall.
 * https://gist.github.com/EmilHernvall/953733
 */

public final class Base64 {
    static class Options {
        static int NONE = 0;
        static int NO_PADDING = 1;
        static int URL_SAFE = 2;
        static int CHUNKING = 4;
    }

    /**
     * Chunk size per RFC 2045 section 6.8.
     *
     * <p>
     * The {@value} character limit does not count the trailing CRLF, but counts all
     * other characters, including any equal signs.
     * </p>
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 6.8</a>
     */
    static final int CHUNK_SIZE = 76;

    /**
     * Chunk separator per RFC 2045 section 2.1.
     *
     * <p>
     * N.B. The next major release may break compatibility and make this field
     * private.
     * </p>
     *
     * @see <a href="http://www.ietf.org/rfc/rfc2045.txt">RFC 2045 section 2.1</a>
     */
    static final char[] CHUNK_SEPARATOR = { '\r', '\n' };

    private static final char[] BASE64_ENCODING_TABLE = { //
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', //
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', //
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', //
            'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', //
    };

    public static String encodeUrlSafe(byte[] data) {
        return encode(data, Options.URL_SAFE);
    }

    public static String encode(byte[] data) {
        return encode(data, Options.NONE);
    }

    public static String encode(byte[] data, int options) {
        if (data == null) {
            return null;
        }

        StringBuilder buffer = new StringBuilder();

        int pad = 0, chunk = 0;

        for (int i = 0; i < data.length; i += 3) {
            int b = ((data[i] & 0xFF) << 16) & 0xFFFFFF;

            if (i + 1 < data.length) {
                b |= (data[i + 1] & 0xFF) << 8;
            } else {
                pad++;
            }
            if (i + 2 < data.length) {
                b |= (data[i + 2] & 0xFF);
            } else {
                pad++;
            }

            for (int j = 0; j < 4 - pad; j++) {
                int c = (b & 0xFC0000) >> 18;
                b <<= 6;

                if ((options & Options.CHUNKING) != 0
                        && ((buffer.length() - (chunk * CHUNK_SEPARATOR.length)) % CHUNK_SIZE) == 0
                        && buffer.length() > 0) {
                    buffer.append(CHUNK_SEPARATOR);
                    chunk++;
                }

                buffer.append(BASE64_ENCODING_TABLE[c]);
            }
        }

        if (!((options & Options.NO_PADDING) != 0 || (options & Options.URL_SAFE) != 0) && pad > 0) {
            for (int j = 0; j < pad; j++) {
                buffer.append("=");
            }
        }

        if ((options & Options.CHUNKING) != 0) {
            buffer.append(CHUNK_SEPARATOR);
        }

        String encoded = buffer.toString();

        if ((options & Options.URL_SAFE) != 0) {
            encoded = encoded.replace('+', '-').replace('/', '_');
        }

        return encoded;
    }

    private static final byte[] BASE64_DECODING_TABLE = { //
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 00-0F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 10-1F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63, // 20-2F
            52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, // 30-3F
            -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, // 40-4F
            15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, // 50-5F
            -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 60-6F
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1, // 70-7F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80-8F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 90-9F
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // A0-AF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // B0-BF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // C0-CF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // D0-DF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // E0-EF
            -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // F0-FF
    };

    public static byte[] decodeUrlSafe(String data) {
        return decode(data, Options.URL_SAFE);
    }

    public static byte[] decode(String data) {
        return decode(data, Options.NONE);
    }

    public static byte[] decode(String data, int options) {
        if (data == null) {
            return null;
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        // Remove all whitespaces.
        data = data.replaceAll("\\s", "");

        int len = data.indexOf('=');
        if (len != -1) {
            data = data.substring(0, len);
        }

        byte[] bytes = data.getBytes(StandardCharsets.US_ASCII);

        for (int i = 0; i < bytes.length;) {
            int b = 0, num = 0;

            for (; i < bytes.length && num < 4; i++) {
                if (BASE64_DECODING_TABLE[bytes[i]] != -1) {
                    b |= (BASE64_DECODING_TABLE[bytes[i]] & 0xFF) << (18 - (num * 6));
                    num++;
                }
            }

            while (--num > 0) {
                int c = (b & 0xFF0000) >> 16;
                b <<= 8;

                buffer.write((char) c);
            }
        }

        return buffer.toByteArray();
    }

    private static String toHex(byte[] bytes) {
        final char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars).toLowerCase();
    }
}
