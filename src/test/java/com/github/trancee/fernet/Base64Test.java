package com.github.trancee.fernet;

import static org.junit.Assert.assertArrayEquals;

import java.nio.charset.StandardCharsets;
import java.util.Random;

import com.github.trancee.fernet.Base64.Options;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for Base64 implementation.
 */
public class Base64Test extends TestCase {
    private final Random random = new Random();

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public Base64Test(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(Base64Test.class);
    }

    /**
     * Test the Base64 implementation
     */
    public void testBase64TestCase1() {
        byte[] original = new byte[] { 0, 1, 2, 3, 64, 99, 127, -128, -77 };
        String encoded = Base64.encode(original);
        byte[] decoded = Base64.decode(encoded);
        assertArrayEquals(decoded, original);
    }

    public void testBase64TestCase2() {
        byte[] original = new byte[] { 1, 2, 4, 8, 16, 32, 64, 0 };
        String encoded = Base64.encode(original);
        byte[] decoded = Base64.decode(encoded);
        assertArrayEquals(decoded, original);
    }

    public void testBase64TestCase3() {
        byte[] original = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 1, 2 };
        String encoded = "AAAAAAAAAAABAg==";
        byte[] decoded = Base64.decode(encoded);
        assertArrayEquals(decoded, original);
    }

    public void testBase64() {
        final String content = "Hello World";
        String encodedContent = Base64.encode(content.getBytes(StandardCharsets.UTF_8));
        assertEquals("encoding hello world", "SGVsbG8gV29ybGQ=", encodedContent);

        encodedContent = Base64.encode(content.getBytes(StandardCharsets.UTF_8), Options.CHUNKING);
        assertEquals("encoding hello world", "SGVsbG8gV29ybGQ=\r\n", encodedContent);

        encodedContent = Base64.encode(content.getBytes(StandardCharsets.UTF_8), Options.NONE);
        assertEquals("encoding hello world", "SGVsbG8gV29ybGQ=", encodedContent);

        // bogus characters to decode (to skip actually) {e-acute*6}
        final byte[] decode = Base64.decode("SGVsbG{\u00e9\u00e9\u00e9\u00e9\u00e9\u00e9}8gV29ybGQ=");
        final String decodeString = new String(decode);
        assertEquals("decode hello world", "Hello World", decodeString);
    }

    public void testDecodeWithInnerPad() {
        final String content = "SGVsbG8gV29ybGQ=SGVsbG8gV29ybGQ=";
        final byte[] result = Base64.decode(content);
        final byte[] shouldBe = "Hello World".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals("decode should halt at pad (=)", shouldBe, result);
    }

    public void testDecodePadMarkerIndex2() {
        assertEquals("A", new String(Base64.decode("QQ==")));
    }

    public void testDecodePadMarkerIndex3() {
        assertEquals("AA", new String(Base64.decode("QUE=")));
        assertEquals("AAA", new String(Base64.decode("QUFB")));
    }

    public void testDecodePadOnly() {
        assertEquals(0, Base64.decode("====").length);
        assertEquals("", new String(Base64.decode("====")));

        // Test truncated padding
        assertEquals(0, Base64.decode("===").length);
        assertEquals(0, Base64.decode("==").length);
        assertEquals(0, Base64.decode("=").length);
        assertEquals(0, Base64.decode("").length);
    }

    public void testDecodePadOnlyChunked() {
        assertEquals(0, Base64.decode("====\n").length);
        assertEquals("", new String(Base64.decode("====\n")));

        // Test truncated padding
        assertEquals(0, Base64.decode("===\n").length);
        assertEquals(0, Base64.decode("==\n").length);
        assertEquals(0, Base64.decode("=\n").length);
        assertEquals(0, Base64.decode("\n").length);
    }

    public void testDecodeWithWhitespace() throws Exception {
        final String orig = "I am a late night coder.";

        final String encodedArray = Base64.encode(orig.getBytes(StandardCharsets.UTF_8));
        final StringBuilder intermediate = new StringBuilder(encodedArray);

        intermediate.insert(2, ' ');
        intermediate.insert(5, '\t');
        intermediate.insert(10, '\r');
        intermediate.insert(15, '\n');

        final String encodedWithWS = intermediate.toString();
        final byte[] decodedWithWS = Base64.decode(encodedWithWS);

        final String dest = new String(decodedWithWS);

        assertEquals("Dest string doesn't equal the original", orig, dest);
    }

    public void testEmptyBase64() {
        byte[] empty = new byte[0];
        String result = Base64.encode(empty);
        assertEquals("empty base64 encode", 0, result.length());
        assertEquals("empty base64 encode", null, Base64.encode(null));

        empty = new byte[0];
        byte[] result2 = Base64.decode(new String(empty));
        assertEquals("empty base64 decode", 0, result2.length);
        assertEquals("empty base64 encode", null, Base64.decode(null));
    }

    public void testEncodeDecodeRandom() {
        for (int i = 1; i < 5; i++) {
            final byte[] data = new byte[this.random.nextInt(10000) + 1];
            this.random.nextBytes(data);
            final String enc = Base64.encode(data);
            final byte[] data2 = Base64.decode(enc);
            assertArrayEquals(data, data2);
        }
    }

    public void testEncodeDecodeSmall() {
        for (int i = 0; i < 12; i++) {
            final byte[] data = new byte[i];
            this.random.nextBytes(data);
            final String enc = Base64.encode(data);
            final byte[] data2 = Base64.decode(enc);
            assertArrayEquals(new String(data) + " equals " + new String(data2), data, data2);
        }
    }

    public void testIgnoringNonBase64InDecode() throws Exception {
        assertEquals("The quick brown fox jumped over the lazy dogs.", new String(Base64.decode(
                "VGhlIH@$#$@%F1aWN@#@#@@rIGJyb3duIGZve\n\r\t%#%#%#%CBqd##$#$W1wZWQgb3ZlciB0aGUgbGF6eSBkb2dzLg==")));
    }

    public void testKnownDecodings() {
        assertEquals("The quick brown fox jumped over the lazy dogs.",
                new String(Base64.decode("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2dzLg==")));
        assertEquals("It was the best of times, it was the worst of times.",
                new String(Base64.decode("SXQgd2FzIHRoZSBiZXN0IG9mIHRpbWVzLCBpdCB3YXMgdGhlIHdvcnN0IG9mIHRpbWVzLg==")));
        assertEquals("http://jakarta.apache.org/commmons",
                new String(Base64.decode("aHR0cDovL2pha2FydGEuYXBhY2hlLm9yZy9jb21tbW9ucw==")));
        assertEquals("AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz",
                new String(Base64.decode("QWFCYkNjRGRFZUZmR2dIaElpSmpLa0xsTW1Obk9vUHBRcVJyU3NUdFV1VnZXd1h4WXlaeg==")));
        assertEquals("{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }",
                new String(Base64.decode("eyAwLCAxLCAyLCAzLCA0LCA1LCA2LCA3LCA4LCA5IH0=")));
        assertEquals("xyzzy!", new String(Base64.decode("eHl6enkh")));
    }

    public void testKnownEncodings() {
        assertEquals("VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wZWQgb3ZlciB0aGUgbGF6eSBkb2dzLg==", new String(
                Base64.encode("The quick brown fox jumped over the lazy dogs.".getBytes(StandardCharsets.UTF_8))));

        assertEquals(
                "YmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJs\r\nYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFo\r\nIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBibGFoIGJsYWggYmxhaCBi\r\nbGFoIGJsYWg=\r\n",
                new String(Base64.encode(
                        "blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah blah"
                                .getBytes(StandardCharsets.UTF_8),
                        Options.CHUNKING)));

        assertEquals("SXQgd2FzIHRoZSBiZXN0IG9mIHRpbWVzLCBpdCB3YXMgdGhlIHdvcnN0IG9mIHRpbWVzLg==", new String(Base64
                .encode("It was the best of times, it was the worst of times.".getBytes(StandardCharsets.UTF_8))));
        assertEquals("aHR0cDovL2pha2FydGEuYXBhY2hlLm9yZy9jb21tbW9ucw==",
                new String(Base64.encode("http://jakarta.apache.org/commmons".getBytes(StandardCharsets.UTF_8))));
        assertEquals("QWFCYkNjRGRFZUZmR2dIaElpSmpLa0xsTW1Obk9vUHBRcVJyU3NUdFV1VnZXd1h4WXlaeg==", new String(Base64
                .encode("AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz".getBytes(StandardCharsets.UTF_8))));
        assertEquals("eyAwLCAxLCAyLCAzLCA0LCA1LCA2LCA3LCA4LCA5IH0=",
                new String(Base64.encode("{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 }".getBytes(StandardCharsets.UTF_8))));
        assertEquals("eHl6enkh", new String(Base64.encode("xyzzy!".getBytes(StandardCharsets.UTF_8))));
    }

    public void testObjectEncode() {
        assertEquals("SGVsbG8gV29ybGQ=", new String(Base64.encode("Hello World".getBytes(StandardCharsets.UTF_8))));
    }

    public void testPairs() {
        assertEquals("AAA=", new String(Base64.encode(new byte[] { 0, 0 })));
        for (int i = -128; i <= 127; i++) {
            final byte test[] = { (byte) i, (byte) i };
            assertArrayEquals(test, Base64.decode(Base64.encode(test)));
        }
    }

    /**
     * Tests RFC 2045 section 2.1 CRLF definition.
     */
    public void testRfc2045Section2Dot1CrLfDefinition() {
        assertArrayEquals(new char[] { 13, 10 }, Base64.CHUNK_SEPARATOR);
    }

    /**
     * Tests RFC 2045 section 6.8 chuck size definition.
     */
    public void testRfc2045Section6Dot8ChunkSizeDefinition() {
        assertEquals(76, Base64.CHUNK_SIZE);
    }

    /**
     * Tests RFC 4648 section 10 test vectors.
     * <ul>
     * <li>BASE64("") = ""</li>
     * <li>BASE64("f") = "Zg=="</li>
     * <li>BASE64("fo") = "Zm8="</li>
     * <li>BASE64("foo") = "Zm9v"</li>
     * <li>BASE64("foob") = "Zm9vYg=="</li>
     * <li>BASE64("fooba") = "Zm9vYmE="</li>
     * <li>BASE64("foobar") = "Zm9vYmFy"</li>
     * </ul>
     *
     * @see <a href="http://tools.ietf.org/html/rfc4648">http://tools.ietf.org/
     *      html/rfc4648</a>
     */
    public void testRfc4648Section10Decode() {
        assertEquals("", new String(Base64.decode("")));
        assertEquals("f", new String(Base64.decode("Zg==")));
        assertEquals("fo", new String(Base64.decode("Zm8=")));
        assertEquals("foo", new String(Base64.decode("Zm9v")));
        assertEquals("foob", new String(Base64.decode("Zm9vYg==")));
        assertEquals("fooba", new String(Base64.decode("Zm9vYmE=")));
        assertEquals("foobar", new String(Base64.decode("Zm9vYmFy")));
    }

    /**
     * Tests RFC 4648 section 10 test vectors.
     * <ul>
     * <li>BASE64("") = ""</li>
     * <li>BASE64("f") = "Zg=="</li>
     * <li>BASE64("fo") = "Zm8="</li>
     * <li>BASE64("foo") = "Zm9v"</li>
     * <li>BASE64("foob") = "Zm9vYg=="</li>
     * <li>BASE64("fooba") = "Zm9vYmE="</li>
     * <li>BASE64("foobar") = "Zm9vYmFy"</li>
     * </ul>
     *
     * @see <a href="http://tools.ietf.org/html/rfc4648">http://tools.ietf.org/
     *      html/rfc4648</a>
     */
    public void testRfc4648Section10DecodeWithCrLf() {
        final String CRLF = new String(Base64.CHUNK_SEPARATOR);
        assertEquals("", new String(Base64.decode("" + CRLF)));
        assertEquals("f", new String(Base64.decode("Zg==" + CRLF)));
        assertEquals("fo", new String(Base64.decode("Zm8=" + CRLF)));
        assertEquals("foo", new String(Base64.decode("Zm9v" + CRLF)));
        assertEquals("foob", new String(Base64.decode("Zm9vYg==" + CRLF)));
        assertEquals("fooba", new String(Base64.decode("Zm9vYmE=" + CRLF)));
        assertEquals("foobar", new String(Base64.decode("Zm9vYmFy" + CRLF)));
    }

    /**
     * Tests RFC 4648 section 10 test vectors.
     * <ul>
     * <li>BASE64("") = ""</li>
     * <li>BASE64("f") = "Zg=="</li>
     * <li>BASE64("fo") = "Zm8="</li>
     * <li>BASE64("foo") = "Zm9v"</li>
     * <li>BASE64("foob") = "Zm9vYg=="</li>
     * <li>BASE64("fooba") = "Zm9vYmE="</li>
     * <li>BASE64("foobar") = "Zm9vYmFy"</li>
     * </ul>
     *
     * @see <a href="http://tools.ietf.org/html/rfc4648">http://tools.ietf.org/
     *      html/rfc4648</a>
     */
    public void testRfc4648Section10Encode() {
        assertEquals("", Base64.encode("".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Zg==", Base64.encode("f".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Zm8=", Base64.encode("fo".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Zm9v", Base64.encode("foo".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Zm9vYg==", Base64.encode("foob".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Zm9vYmE=", Base64.encode("fooba".getBytes(StandardCharsets.UTF_8)));
        assertEquals("Zm9vYmFy", Base64.encode("foobar".getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Tests RFC 4648 section 10 test vectors.
     * <ul>
     * <li>BASE64("") = ""</li>
     * <li>BASE64("f") = "Zg=="</li>
     * <li>BASE64("fo") = "Zm8="</li>
     * <li>BASE64("foo") = "Zm9v"</li>
     * <li>BASE64("foob") = "Zm9vYg=="</li>
     * <li>BASE64("fooba") = "Zm9vYmE="</li>
     * <li>BASE64("foobar") = "Zm9vYmFy"</li>
     * </ul>
     *
     * @see <a href="http://tools.ietf.org/html/rfc4648">http://tools.ietf.org/
     *      html/rfc4648</a>
     */
    public void testRfc4648Section10DecodeEncode() {
        testDecodeEncode("");
        testDecodeEncode("Zg==");
        testDecodeEncode("Zm8=");
        testDecodeEncode("Zm9v");
        testDecodeEncode("Zm9vYg==");
        testDecodeEncode("Zm9vYmE=");
        testDecodeEncode("Zm9vYmFy");
    }

    private void testDecodeEncode(final String encodedText) {
        final String decodedText = new String(Base64.decode(encodedText));
        final String encodedText2 = Base64.encode(decodedText.getBytes(StandardCharsets.UTF_8));
        assertEquals(encodedText, encodedText2);
    }

    /**
     * Tests RFC 4648 section 10 test vectors.
     * <ul>
     * <li>BASE64("") = ""</li>
     * <li>BASE64("f") = "Zg=="</li>
     * <li>BASE64("fo") = "Zm8="</li>
     * <li>BASE64("foo") = "Zm9v"</li>
     * <li>BASE64("foob") = "Zm9vYg=="</li>
     * <li>BASE64("fooba") = "Zm9vYmE="</li>
     * <li>BASE64("foobar") = "Zm9vYmFy"</li>
     * </ul>
     *
     * @see <a href="http://tools.ietf.org/html/rfc4648">http://tools.ietf.org/
     *      html/rfc4648</a>
     */
    public void testRfc4648Section10EncodeDecode() {
        testEncodeDecode("");
        testEncodeDecode("f");
        testEncodeDecode("fo");
        testEncodeDecode("foo");
        testEncodeDecode("foob");
        testEncodeDecode("fooba");
        testEncodeDecode("foobar");
    }

    private void testEncodeDecode(final String plainText) {
        final String encodedText = Base64.encode(plainText.getBytes(StandardCharsets.UTF_8));
        final String decodedText = new String(Base64.decode(encodedText));
        assertEquals(plainText, decodedText);
    }

    public void testSingletons() {
        assertEquals("AA==", new String(Base64.encode(new byte[] { (byte) 0 })));
        assertEquals("AQ==", new String(Base64.encode(new byte[] { (byte) 1 })));
        assertEquals("Ag==", new String(Base64.encode(new byte[] { (byte) 2 })));
        assertEquals("Aw==", new String(Base64.encode(new byte[] { (byte) 3 })));
        assertEquals("BA==", new String(Base64.encode(new byte[] { (byte) 4 })));
        assertEquals("BQ==", new String(Base64.encode(new byte[] { (byte) 5 })));
        assertEquals("Bg==", new String(Base64.encode(new byte[] { (byte) 6 })));
        assertEquals("Bw==", new String(Base64.encode(new byte[] { (byte) 7 })));
        assertEquals("CA==", new String(Base64.encode(new byte[] { (byte) 8 })));
        assertEquals("CQ==", new String(Base64.encode(new byte[] { (byte) 9 })));
        assertEquals("Cg==", new String(Base64.encode(new byte[] { (byte) 10 })));
        assertEquals("Cw==", new String(Base64.encode(new byte[] { (byte) 11 })));
        assertEquals("DA==", new String(Base64.encode(new byte[] { (byte) 12 })));
        assertEquals("DQ==", new String(Base64.encode(new byte[] { (byte) 13 })));
        assertEquals("Dg==", new String(Base64.encode(new byte[] { (byte) 14 })));
        assertEquals("Dw==", new String(Base64.encode(new byte[] { (byte) 15 })));
        assertEquals("EA==", new String(Base64.encode(new byte[] { (byte) 16 })));
        assertEquals("EQ==", new String(Base64.encode(new byte[] { (byte) 17 })));
        assertEquals("Eg==", new String(Base64.encode(new byte[] { (byte) 18 })));
        assertEquals("Ew==", new String(Base64.encode(new byte[] { (byte) 19 })));
        assertEquals("FA==", new String(Base64.encode(new byte[] { (byte) 20 })));
        assertEquals("FQ==", new String(Base64.encode(new byte[] { (byte) 21 })));
        assertEquals("Fg==", new String(Base64.encode(new byte[] { (byte) 22 })));
        assertEquals("Fw==", new String(Base64.encode(new byte[] { (byte) 23 })));
        assertEquals("GA==", new String(Base64.encode(new byte[] { (byte) 24 })));
        assertEquals("GQ==", new String(Base64.encode(new byte[] { (byte) 25 })));
        assertEquals("Gg==", new String(Base64.encode(new byte[] { (byte) 26 })));
        assertEquals("Gw==", new String(Base64.encode(new byte[] { (byte) 27 })));
        assertEquals("HA==", new String(Base64.encode(new byte[] { (byte) 28 })));
        assertEquals("HQ==", new String(Base64.encode(new byte[] { (byte) 29 })));
        assertEquals("Hg==", new String(Base64.encode(new byte[] { (byte) 30 })));
        assertEquals("Hw==", new String(Base64.encode(new byte[] { (byte) 31 })));
        assertEquals("IA==", new String(Base64.encode(new byte[] { (byte) 32 })));
        assertEquals("IQ==", new String(Base64.encode(new byte[] { (byte) 33 })));
        assertEquals("Ig==", new String(Base64.encode(new byte[] { (byte) 34 })));
        assertEquals("Iw==", new String(Base64.encode(new byte[] { (byte) 35 })));
        assertEquals("JA==", new String(Base64.encode(new byte[] { (byte) 36 })));
        assertEquals("JQ==", new String(Base64.encode(new byte[] { (byte) 37 })));
        assertEquals("Jg==", new String(Base64.encode(new byte[] { (byte) 38 })));
        assertEquals("Jw==", new String(Base64.encode(new byte[] { (byte) 39 })));
        assertEquals("KA==", new String(Base64.encode(new byte[] { (byte) 40 })));
        assertEquals("KQ==", new String(Base64.encode(new byte[] { (byte) 41 })));
        assertEquals("Kg==", new String(Base64.encode(new byte[] { (byte) 42 })));
        assertEquals("Kw==", new String(Base64.encode(new byte[] { (byte) 43 })));
        assertEquals("LA==", new String(Base64.encode(new byte[] { (byte) 44 })));
        assertEquals("LQ==", new String(Base64.encode(new byte[] { (byte) 45 })));
        assertEquals("Lg==", new String(Base64.encode(new byte[] { (byte) 46 })));
        assertEquals("Lw==", new String(Base64.encode(new byte[] { (byte) 47 })));
        assertEquals("MA==", new String(Base64.encode(new byte[] { (byte) 48 })));
        assertEquals("MQ==", new String(Base64.encode(new byte[] { (byte) 49 })));
        assertEquals("Mg==", new String(Base64.encode(new byte[] { (byte) 50 })));
        assertEquals("Mw==", new String(Base64.encode(new byte[] { (byte) 51 })));
        assertEquals("NA==", new String(Base64.encode(new byte[] { (byte) 52 })));
        assertEquals("NQ==", new String(Base64.encode(new byte[] { (byte) 53 })));
        assertEquals("Ng==", new String(Base64.encode(new byte[] { (byte) 54 })));
        assertEquals("Nw==", new String(Base64.encode(new byte[] { (byte) 55 })));
        assertEquals("OA==", new String(Base64.encode(new byte[] { (byte) 56 })));
        assertEquals("OQ==", new String(Base64.encode(new byte[] { (byte) 57 })));
        assertEquals("Og==", new String(Base64.encode(new byte[] { (byte) 58 })));
        assertEquals("Ow==", new String(Base64.encode(new byte[] { (byte) 59 })));
        assertEquals("PA==", new String(Base64.encode(new byte[] { (byte) 60 })));
        assertEquals("PQ==", new String(Base64.encode(new byte[] { (byte) 61 })));
        assertEquals("Pg==", new String(Base64.encode(new byte[] { (byte) 62 })));
        assertEquals("Pw==", new String(Base64.encode(new byte[] { (byte) 63 })));
        assertEquals("QA==", new String(Base64.encode(new byte[] { (byte) 64 })));
        assertEquals("QQ==", new String(Base64.encode(new byte[] { (byte) 65 })));
        assertEquals("Qg==", new String(Base64.encode(new byte[] { (byte) 66 })));
        assertEquals("Qw==", new String(Base64.encode(new byte[] { (byte) 67 })));
        assertEquals("RA==", new String(Base64.encode(new byte[] { (byte) 68 })));
        assertEquals("RQ==", new String(Base64.encode(new byte[] { (byte) 69 })));
        assertEquals("Rg==", new String(Base64.encode(new byte[] { (byte) 70 })));
        assertEquals("Rw==", new String(Base64.encode(new byte[] { (byte) 71 })));
        assertEquals("SA==", new String(Base64.encode(new byte[] { (byte) 72 })));
        assertEquals("SQ==", new String(Base64.encode(new byte[] { (byte) 73 })));
        assertEquals("Sg==", new String(Base64.encode(new byte[] { (byte) 74 })));
        assertEquals("Sw==", new String(Base64.encode(new byte[] { (byte) 75 })));
        assertEquals("TA==", new String(Base64.encode(new byte[] { (byte) 76 })));
        assertEquals("TQ==", new String(Base64.encode(new byte[] { (byte) 77 })));
        assertEquals("Tg==", new String(Base64.encode(new byte[] { (byte) 78 })));
        assertEquals("Tw==", new String(Base64.encode(new byte[] { (byte) 79 })));
        assertEquals("UA==", new String(Base64.encode(new byte[] { (byte) 80 })));
        assertEquals("UQ==", new String(Base64.encode(new byte[] { (byte) 81 })));
        assertEquals("Ug==", new String(Base64.encode(new byte[] { (byte) 82 })));
        assertEquals("Uw==", new String(Base64.encode(new byte[] { (byte) 83 })));
        assertEquals("VA==", new String(Base64.encode(new byte[] { (byte) 84 })));
        assertEquals("VQ==", new String(Base64.encode(new byte[] { (byte) 85 })));
        assertEquals("Vg==", new String(Base64.encode(new byte[] { (byte) 86 })));
        assertEquals("Vw==", new String(Base64.encode(new byte[] { (byte) 87 })));
        assertEquals("WA==", new String(Base64.encode(new byte[] { (byte) 88 })));
        assertEquals("WQ==", new String(Base64.encode(new byte[] { (byte) 89 })));
        assertEquals("Wg==", new String(Base64.encode(new byte[] { (byte) 90 })));
        assertEquals("Ww==", new String(Base64.encode(new byte[] { (byte) 91 })));
        assertEquals("XA==", new String(Base64.encode(new byte[] { (byte) 92 })));
        assertEquals("XQ==", new String(Base64.encode(new byte[] { (byte) 93 })));
        assertEquals("Xg==", new String(Base64.encode(new byte[] { (byte) 94 })));
        assertEquals("Xw==", new String(Base64.encode(new byte[] { (byte) 95 })));
        assertEquals("YA==", new String(Base64.encode(new byte[] { (byte) 96 })));
        assertEquals("YQ==", new String(Base64.encode(new byte[] { (byte) 97 })));
        assertEquals("Yg==", new String(Base64.encode(new byte[] { (byte) 98 })));
        assertEquals("Yw==", new String(Base64.encode(new byte[] { (byte) 99 })));
        assertEquals("ZA==", new String(Base64.encode(new byte[] { (byte) 100 })));
        assertEquals("ZQ==", new String(Base64.encode(new byte[] { (byte) 101 })));
        assertEquals("Zg==", new String(Base64.encode(new byte[] { (byte) 102 })));
        assertEquals("Zw==", new String(Base64.encode(new byte[] { (byte) 103 })));
        assertEquals("aA==", new String(Base64.encode(new byte[] { (byte) 104 })));
        for (int i = -128; i <= 127; i++) {
            final byte test[] = { (byte) i };
            assertArrayEquals(test, Base64.decode(Base64.encode(test)));
        }
    }

    public void testSingletonsChunked() {
        assertEquals("AA==\r\n", new String(Base64.encode(new byte[] { (byte) 0 }, Base64.Options.CHUNKING)));
        assertEquals("AQ==\r\n", new String(Base64.encode(new byte[] { (byte) 1 }, Base64.Options.CHUNKING)));
        assertEquals("Ag==\r\n", new String(Base64.encode(new byte[] { (byte) 2 }, Base64.Options.CHUNKING)));
        assertEquals("Aw==\r\n", new String(Base64.encode(new byte[] { (byte) 3 }, Base64.Options.CHUNKING)));
        assertEquals("BA==\r\n", new String(Base64.encode(new byte[] { (byte) 4 }, Base64.Options.CHUNKING)));
        assertEquals("BQ==\r\n", new String(Base64.encode(new byte[] { (byte) 5 }, Base64.Options.CHUNKING)));
        assertEquals("Bg==\r\n", new String(Base64.encode(new byte[] { (byte) 6 }, Base64.Options.CHUNKING)));
        assertEquals("Bw==\r\n", new String(Base64.encode(new byte[] { (byte) 7 }, Base64.Options.CHUNKING)));
        assertEquals("CA==\r\n", new String(Base64.encode(new byte[] { (byte) 8 }, Base64.Options.CHUNKING)));
        assertEquals("CQ==\r\n", new String(Base64.encode(new byte[] { (byte) 9 }, Base64.Options.CHUNKING)));
        assertEquals("Cg==\r\n", new String(Base64.encode(new byte[] { (byte) 10 }, Base64.Options.CHUNKING)));
        assertEquals("Cw==\r\n", new String(Base64.encode(new byte[] { (byte) 11 }, Base64.Options.CHUNKING)));
        assertEquals("DA==\r\n", new String(Base64.encode(new byte[] { (byte) 12 }, Base64.Options.CHUNKING)));
        assertEquals("DQ==\r\n", new String(Base64.encode(new byte[] { (byte) 13 }, Base64.Options.CHUNKING)));
        assertEquals("Dg==\r\n", new String(Base64.encode(new byte[] { (byte) 14 }, Base64.Options.CHUNKING)));
        assertEquals("Dw==\r\n", new String(Base64.encode(new byte[] { (byte) 15 }, Base64.Options.CHUNKING)));
        assertEquals("EA==\r\n", new String(Base64.encode(new byte[] { (byte) 16 }, Base64.Options.CHUNKING)));
        assertEquals("EQ==\r\n", new String(Base64.encode(new byte[] { (byte) 17 }, Base64.Options.CHUNKING)));
        assertEquals("Eg==\r\n", new String(Base64.encode(new byte[] { (byte) 18 }, Base64.Options.CHUNKING)));
        assertEquals("Ew==\r\n", new String(Base64.encode(new byte[] { (byte) 19 }, Base64.Options.CHUNKING)));
        assertEquals("FA==\r\n", new String(Base64.encode(new byte[] { (byte) 20 }, Base64.Options.CHUNKING)));
        assertEquals("FQ==\r\n", new String(Base64.encode(new byte[] { (byte) 21 }, Base64.Options.CHUNKING)));
        assertEquals("Fg==\r\n", new String(Base64.encode(new byte[] { (byte) 22 }, Base64.Options.CHUNKING)));
        assertEquals("Fw==\r\n", new String(Base64.encode(new byte[] { (byte) 23 }, Base64.Options.CHUNKING)));
        assertEquals("GA==\r\n", new String(Base64.encode(new byte[] { (byte) 24 }, Base64.Options.CHUNKING)));
        assertEquals("GQ==\r\n", new String(Base64.encode(new byte[] { (byte) 25 }, Base64.Options.CHUNKING)));
        assertEquals("Gg==\r\n", new String(Base64.encode(new byte[] { (byte) 26 }, Base64.Options.CHUNKING)));
        assertEquals("Gw==\r\n", new String(Base64.encode(new byte[] { (byte) 27 }, Base64.Options.CHUNKING)));
        assertEquals("HA==\r\n", new String(Base64.encode(new byte[] { (byte) 28 }, Base64.Options.CHUNKING)));
        assertEquals("HQ==\r\n", new String(Base64.encode(new byte[] { (byte) 29 }, Base64.Options.CHUNKING)));
        assertEquals("Hg==\r\n", new String(Base64.encode(new byte[] { (byte) 30 }, Base64.Options.CHUNKING)));
        assertEquals("Hw==\r\n", new String(Base64.encode(new byte[] { (byte) 31 }, Base64.Options.CHUNKING)));
        assertEquals("IA==\r\n", new String(Base64.encode(new byte[] { (byte) 32 }, Base64.Options.CHUNKING)));
        assertEquals("IQ==\r\n", new String(Base64.encode(new byte[] { (byte) 33 }, Base64.Options.CHUNKING)));
        assertEquals("Ig==\r\n", new String(Base64.encode(new byte[] { (byte) 34 }, Base64.Options.CHUNKING)));
        assertEquals("Iw==\r\n", new String(Base64.encode(new byte[] { (byte) 35 }, Base64.Options.CHUNKING)));
        assertEquals("JA==\r\n", new String(Base64.encode(new byte[] { (byte) 36 }, Base64.Options.CHUNKING)));
        assertEquals("JQ==\r\n", new String(Base64.encode(new byte[] { (byte) 37 }, Base64.Options.CHUNKING)));
        assertEquals("Jg==\r\n", new String(Base64.encode(new byte[] { (byte) 38 }, Base64.Options.CHUNKING)));
        assertEquals("Jw==\r\n", new String(Base64.encode(new byte[] { (byte) 39 }, Base64.Options.CHUNKING)));
        assertEquals("KA==\r\n", new String(Base64.encode(new byte[] { (byte) 40 }, Base64.Options.CHUNKING)));
        assertEquals("KQ==\r\n", new String(Base64.encode(new byte[] { (byte) 41 }, Base64.Options.CHUNKING)));
        assertEquals("Kg==\r\n", new String(Base64.encode(new byte[] { (byte) 42 }, Base64.Options.CHUNKING)));
        assertEquals("Kw==\r\n", new String(Base64.encode(new byte[] { (byte) 43 }, Base64.Options.CHUNKING)));
        assertEquals("LA==\r\n", new String(Base64.encode(new byte[] { (byte) 44 }, Base64.Options.CHUNKING)));
        assertEquals("LQ==\r\n", new String(Base64.encode(new byte[] { (byte) 45 }, Base64.Options.CHUNKING)));
        assertEquals("Lg==\r\n", new String(Base64.encode(new byte[] { (byte) 46 }, Base64.Options.CHUNKING)));
        assertEquals("Lw==\r\n", new String(Base64.encode(new byte[] { (byte) 47 }, Base64.Options.CHUNKING)));
        assertEquals("MA==\r\n", new String(Base64.encode(new byte[] { (byte) 48 }, Base64.Options.CHUNKING)));
        assertEquals("MQ==\r\n", new String(Base64.encode(new byte[] { (byte) 49 }, Base64.Options.CHUNKING)));
        assertEquals("Mg==\r\n", new String(Base64.encode(new byte[] { (byte) 50 }, Base64.Options.CHUNKING)));
        assertEquals("Mw==\r\n", new String(Base64.encode(new byte[] { (byte) 51 }, Base64.Options.CHUNKING)));
        assertEquals("NA==\r\n", new String(Base64.encode(new byte[] { (byte) 52 }, Base64.Options.CHUNKING)));
        assertEquals("NQ==\r\n", new String(Base64.encode(new byte[] { (byte) 53 }, Base64.Options.CHUNKING)));
        assertEquals("Ng==\r\n", new String(Base64.encode(new byte[] { (byte) 54 }, Base64.Options.CHUNKING)));
        assertEquals("Nw==\r\n", new String(Base64.encode(new byte[] { (byte) 55 }, Base64.Options.CHUNKING)));
        assertEquals("OA==\r\n", new String(Base64.encode(new byte[] { (byte) 56 }, Base64.Options.CHUNKING)));
        assertEquals("OQ==\r\n", new String(Base64.encode(new byte[] { (byte) 57 }, Base64.Options.CHUNKING)));
        assertEquals("Og==\r\n", new String(Base64.encode(new byte[] { (byte) 58 }, Base64.Options.CHUNKING)));
        assertEquals("Ow==\r\n", new String(Base64.encode(new byte[] { (byte) 59 }, Base64.Options.CHUNKING)));
        assertEquals("PA==\r\n", new String(Base64.encode(new byte[] { (byte) 60 }, Base64.Options.CHUNKING)));
        assertEquals("PQ==\r\n", new String(Base64.encode(new byte[] { (byte) 61 }, Base64.Options.CHUNKING)));
        assertEquals("Pg==\r\n", new String(Base64.encode(new byte[] { (byte) 62 }, Base64.Options.CHUNKING)));
        assertEquals("Pw==\r\n", new String(Base64.encode(new byte[] { (byte) 63 }, Base64.Options.CHUNKING)));
        assertEquals("QA==\r\n", new String(Base64.encode(new byte[] { (byte) 64 }, Base64.Options.CHUNKING)));
        assertEquals("QQ==\r\n", new String(Base64.encode(new byte[] { (byte) 65 }, Base64.Options.CHUNKING)));
        assertEquals("Qg==\r\n", new String(Base64.encode(new byte[] { (byte) 66 }, Base64.Options.CHUNKING)));
        assertEquals("Qw==\r\n", new String(Base64.encode(new byte[] { (byte) 67 }, Base64.Options.CHUNKING)));
        assertEquals("RA==\r\n", new String(Base64.encode(new byte[] { (byte) 68 }, Base64.Options.CHUNKING)));
        assertEquals("RQ==\r\n", new String(Base64.encode(new byte[] { (byte) 69 }, Base64.Options.CHUNKING)));
        assertEquals("Rg==\r\n", new String(Base64.encode(new byte[] { (byte) 70 }, Base64.Options.CHUNKING)));
        assertEquals("Rw==\r\n", new String(Base64.encode(new byte[] { (byte) 71 }, Base64.Options.CHUNKING)));
        assertEquals("SA==\r\n", new String(Base64.encode(new byte[] { (byte) 72 }, Base64.Options.CHUNKING)));
        assertEquals("SQ==\r\n", new String(Base64.encode(new byte[] { (byte) 73 }, Base64.Options.CHUNKING)));
        assertEquals("Sg==\r\n", new String(Base64.encode(new byte[] { (byte) 74 }, Base64.Options.CHUNKING)));
        assertEquals("Sw==\r\n", new String(Base64.encode(new byte[] { (byte) 75 }, Base64.Options.CHUNKING)));
        assertEquals("TA==\r\n", new String(Base64.encode(new byte[] { (byte) 76 }, Base64.Options.CHUNKING)));
        assertEquals("TQ==\r\n", new String(Base64.encode(new byte[] { (byte) 77 }, Base64.Options.CHUNKING)));
        assertEquals("Tg==\r\n", new String(Base64.encode(new byte[] { (byte) 78 }, Base64.Options.CHUNKING)));
        assertEquals("Tw==\r\n", new String(Base64.encode(new byte[] { (byte) 79 }, Base64.Options.CHUNKING)));
        assertEquals("UA==\r\n", new String(Base64.encode(new byte[] { (byte) 80 }, Base64.Options.CHUNKING)));
        assertEquals("UQ==\r\n", new String(Base64.encode(new byte[] { (byte) 81 }, Base64.Options.CHUNKING)));
        assertEquals("Ug==\r\n", new String(Base64.encode(new byte[] { (byte) 82 }, Base64.Options.CHUNKING)));
        assertEquals("Uw==\r\n", new String(Base64.encode(new byte[] { (byte) 83 }, Base64.Options.CHUNKING)));
        assertEquals("VA==\r\n", new String(Base64.encode(new byte[] { (byte) 84 }, Base64.Options.CHUNKING)));
        assertEquals("VQ==\r\n", new String(Base64.encode(new byte[] { (byte) 85 }, Base64.Options.CHUNKING)));
        assertEquals("Vg==\r\n", new String(Base64.encode(new byte[] { (byte) 86 }, Base64.Options.CHUNKING)));
        assertEquals("Vw==\r\n", new String(Base64.encode(new byte[] { (byte) 87 }, Base64.Options.CHUNKING)));
        assertEquals("WA==\r\n", new String(Base64.encode(new byte[] { (byte) 88 }, Base64.Options.CHUNKING)));
        assertEquals("WQ==\r\n", new String(Base64.encode(new byte[] { (byte) 89 }, Base64.Options.CHUNKING)));
        assertEquals("Wg==\r\n", new String(Base64.encode(new byte[] { (byte) 90 }, Base64.Options.CHUNKING)));
        assertEquals("Ww==\r\n", new String(Base64.encode(new byte[] { (byte) 91 }, Base64.Options.CHUNKING)));
        assertEquals("XA==\r\n", new String(Base64.encode(new byte[] { (byte) 92 }, Base64.Options.CHUNKING)));
        assertEquals("XQ==\r\n", new String(Base64.encode(new byte[] { (byte) 93 }, Base64.Options.CHUNKING)));
        assertEquals("Xg==\r\n", new String(Base64.encode(new byte[] { (byte) 94 }, Base64.Options.CHUNKING)));
        assertEquals("Xw==\r\n", new String(Base64.encode(new byte[] { (byte) 95 }, Base64.Options.CHUNKING)));
        assertEquals("YA==\r\n", new String(Base64.encode(new byte[] { (byte) 96 }, Base64.Options.CHUNKING)));
        assertEquals("YQ==\r\n", new String(Base64.encode(new byte[] { (byte) 97 }, Base64.Options.CHUNKING)));
        assertEquals("Yg==\r\n", new String(Base64.encode(new byte[] { (byte) 98 }, Base64.Options.CHUNKING)));
        assertEquals("Yw==\r\n", new String(Base64.encode(new byte[] { (byte) 99 }, Base64.Options.CHUNKING)));
        assertEquals("ZA==\r\n", new String(Base64.encode(new byte[] { (byte) 100 }, Base64.Options.CHUNKING)));
        assertEquals("ZQ==\r\n", new String(Base64.encode(new byte[] { (byte) 101 }, Base64.Options.CHUNKING)));
        assertEquals("Zg==\r\n", new String(Base64.encode(new byte[] { (byte) 102 }, Base64.Options.CHUNKING)));
        assertEquals("Zw==\r\n", new String(Base64.encode(new byte[] { (byte) 103 }, Base64.Options.CHUNKING)));
        assertEquals("aA==\r\n", new String(Base64.encode(new byte[] { (byte) 104 }, Base64.Options.CHUNKING)));
    }

    public void testTriplets() {
        assertEquals("AAAA", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 0 })));
        assertEquals("AAAB", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 1 })));
        assertEquals("AAAC", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 2 })));
        assertEquals("AAAD", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 3 })));
        assertEquals("AAAE", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 4 })));
        assertEquals("AAAF", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 5 })));
        assertEquals("AAAG", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 6 })));
        assertEquals("AAAH", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 7 })));
        assertEquals("AAAI", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 8 })));
        assertEquals("AAAJ", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 9 })));
        assertEquals("AAAK", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 10 })));
        assertEquals("AAAL", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 11 })));
        assertEquals("AAAM", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 12 })));
        assertEquals("AAAN", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 13 })));
        assertEquals("AAAO", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 14 })));
        assertEquals("AAAP", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 15 })));
        assertEquals("AAAQ", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 16 })));
        assertEquals("AAAR", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 17 })));
        assertEquals("AAAS", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 18 })));
        assertEquals("AAAT", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 19 })));
        assertEquals("AAAU", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 20 })));
        assertEquals("AAAV", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 21 })));
        assertEquals("AAAW", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 22 })));
        assertEquals("AAAX", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 23 })));
        assertEquals("AAAY", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 24 })));
        assertEquals("AAAZ", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 25 })));
        assertEquals("AAAa", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 26 })));
        assertEquals("AAAb", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 27 })));
        assertEquals("AAAc", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 28 })));
        assertEquals("AAAd", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 29 })));
        assertEquals("AAAe", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 30 })));
        assertEquals("AAAf", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 31 })));
        assertEquals("AAAg", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 32 })));
        assertEquals("AAAh", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 33 })));
        assertEquals("AAAi", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 34 })));
        assertEquals("AAAj", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 35 })));
        assertEquals("AAAk", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 36 })));
        assertEquals("AAAl", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 37 })));
        assertEquals("AAAm", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 38 })));
        assertEquals("AAAn", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 39 })));
        assertEquals("AAAo", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 40 })));
        assertEquals("AAAp", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 41 })));
        assertEquals("AAAq", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 42 })));
        assertEquals("AAAr", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 43 })));
        assertEquals("AAAs", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 44 })));
        assertEquals("AAAt", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 45 })));
        assertEquals("AAAu", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 46 })));
        assertEquals("AAAv", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 47 })));
        assertEquals("AAAw", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 48 })));
        assertEquals("AAAx", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 49 })));
        assertEquals("AAAy", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 50 })));
        assertEquals("AAAz", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 51 })));
        assertEquals("AAA0", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 52 })));
        assertEquals("AAA1", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 53 })));
        assertEquals("AAA2", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 54 })));
        assertEquals("AAA3", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 55 })));
        assertEquals("AAA4", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 56 })));
        assertEquals("AAA5", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 57 })));
        assertEquals("AAA6", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 58 })));
        assertEquals("AAA7", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 59 })));
        assertEquals("AAA8", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 60 })));
        assertEquals("AAA9", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 61 })));
        assertEquals("AAA+", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 62 })));
        assertEquals("AAA/", new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 63 })));
    }

    public void testTripletsChunked() {
        assertEquals("AAAA\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 0 }, Base64.Options.CHUNKING)));
        assertEquals("AAAB\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 1 }, Base64.Options.CHUNKING)));
        assertEquals("AAAC\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 2 }, Base64.Options.CHUNKING)));
        assertEquals("AAAD\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 3 }, Base64.Options.CHUNKING)));
        assertEquals("AAAE\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 4 }, Base64.Options.CHUNKING)));
        assertEquals("AAAF\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 5 }, Base64.Options.CHUNKING)));
        assertEquals("AAAG\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 6 }, Base64.Options.CHUNKING)));
        assertEquals("AAAH\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 7 }, Base64.Options.CHUNKING)));
        assertEquals("AAAI\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 8 }, Base64.Options.CHUNKING)));
        assertEquals("AAAJ\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 9 }, Base64.Options.CHUNKING)));
        assertEquals("AAAK\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 10 }, Base64.Options.CHUNKING)));
        assertEquals("AAAL\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 11 }, Base64.Options.CHUNKING)));
        assertEquals("AAAM\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 12 }, Base64.Options.CHUNKING)));
        assertEquals("AAAN\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 13 }, Base64.Options.CHUNKING)));
        assertEquals("AAAO\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 14 }, Base64.Options.CHUNKING)));
        assertEquals("AAAP\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 15 }, Base64.Options.CHUNKING)));
        assertEquals("AAAQ\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 16 }, Base64.Options.CHUNKING)));
        assertEquals("AAAR\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 17 }, Base64.Options.CHUNKING)));
        assertEquals("AAAS\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 18 }, Base64.Options.CHUNKING)));
        assertEquals("AAAT\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 19 }, Base64.Options.CHUNKING)));
        assertEquals("AAAU\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 20 }, Base64.Options.CHUNKING)));
        assertEquals("AAAV\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 21 }, Base64.Options.CHUNKING)));
        assertEquals("AAAW\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 22 }, Base64.Options.CHUNKING)));
        assertEquals("AAAX\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 23 }, Base64.Options.CHUNKING)));
        assertEquals("AAAY\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 24 }, Base64.Options.CHUNKING)));
        assertEquals("AAAZ\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 25 }, Base64.Options.CHUNKING)));
        assertEquals("AAAa\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 26 }, Base64.Options.CHUNKING)));
        assertEquals("AAAb\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 27 }, Base64.Options.CHUNKING)));
        assertEquals("AAAc\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 28 }, Base64.Options.CHUNKING)));
        assertEquals("AAAd\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 29 }, Base64.Options.CHUNKING)));
        assertEquals("AAAe\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 30 }, Base64.Options.CHUNKING)));
        assertEquals("AAAf\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 31 }, Base64.Options.CHUNKING)));
        assertEquals("AAAg\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 32 }, Base64.Options.CHUNKING)));
        assertEquals("AAAh\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 33 }, Base64.Options.CHUNKING)));
        assertEquals("AAAi\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 34 }, Base64.Options.CHUNKING)));
        assertEquals("AAAj\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 35 }, Base64.Options.CHUNKING)));
        assertEquals("AAAk\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 36 }, Base64.Options.CHUNKING)));
        assertEquals("AAAl\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 37 }, Base64.Options.CHUNKING)));
        assertEquals("AAAm\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 38 }, Base64.Options.CHUNKING)));
        assertEquals("AAAn\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 39 }, Base64.Options.CHUNKING)));
        assertEquals("AAAo\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 40 }, Base64.Options.CHUNKING)));
        assertEquals("AAAp\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 41 }, Base64.Options.CHUNKING)));
        assertEquals("AAAq\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 42 }, Base64.Options.CHUNKING)));
        assertEquals("AAAr\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 43 }, Base64.Options.CHUNKING)));
        assertEquals("AAAs\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 44 }, Base64.Options.CHUNKING)));
        assertEquals("AAAt\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 45 }, Base64.Options.CHUNKING)));
        assertEquals("AAAu\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 46 }, Base64.Options.CHUNKING)));
        assertEquals("AAAv\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 47 }, Base64.Options.CHUNKING)));
        assertEquals("AAAw\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 48 }, Base64.Options.CHUNKING)));
        assertEquals("AAAx\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 49 }, Base64.Options.CHUNKING)));
        assertEquals("AAAy\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 50 }, Base64.Options.CHUNKING)));
        assertEquals("AAAz\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 51 }, Base64.Options.CHUNKING)));
        assertEquals("AAA0\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 52 }, Base64.Options.CHUNKING)));
        assertEquals("AAA1\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 53 }, Base64.Options.CHUNKING)));
        assertEquals("AAA2\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 54 }, Base64.Options.CHUNKING)));
        assertEquals("AAA3\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 55 }, Base64.Options.CHUNKING)));
        assertEquals("AAA4\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 56 }, Base64.Options.CHUNKING)));
        assertEquals("AAA5\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 57 }, Base64.Options.CHUNKING)));
        assertEquals("AAA6\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 58 }, Base64.Options.CHUNKING)));
        assertEquals("AAA7\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 59 }, Base64.Options.CHUNKING)));
        assertEquals("AAA8\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 60 }, Base64.Options.CHUNKING)));
        assertEquals("AAA9\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 61 }, Base64.Options.CHUNKING)));
        assertEquals("AAA+\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 62 }, Base64.Options.CHUNKING)));
        assertEquals("AAA/\r\n",
                new String(Base64.encode(new byte[] { (byte) 0, (byte) 0, (byte) 63 }, Base64.Options.CHUNKING)));
    }

    public void testUrlSafe() {
        // test random data of sizes 0 thru 150
        for (int i = 0; i <= 150; i++) {
            final byte[][] randomData = randomData(i, true);
            final byte[] encoded = randomData[1];
            final byte[] decoded = randomData[0];
            final byte[] result = Base64.decodeUrlSafe(new String(encoded));
            assertArrayEquals("url-safe i=" + i, result, decoded);
            assertFalse("url-safe i=" + i + " no '='", bytesContain(encoded, (byte) '='));
            assertFalse("url-safe i=" + i + " no '\\'", bytesContain(encoded, (byte) '\\'));
            assertFalse("url-safe i=" + i + " no '+'", bytesContain(encoded, (byte) '+'));
        }
    }

    public void testUUID() {
        // The 4 UUID's below contains mixtures of + and / to help us test the
        // URL-SAFE encoding mode.
        final byte[][] ids = new byte[4][];

        // ids[0] was chosen so that it encodes with at least one +.
        ids[0] = fromHex("94ed8d0319e4493399560fb67404d370");

        // ids[1] was chosen so that it encodes with both / and +.
        ids[1] = fromHex("2bf7cc2701fe4397b49ebeed5acc7090");

        // ids[2] was chosen so that it encodes with at least one /.
        ids[2] = fromHex("64be154b6ffa40258d1a01288e7c31ca");

        // ids[3] was chosen so that it encodes with both / and +, with /
        // right at the beginning.
        ids[3] = fromHex("ff7f8fc01cdb471a8c8b5a9306183fe8");

        final String[] standard = new String[4];
        standard[0] = "lO2NAxnkSTOZVg+2dATTcA==";
        standard[1] = "K/fMJwH+Q5e0nr7tWsxwkA==";
        standard[2] = "ZL4VS2/6QCWNGgEojnwxyg==";
        standard[3] = "/3+PwBzbRxqMi1qTBhg/6A==";

        final String[] urlSafe1 = new String[4];
        // regular padding (two '==' signs).
        urlSafe1[0] = "lO2NAxnkSTOZVg-2dATTcA==";
        urlSafe1[1] = "K_fMJwH-Q5e0nr7tWsxwkA==";
        urlSafe1[2] = "ZL4VS2_6QCWNGgEojnwxyg==";
        urlSafe1[3] = "_3-PwBzbRxqMi1qTBhg_6A==";

        final String[] urlSafe2 = new String[4];
        // single padding (only one '=' sign).
        urlSafe2[0] = "lO2NAxnkSTOZVg-2dATTcA=";
        urlSafe2[1] = "K_fMJwH-Q5e0nr7tWsxwkA=";
        urlSafe2[2] = "ZL4VS2_6QCWNGgEojnwxyg=";
        urlSafe2[3] = "_3-PwBzbRxqMi1qTBhg_6A=";

        final String[] urlSafe3 = new String[4];
        // no padding (no '=' signs).
        urlSafe3[0] = "lO2NAxnkSTOZVg-2dATTcA";
        urlSafe3[1] = "K_fMJwH-Q5e0nr7tWsxwkA";
        urlSafe3[2] = "ZL4VS2_6QCWNGgEojnwxyg";
        urlSafe3[3] = "_3-PwBzbRxqMi1qTBhg_6A";

        for (int i = 0; i < 4; i++) {
            final String encodedStandard = Base64.encode(ids[i]);
            final String encodedUrlSafe = Base64.encodeUrlSafe(ids[i]);
            final byte[] decodedStandard = Base64.decode(standard[i]);
            final byte[] decodedUrlSafe1 = Base64.decodeUrlSafe(urlSafe1[i]);
            final byte[] decodedUrlSafe2 = Base64.decodeUrlSafe(urlSafe2[i]);
            final byte[] decodedUrlSafe3 = Base64.decodeUrlSafe(urlSafe3[i]);

            assertArrayEquals("standard encode uuid", standard[i].getBytes(StandardCharsets.UTF_8),
                    encodedStandard.getBytes(StandardCharsets.UTF_8));
            assertArrayEquals("url-safe encode uuid", urlSafe3[i].getBytes(StandardCharsets.UTF_8),
                    encodedUrlSafe.getBytes(StandardCharsets.UTF_8));
            assertArrayEquals("standard decode uuid", ids[i], decodedStandard);
            assertArrayEquals("url-safe1 decode uuid", ids[i], decodedUrlSafe1);
            assertArrayEquals("url-safe2 decode uuid", ids[i], decodedUrlSafe2);
            assertArrayEquals("url-safe3 decode uuid", ids[i], decodedUrlSafe3);
        }
    }

    public void testByteToStringVariations() {
        final byte[] b1 = "Hello World".getBytes(StandardCharsets.UTF_8);
        final byte[] b2 = new byte[0];
        final byte[] b3 = null;
        final byte[] b4 = fromHex("2bf7cc2701fe4397b49ebeed5acc7090"); // for
                                                                       // url-safe
                                                                       // tests

        assertEquals("byteToString Hello World", "SGVsbG8gV29ybGQ=", Base64.encode(b1));
        assertEquals("byteToString \"\"", "", Base64.encode(b2));
        assertEquals("byteToString null", null, Base64.encode(b3));
        assertEquals("byteToString UUID", "K/fMJwH+Q5e0nr7tWsxwkA==", Base64.encode(b4));
        assertEquals("byteToString static-url-safe UUID", "K_fMJwH-Q5e0nr7tWsxwkA",
                Base64.encode(b4, Base64.Options.URL_SAFE));
    }

    public void testStringToByteVariations() {
        final String s1 = "SGVsbG8gV29ybGQ=\r\n";
        final String s2 = "";
        final String s3 = null;
        final String s4a = "K/fMJwH+Q5e0nr7tWsxwkA==\r\n";
        final String s4b = "K_fMJwH-Q5e0nr7tWsxwkA";
        final byte[] b4 = fromHex("2bf7cc2701fe4397b49ebeed5acc7090"); // for
                                                                       // url-safe
                                                                       // tests

        assertEquals("StringToByte Hello World", "Hello World", new String(Base64.decode(s1)));
        assertEquals("StringToByte \"\"", "", new String(Base64.decode(s2)));
        assertEquals("StringToByte null", null, Base64.decode(s3));
        assertArrayEquals("StringToByte static UUID", b4, Base64.decode(s4a));
        assertArrayEquals("StringToByte static-url-safe UUID", b4, Base64.decode(s4b));
    }

    static byte[][] randomData(final int size, final boolean urlSafe) {
        final Random r = new Random();
        final byte[] decoded = new byte[size];
        r.nextBytes(decoded);
        final byte[] encoded = (urlSafe ? Base64.encodeUrlSafe(decoded) : Base64.encode(decoded))
                .getBytes(StandardCharsets.UTF_8);
        return new byte[][] { decoded, encoded };
    }

    static boolean bytesContain(final byte[] bytes, final byte c) {
        for (final byte b : bytes) {
            if (b == c) {
                return true;
            }
        }
        return false;
    }

    static byte[] fromHex(String hex) {
        int l = hex.length();
        byte[] data = new byte[l / 2];
        for (int i = 0; i < l; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    static String toHex(byte[] bytes) {
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
