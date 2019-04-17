package com.github.trancee.fernet;

import static org.junit.Assert.assertArrayEquals;

import com.github.trancee.fernet.Fernet.Token;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for Fernet implementation.
 */
public class FernetTest extends TestCase {
    protected static final byte VERSION = (byte) 0x80;
    protected static final int FERNET_TTL = (10 * 60); // Age of message should not exceed 10 minutes.

    byte[] testKey = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    byte[] testData = "The quick brown fox jumps over the lazy dog.".getBytes();

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public FernetTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(FernetTest.class);
    }

    /**
     * Test the Fernet implementation
     */
    public void testFernetRaw() throws FernetException {
        long timestamp = 0L;
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        Fernet.Token token = new Fernet.Token(timestamp, iv);

        Fernet fernet = new Fernet(testKey);

        byte[] data = fernet.encryptRaw(testData, token);
        assertArrayEquals(fromHex(
                "80000000000000000000000000000000000000000000000000dcd3096e636c7785a42721846747d1c32349be98993a010c7ce1b9a9bc350b31119a1cac9945b083bd67a584d64fa4615a1476c109f9af57e8c6c575a2e6c705834938eb36c7c0bcec5984571dd0d2a1"),
                data);

        byte[] bytes = fernet.decryptRaw(data);
        assertArrayEquals(testData, bytes);
    }

    public void testFernetBase64() throws FernetException {
        long timestamp = 0L;
        byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        Fernet.Token token = new Fernet.Token(timestamp, iv);

        Fernet fernet = new Fernet(testKey);

        String data = fernet.encrypt(testData, token);
        assertEquals(
                "gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANzTCW5jbHeFpCchhGdH0cMjSb6YmToBDHzhuam8NQsxEZocrJlFsIO9Z6WE1k-kYVoUdsEJ-a9X6MbFdaLmxwWDSTjrNsfAvOxZhFcd0NKh",
                data);

        byte[] bytes = fernet.decrypt(data);
        assertArrayEquals(testData, bytes);
    }

    public void testFernet() throws FernetException {
        Fernet fernet = new Fernet();

        String data = fernet.encrypt(testData);

        byte[] bytes = fernet.decrypt(data);
        assertArrayEquals(testData, bytes);
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
