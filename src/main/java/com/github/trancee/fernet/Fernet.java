package com.github.trancee.fernet;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Fernet (symmetric encryption)
 *
 * Fernet guarantees that a message encrypted using it cannot be manipulated or
 * read without the key. Fernet is an implementation of symmetric (also known as
 * “secret key”) authenticated cryptography.
 *
 * Fernet Spec https://github.com/fernet/spec/blob/master/Spec.md
 *
 * All encryption in this version is done with AES 128 in CBC mode. All base 64
 * encoding is done with the "URL and Filename Safe" variant, defined in RFC
 * 4648 as "base64url".
 *
 * @author Philipp Grosswiler <philipp.grosswiler@gmail.com>
 */
@SuppressWarnings("restriction")
public class Fernet {
	public static final byte VERSION = (byte) 0x80; // 8 bits

	private static final int MIN_TOKEN_SIZE = (8 + 64 + 128 + 0 + 256) >> 3;
	private static final int KEY_SIZE = (128) >> 3;
	private static final int HMAC_SIZE = (256) >> 3;

	private static final int MAX_CLOCK_SKEW = 60;

	private static class Bytes {
		/**
		 * Returns the values from each provided array combined into a single array. For
		 * example, {@code concat(new byte[] {a, b}, new byte[] {}, new byte[] {c}}
		 * returns the array {@code {a, b, c}}.
		 *
		 * @param arrays zero or more {@code byte} arrays
		 * @return a single array containing all the values from the source arrays, in
		 *         order
		 */
		static byte[] concat(byte[]... arrays) {
			int length = 0;
			for (byte[] array : arrays) {
				length += array.length;
			}
			byte[] result = new byte[length];
			int pos = 0;
			for (byte[] array : arrays) {
				System.arraycopy(array, 0, result, pos, array.length);
				pos += array.length;
			}
			return result;
		}
	}

	/**
	 * Key Format
	 *
	 * A fernet key is the base64url encoding of the following fields: Signing-key ‖
	 * Encryption-key
	 *
	 * Signing-key, 128 bits Encryption-key, 128 bits
	 */
	private static class Key {
		private final byte[] signingKey;
		private final byte[] encryptionKey;

		public Key() {
			this.signingKey = generateKey();
			this.encryptionKey = generateKey();
		}

		public Key(String key) throws FernetException {
			this(base64UrlDecode(key));
		}

		public Key(byte[] key) throws FernetException {
			if (key != null && key.length == 32) {
				this.signingKey = Arrays.copyOf(key, 16);
				this.encryptionKey = Arrays.copyOfRange(key, 16, 32);
			} else {
				throw new FernetException("Incorrect key.");
			}
		}

		@Override
		public String toString() {
			return base64UrlEncode(Bytes.concat(this.signingKey, this.encryptionKey));
		}
	}

	/**
	 * Token Format
	 *
	 * A fernet token is the base64url encoding of the concatenation of the
	 * following fields: Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC
	 *
	 * Version, 8 bits Timestamp, 64 bits IV, 128 bits Ciphertext, variable length,
	 * multiple of 128 bits HMAC, 256 bits
	 *
	 * Fernet tokens are not self-delimiting. It is assumed that the transport will
	 * provide a means of finding the length of each complete fernet token.
	 */
	public static class Token {
		// Token Fields

		/**
		 * Version
		 *
		 * This field denotes which version of the format is being used by the token.
		 * Currently there is only one version defined, with the value 128 (0x80).
		 */
		private byte version = Fernet.VERSION;

		/**
		 * Timestamp
		 *
		 * This field is a 64-bit unsigned big-endian integer. It records the number of
		 * seconds elapsed between January 1, 1970 UTC and the time the token was
		 * created.
		 */
		private long timestamp;

		/**
		 * IV
		 *
		 * The 128-bit Initialization Vector used in AES encryption and decryption of
		 * the Ciphertext.
		 *
		 * When generating new fernet tokens, the IV must be chosen uniquely for every
		 * token. With a high-quality source of entropy, random selection will do this
		 * with high probability.
		 */
		private byte[] iv = new byte[KEY_SIZE];

		/**
		 * Ciphertext
		 *
		 * This field has variable size, but is always a multiple of 128 bits, the AES
		 * block size. It contains the original input message, padded and encrypted.
		 */
		private byte[] ciphertext;

		/**
		 * HMAC
		 *
		 * This field is the 256-bit SHA256 HMAC, under signing-key, of the
		 * concatenation of the following fields: Version ‖ Timestamp ‖ IV ‖ Ciphertext
		 *
		 * Note that the HMAC input is the entire rest of the token verbatim, and that
		 * this input is not base64url encoded.
		 */
		private byte[] signature = new byte[HMAC_SIZE];

		public Token() {
			this.timestamp = getTime();
			this.iv = generateKey();
		}

		public Token(long timestamp, byte[] iv) {
			this.timestamp = timestamp;
			this.iv = iv;
		}

		public Token(byte[] token) {
			ByteBuffer buffer = ByteBuffer.wrap(token);
			buffer.order(ByteOrder.BIG_ENDIAN);

			if (buffer != null && buffer.capacity() >= MIN_TOKEN_SIZE) {
				version = buffer.get();
				timestamp = buffer.getLong();

				buffer.get(iv);

				ciphertext = new byte[buffer.remaining() - signature.length];
				buffer.get(ciphertext);

				buffer.get(signature);
			}
		}

		public Token(String token) {
			// 1. base64url decode the token.
			this(base64UrlDecode(token));
		}

		public Boolean verify(int ttl, byte[] signingKey) throws FernetException {
			// 2. Ensure the first byte of the token is 0x80.
			if (version != Fernet.VERSION) {
				throw new FernetException("Invalid version.");
			}

			// 3. If the user has specified a maximum age (or "time-to-live") for the token,
			// ensure the recorded timestamp is not too far in the past.
			if (ttl > 0) {
				long currentTime = getTime();

				if (timestamp + ttl < currentTime || currentTime + MAX_CLOCK_SKEW < timestamp) {
					throw new TokenExpiredException("Token has expired.");
				}
			}

			// 4. Recompute the HMAC from the other fields and the user-supplied
			// signing-key.
			byte[] token = buildToken();

			// 5. Ensure the recomputed HMAC matches the HMAC field stored in the token,
			// using a constant-time comparison function.
			try {
				if (!Arrays.equals(signature, generateHash(token, signingKey))) {
					throw new FernetException("Invalid signature.");
				}
			} catch (Exception e) {
				throw new FernetException(e);
			}

			return true;
		}

		public byte[] sign(byte[] ciphertext, byte[] signingKey) throws InvalidKeyException, NoSuchAlgorithmException {
			this.ciphertext = ciphertext;

			byte[] token = buildToken();

			this.signature = generateHash(token, signingKey);

			return Bytes.concat(token,
					// This field is the 256-bit SHA256 HMAC, under signing-key.
					signature);
		}

		private final byte[] buildToken() {
			return Bytes.concat(
					// This field denotes which version of the format is being used by the token.
					byteToByteArray(this.version),
					// This field is a 64-bit unsigned big-endian integer.
					longToByteArray(this.timestamp),
					// The 128-bit Initialization Vector used in AES encryption and decryption of
					// the Ciphertext.
					this.iv,
					// This field has variable size, but is always a multiple of 128 bits, the AES
					// block size.
					this.ciphertext);
		}

		private final byte[] generateHash(byte[] data, byte[] signingKey)
				throws NoSuchAlgorithmException, InvalidKeyException {
			Mac mac;

			SecretKeySpec keySpec = new SecretKeySpec(signingKey, "HmacSHA256");

			mac = Mac.getInstance("HmacSHA256");
			mac.init(keySpec);

			return mac.doFinal(data);
		}

		private final byte[] byteToByteArray(byte value) {
			return new byte[] { value };
		}

		/**
		 * Returns a big-endian representation of {@code value} in an 8-element byte
		 * array; equivalent to {@code ByteBuffer.allocate(8).putLong(value).array()}.
		 * For example, the input value {@code
		 * 0x1213141516171819L} would yield the byte array {@code {0x12, 0x13, 0x14,
		 * 0x15, 0x16, 0x17, 0x18, 0x19}}.
		 *
		 * <p>
		 * If you need to convert and concatenate several values (possibly even of
		 * different types), use a shared {@link java.nio.ByteBuffer} instance, or use
		 * {@link com.google.common.io.ByteStreams#newDataOutput()} to get a growable
		 * buffer.
		 */
		private final byte[] longToByteArray(long value) {
			// Note that this code needs to stay compatible with GWT, which has known
			// bugs when narrowing byte casts of long values occur.
			byte[] result = new byte[8];
			for (int i = 7; i >= 0; i--) {
				result[i] = (byte) (value & 0xffL);
				value >>= 8;
			}
			return result;
		}
	}

	private final Key key;

	public Fernet() {
		// Generate random keys.
		this.key = new Key();
	}

	/**
	 * A URL-safe base64-encoded 32-byte key. This must be kept secret. Anyone with
	 * this key is able to create and read messages.
	 *
	 * @param key
	 * @throws FernetException
	 */
	public Fernet(String key) throws FernetException {
		this.key = new Key(key);
	}

	public Fernet(byte[] key) throws FernetException {
		this.key = new Key(key);
	}

	public Fernet(Key key) {
		this.key = key;
	}

	/**
	 * Generates a fresh fernet key.
	 *
	 * Keep this some place safe! If you lose it you’ll no longer be able to decrypt
	 * messages; if anyone else gains access to it, they’ll be able to decrypt all
	 * of your messages, and they’ll also be able forge arbitrary messages that will
	 * be authenticated and decrypted.
	 *
	 * @return key
	 */
	private static byte[] generateKey() {
		SecureRandom random;
		byte[] key = new byte[KEY_SIZE];

		try {
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			random = new SecureRandom();
		}

		random.nextBytes(key);

		return key;
	}

	/**
	 * The encrypted message contains the current time when it was generated in
	 * plaintext, the time a message was created will therefore be visible to a
	 * possible attacker.
	 *
	 * @param data The message you would like to encrypt.
	 * @return A secure message that cannot be read or altered without the key. It
	 *         is URL-safe base64-encoded. This is referred to as a “Fernet token”.
	 * @throws FernetException
	 */
	public final String encrypt(final byte[] data) throws FernetException {
		return base64UrlEncode(encryptRaw(data));
	}

	/**
	 * The encrypted message contains the current time when it was generated in
	 * plaintext, the time a message was created will therefore be visible to a
	 * possible attacker.
	 *
	 * @param data  The message you would like to encrypt.
	 * @param token The Fernet token to use.
	 * @return A secure message that cannot be read or altered without the key. It
	 *         is URL-safe base64-encoded. This is referred to as a “Fernet token”.
	 * @throws FernetException
	 */
	public final String encrypt(final byte[] data, final Token token) throws FernetException {
		return base64UrlEncode(encryptRaw(data, token));
	}

	/**
	 * The encrypted message contains the current time when it was generated in
	 * plaintext, the time a message was created will therefore be visible to a
	 * possible attacker.
	 *
	 * @param data  The message you would like to encrypt.
	 * @param token The Fernet token to use.
	 * @return A secure message that cannot be read or altered without the key. This
	 *         is referred to as a “Fernet token”.
	 * @throws FernetException
	 */
	public final byte[] encryptRaw(final byte[] data) throws FernetException {
		return encryptRaw(data, new Token());
	}

	/**
	 * The encrypted message contains the current time when it was generated in
	 * plaintext, the time a message was created will therefore be visible to a
	 * possible attacker.
	 *
	 * @param data The message you would like to encrypt.
	 * @return A secure message that cannot be read or altered without the key. This
	 *         is referred to as a “Fernet token”.
	 * @throws FernetException
	 */
	public final byte[] encryptRaw(final byte[] data, final Token token) throws FernetException {
		IvParameterSpec ivSpec = new IvParameterSpec(token.iv);
		SecretKeySpec keySpec = new SecretKeySpec(this.key.encryptionKey, "AES");

		try {
			// In Java, the standard padding name is PKCS5Padding, not PKCS7Padding.
			// Java is actually performing PKCS #7 padding, but in the JCA specification,
			// PKCS5Padding is the name given.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

			byte[] ciphertext = cipher.doFinal(data);

			return token.sign(ciphertext, this.key.signingKey);
		} catch (Exception e) {
			throw new FernetException(e);
		}
	}

	/**
	 * @param data The Fernet token. This is the result of calling encrypt().
	 * @param ttl  Optionally, the number of seconds old a message may be for it to
	 *             be valid. If the message is older than ttl seconds (from the time
	 *             it was originally created) an exception will be raised. If ttl is
	 *             not provided (or is None), the age of the message is not
	 *             considered.
	 * @return The original plaintext.
	 * @throws FernetException
	 */
	public final byte[] decrypt(final Token token, final int ttl) throws FernetException {
		token.verify(ttl, this.key.signingKey);

		try {
			// 6. Decrypt the ciphertext field using AES 128 in CBC mode with the recorded
			// IV and user-supplied encryption-key.
			IvParameterSpec ivSpec = new IvParameterSpec(token.iv);
			SecretKeySpec keySpec = new SecretKeySpec(this.key.encryptionKey, "AES");

			// In Java, the standard padding name is PKCS5Padding, not PKCS7Padding.
			// Java is actually performing PKCS #7 padding, but in the JCA specification,
			// PKCS5Padding is the name given.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

			return cipher.doFinal(token.ciphertext);
		} catch (Exception e) {
			throw new FernetException(e);
		}
	}

	public final byte[] decrypt(final String data, final int ttl) throws FernetException {
		final Token token = new Token(data);
		return decrypt(token, ttl);
	}

	public final byte[] decrypt(final byte[] data, final int ttl) throws FernetException {
		final Token token = new Token(data);
		return decrypt(token, ttl);
	}

	/**
	 *
	 * @param token The Fernet token. This is the result of calling encrypt().
	 * @return The original plaintext.
	 * @throws FernetException
	 */
	public final byte[] decrypt(final String token) throws FernetException {
		return decrypt(token, 0);
	}

	public final byte[] decryptRaw(final byte[] data, final int ttl) throws FernetException {
		return decrypt(data, ttl);
	}

	public final byte[] decryptRaw(final byte[] data) throws FernetException {
		return decryptRaw(data, 0);
	}

	private static long getTime() {
		return System.currentTimeMillis() / 1000L;
	}

	public static String base64UrlEncode(byte[] input) {
		return Base64.encodeUrlSafe(input);
	}

	public static byte[] base64UrlDecode(String input) {
		return Base64.decodeUrlSafe(input);
	}

	public static void main(String[] args) {
		Fernet fernet = new Fernet();
		System.out.println("Key = " + fernet.key);

		try {
			String token = fernet.encrypt("The quick brown fox jumps over the lazy dog.".getBytes());

			System.out.println("Token = " + token);

			byte[] message = fernet.decrypt(token);
			System.out.println("Message = " + new String(message));
		} catch (FernetException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
