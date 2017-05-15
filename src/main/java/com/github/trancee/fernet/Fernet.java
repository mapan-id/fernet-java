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
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.codec.binary.Base64;

import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;

/**
 * Fernet (symmetric encryption)
 *
 * Fernet guarantees that a message encrypted using it cannot be manipulated
 * or read without the key. Fernet is an implementation of symmetric (also
 * known as “secret key”) authenticated cryptography.
 *
 * Fernet Spec
 * https://github.com/fernet/spec/blob/master/Spec.md
 *
 * All encryption in this version is done with AES 128 in CBC mode.
 * All base 64 encoding is done with the "URL and Filename Safe" variant, defined in RFC 4648 as "base64url".
 *
 * @author Philipp Grosswiler <philipp.grosswiler@gmail.com>
 */
@SuppressWarnings("restriction")
public class Fernet {
	public static final byte VERSION = (byte) 0x80;	// 8 bits

	private static final int MIN_TOKEN_SIZE = (8 + 64 + 128 + 0 + 256) >> 3;
	private static final int KEY_SIZE = (128) >> 3;
	private static final int HMAC_SIZE = (256) >> 3;

	private static final int MAX_CLOCK_SKEW = 60;

	/**
	 * Key Format
	 *
	 * A fernet key is the base64url encoding of the following fields:
	 * Signing-key ‖ Encryption-key
	 *
	 * Signing-key, 128 bits
	 * Encryption-key, 128 bits
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
	 * A fernet token is the base64url encoding of the concatenation of the following fields:
	 * Version ‖ Timestamp ‖ IV ‖ Ciphertext ‖ HMAC
	 *
	 * Version, 8 bits
	 * Timestamp, 64 bits
	 * IV, 128 bits
	 * Ciphertext, variable length, multiple of 128 bits
	 * HMAC, 256 bits
	 *
	 * Fernet tokens are not self-delimiting. It is assumed that the transport will provide a means of
	 * finding the length of each complete fernet token.
	 */
	private class Token {
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
		 * This field is a 64-bit unsigned big-endian integer.
		 * It records the number of seconds elapsed between January 1, 1970 UTC and the time the token was created.
		 */
		private long timestamp;

		/**
		 * IV
		 *
		 * The 128-bit Initialization Vector used in AES encryption and decryption of the Ciphertext.
		 *
		 * When generating new fernet tokens, the IV must be chosen uniquely for every token.
		 * With a high-quality source of entropy, random selection will do this with high probability.
		 */
		private byte[] iv = new byte[KEY_SIZE];

		/**
		 * Ciphertext
		 *
		 * This field has variable size, but is always a multiple of 128 bits, the AES block size.
		 * It contains the original input message, padded and encrypted.
		 */
		private byte[] ciphertext;

		/**
		 * HMAC
		 *
		 * This field is the 256-bit SHA256 HMAC, under signing-key,
		 * of the concatenation of the following fields:
		 * Version ‖ Timestamp ‖ IV ‖ Ciphertext
		 *
		 * Note that the HMAC input is the entire rest of the token verbatim,
		 * and that this input is not base64url encoded.
		 */
		private byte[] signature = new byte[HMAC_SIZE];

		public Token() {
			timestamp = getTime();
			iv = generateKey();
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

		public Boolean verify(int ttl) throws FernetException {
			// 2. Ensure the first byte of the token is 0x80.
			if (version != Fernet.VERSION) {
				throw new FernetException("Invalid version.");
			}

			// 3. If the user has specified a maximum age (or "time-to-live") for the token,
			//    ensure the recorded timestamp is not too far in the past.
			if (ttl > 0) {
				long currentTime = getTime();

				if (timestamp + ttl < currentTime || currentTime + MAX_CLOCK_SKEW < timestamp) {
					throw new TokenExpiredException("Token has expired.");
				}
			}

			// 4. Recompute the HMAC from the other fields and the user-supplied signing-key.
			byte[] token = buildToken();

			// 5. Ensure the recomputed HMAC matches the HMAC field stored in the token,
			//    using a constant-time comparison function.
			try {
				if (! Arrays.equals(signature, generateHash(token))) {
					throw new FernetException("Invalid signature.");
				}
			} catch (Exception e) {
				throw new FernetException(e);
			}

			return true;
		}

		public byte[] sign(byte[] ciphertext) throws InvalidKeyException, NoSuchAlgorithmException {
			this.ciphertext = ciphertext;

			byte[] token = buildToken();

			this.signature = generateHash(token);

			return Bytes.concat(
					token,
					// This field is the 256-bit SHA256 HMAC, under signing-key.
					signature
					);
		}

		private final byte[] buildToken() {
			return Bytes.concat(
					// This field denotes which version of the format is being used by the token.
					byteToByteArray(this.version),
					// This field is a 64-bit unsigned big-endian integer.
					Longs.toByteArray(this.timestamp),
					// The 128-bit Initialization Vector used in AES encryption and decryption of the Ciphertext.
					this.iv,
					// This field has variable size, but is always a multiple of 128 bits, the AES block size.
					this.ciphertext
					);
		}

		private final byte[] byteToByteArray(byte input) {
			byte[] output = new byte[1];

			output[0] = input;

			return output;
		}
	}

	private final Key key;

	public Fernet() {
		// Generate random keys.
		this.key = new Key();
	}
	/**
	 * A URL-safe base64-encoded 32-byte key. This must be kept secret.
	 * Anyone with this key is able to create and read messages.
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

	public static String toHex(byte[] data) {
		return DatatypeConverter.printHexBinary(data).toLowerCase();
	}

	private final byte[] generateHash(byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac;

		SecretKeySpec keySpec = new SecretKeySpec(this.key.signingKey, "HmacSHA256");

		mac = Mac.getInstance("HmacSHA256");
		mac.init(keySpec);

		return mac.doFinal(data);
	}

	/**
	 * Generates a fresh fernet key.
	 *
	 * Keep this some place safe! If you lose it you’ll no longer be able to decrypt messages;
	 * if anyone else gains access to it, they’ll be able to decrypt all of your messages,
	 * and they’ll also be able forge arbitrary messages that will be authenticated and decrypted.
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
	 * The encrypted message contains the current time when it was
	 * generated in plaintext, the time a message was created will
	 * therefore be visible to a possible attacker.
	 *
	 * @param data
	 * The message you would like to encrypt.
	 * @return
	 * A secure message that cannot be read or altered without the key.
	 * It is URL-safe base64-encoded. This is referred to as a “Fernet token”.
	 * @throws FernetException
	 */
	public final String encrypt(final byte[] data) throws FernetException {
		return base64UrlEncode(encryptRaw(data));
	}
	/**
	 * The encrypted message contains the current time when it was
	 * generated in plaintext, the time a message was created will
	 * therefore be visible to a possible attacker.
	 *
	 * @param data
	 * The message you would like to encrypt.
	 * @return
	 * A secure message that cannot be read or altered without the key.
	 * This is referred to as a “Fernet token”.
	 * @throws FernetException
	 */
	public final byte[] encryptRaw(final byte[] data) throws FernetException {
		final Token token = new Token();

		IvParameterSpec ivSpec = new IvParameterSpec(token.iv);
		SecretKeySpec keySpec = new SecretKeySpec(key.encryptionKey, "AES");

		try {
			// In Java, the standard padding name is PKCS5Padding, not PKCS7Padding.
			// Java is actually performing PKCS #7 padding, but in the JCA specification,
			// PKCS5Padding is the name given.
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

			byte[] ciphertext = cipher.doFinal(data);

			return token.sign(ciphertext);
		} catch (Exception e) {
			throw new FernetException(e);
		}
	}
	/**
	 * @param data
	 * The Fernet token. This is the result of calling encrypt().
	 * @param ttl
	 * Optionally, the number of seconds old a message may be for it to be valid.
	 * If the message is older than ttl seconds (from the time it was originally created)
	 * an exception will be raised. If ttl is not provided (or is None), the age of
	 * the message is not considered.
	 * @return
	 * The original plaintext.
	 * @throws FernetException
	 */
	public final byte[] decrypt(final Token token, final int ttl) throws FernetException {
		token.verify(ttl);

		try {
			// 6. Decrypt the ciphertext field using AES 128 in CBC mode with the recorded IV and user-supplied encryption-key.
			IvParameterSpec ivSpec = new IvParameterSpec(token.iv);
			SecretKeySpec keySpec = new SecretKeySpec(key.encryptionKey, "AES");

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
	 * @param token
	 * The Fernet token. This is the result of calling encrypt().
	 * @return
	 * The original plaintext.
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
		return Base64.encodeBase64URLSafeString(input);
		// return Base64.getUrlEncoder()/*.withoutPadding()*/.encodeToString(input);	// Java 8
	}
	public static byte[] base64UrlDecode(String input) {
		return Base64.decodeBase64(input);
		// return Base64.getUrlDecoder().decode(input);	// Java 8
	}

	public static void main( String[] args )
	{
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
