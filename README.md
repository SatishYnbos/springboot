# springboot
to evaluate spring




package com.dbs.ipe.batch.encryption;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Base64Utils;

import com.dbs.ipe.batch.util.FileUtil;

public class TripleDES {
	private static final Logger logger = LoggerFactory.getLogger(TripleDES.class);

	// Changing to 'AES' from 'DESede'
	private static final String cipherProvider = "DESede";
	private static final String INNER_KEY = "NCS.EADV.INNER_KEY";
	private static final String ENCODING = "UTF-8";

	public static void main(String[] args) {
		encodePassword(args);
	}

	private static void encodePassword(String[] args) {
		TripleDES des = new TripleDES();
		// Check to see whether there is a provider that can do TripleDES
		// encryption. If not, explicitly install the SunJCE provider.
		/*
		 * try{ try { logger.info("Started encoding of password"); Cipher cipher =
		 * Cipher.getInstance(cipherProvider); logger.info("Found cipher."); } catch
		 * (Exception e) { // An exception here probably means the JCE provider hasn't
		 * // been permanently installed on this system by listing it // in the
		 * $JAVA_HOME/jre/lib/security/java.security file. // Therefore, we have to
		 * install the JCE provider explicitly.
		 * //System.err.println("INFO : Installing SunJCE provider.");
		 * logger.info("INFO : Installing SunJCE provider."); Provider sunjce = new
		 * com.sun.crypto.provider.SunJCE(); Security.addProvider(sunjce); }
		 * 
		 * if (args==null || args.length<2){
		 * logger.info("Please input 2 arguments : key,password"); } else if
		 * (args.length>2 && args[2].equalsIgnoreCase("-d")){
		 * logger.info("DECRYPTION_RESULT|" +
		 * FileUtil.cleanString(des.decrypt(validate(args[0]), validate(args[1])))); } }
		 * catch (Exception e){ logger.error(e.getMessage()); }
		 */

		TripleDES tripleDES = new TripleDES();
		String keyString = "ipe2";
		String pwd = "Ipe2tw_1234";

		String encryptedText;
		try {
			encryptedText = tripleDES.encrypt(keyString, pwd);
			System.out.println("encryptedText :" + encryptedText);

			String decrypteText = tripleDES.decrypt(keyString, encryptedText);
			System.out.println("decrypteText :" + decrypteText);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public String encrypt(String keyString, String password) throws Exception {
		return Base64Utils.encodeToString(encrypt(getKey(keyString), password));
	}

	public String decrypt(String keyString, String encrytedPassword) throws Exception {
		return decrypt(getKey(keyString), encrytedPassword);
	}

	/**
	 * Use the specified TripleDES key to encrypt bytes from the input stream and
	 * write them to the output stream. This method uses CipherOutputStream to
	 * perform the encryption and write bytes at the same time.
	 */
	public byte[] encrypt(SecretKey key, String password) throws Exception {
		// Create and initialize the encryption engine
		Cipher cipher = Cipher.getInstance(cipherProvider);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(password.getBytes(ENCODING));
	}

	/**
	 * Use the specified TripleDES key to decrypt bytes ready from the input stream
	 * and write them to the output stream. This method uses uses Cipher directly to
	 * show how it can be done without CipherInputStream and CipherOutputStream.
	 */
	public String decrypt(SecretKey key, String encrytedPassword) throws Exception {
		// Create and initialize the decryption engine
		Cipher cipher = Cipher.getInstance(cipherProvider);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] bOut = cipher.doFinal(Base64Utils.decodeFromString(encrytedPassword));
		return (new String(bOut, ENCODING));

	}

	private SecretKey getKey(String userDefinedKey) {
		String innerKey = INNER_KEY;

		// Make the Key
		try {
			String finalKey = innerKey + userDefinedKey + innerKey + "12345678901234567890";
			byte[] keyB = new byte[24];
			for (int i = 0; i < finalKey.length() && i < keyB.length; i++)
				keyB[i] = (byte) finalKey.charAt(i);
			return new SecretKeySpec(keyB, cipherProvider);
		} catch (Exception e) {
			logger.error(e.getMessage());
		}
		return null;

	}

	/*
	 * public String getUserDefineKey(){ String key=""; String filePath =
	 * CommonConstants.CONFIG_FILE_PATH + "key.txt"; try { key =
	 * FileUtil.readFileAsString(filePath); } catch (IOException e) { logger.
	 * error("Can't get key for encrypt or decrypt, please to check the file " +
	 * filePath); logger.error(e.getMessage()); } return key; }
	 */

	public static String validate(String str) {
		return str;
	}

	public static SecretKey generateKey() {
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128);
			return kgen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e.toString());
		}
	}

	public static byte[] encryptCbc(SecretKey skey, String plaintext) {
		/* Precond: skey is valid; otherwise IllegalStateException will be thrown. */
		try {
			byte[] ciphertext = null;
			Cipher cipher = Cipher.getInstance("AES");
			final int blockSize = cipher.getBlockSize();
			byte[] initVector = new byte[blockSize];
			(new SecureRandom()).nextBytes(initVector);
			IvParameterSpec ivSpec = new IvParameterSpec(initVector);
			cipher.init(Cipher.ENCRYPT_MODE, skey, ivSpec);
			byte[] encoded = plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8);
			ciphertext = new byte[initVector.length + cipher.getOutputSize(encoded.length)];
			for (int i = 0; i < initVector.length; i++) {
				ciphertext[i] = initVector[i];
			}
			// Perform encryption
			cipher.doFinal(encoded, 0, encoded.length, ciphertext, initVector.length);
			return ciphertext;
		} catch (NoSuchPaddingException | InvalidAlgorithmParameterException | ShortBufferException
				| BadPaddingException | IllegalBlockSizeException | InvalidKeyException | NoSuchAlgorithmException e) {
			/* None of these exceptions should be possible if precond is met. */
			throw new IllegalStateException(e.toString());
		}
	}

	public static String decryptCbc(SecretKey skey, byte[] ciphertext)
			throws BadPaddingException, IllegalBlockSizeException /* these indicate corrupt or malicious ciphertext */
	{
		try {
			Cipher cipher = Cipher.getInstance("AES");
			final int blockSize = cipher.getBlockSize();
			byte[] initVector = Arrays.copyOfRange(ciphertext, 0, blockSize);
			IvParameterSpec ivSpec = new IvParameterSpec(initVector);
			cipher.init(Cipher.DECRYPT_MODE, skey, ivSpec);
			byte[] plaintext = cipher.doFinal(ciphertext, blockSize, ciphertext.length - blockSize);
			return new String(plaintext);
		} catch (NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException
				| NoSuchAlgorithmException e) {
			/* None of these exceptions should be possible if precond is met. */
			throw new IllegalStateException(e.toString());
		}
	}
}

