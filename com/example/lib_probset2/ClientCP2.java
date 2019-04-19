package com.example.lib_probset2;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

//This! protocol! uses!
//AES! for! data! confidentiality.!Your! protocol!must! negotiate a! session! key!
//for!the!AES!after!the!client!has!established!a connection!with!the server.!It!
//must!also!ensure!the!confidentiality!of!the!session!key!itself.

public class ClientCP2 {
	//make session key to encrypt a symmetric key 
	public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
		String unencrypted = "Hello";
		System.out.println("Original String: " + unencrypted);
		byte [] unencryptedBytes = unencrypted.getBytes();
		PublicKey publicKey = Auth.getPublicKey("recv_server.crt");
		PrivateKey privateKey = Auth.readPrivateKey("privateServer.der");

		byte[] encryptedBytes = encryptSessionKey(unencryptedBytes,publicKey);
		System.out.println("Number of bytes (unencrypted): " + unencryptedBytes.length);
		System.out.println("Number of bytes (encrypted): " + encryptedBytes.length);
		System.out.println("Encrypted Base64 String: " + DatatypeConverter.printBase64Binary(encryptedBytes));
		byte[] decryptedBytes = ClientCP1.decrypt(encryptedBytes,privateKey);

		System.out.println("Number of bytes (decrypted): " + decryptedBytes.length);
		System.out.println("Decrypted String: " + new String(decryptedBytes));

	}

	public static SecretKey generateSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		return KeyGenerator.getInstance("AES").generateKey();
	}

	public static byte[] encryptSessionKey(byte[] unencryptedSessionKey, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		byte[] encryptedSessionKey = ClientCP1.encrypt(unencryptedSessionKey, key);
		return encryptedSessionKey;
	}

	public static SecretKey decryptSessionKey(byte[] encryptedSessionKey, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		byte[] decryptedSessionKey = ClientCP1.decrypt(encryptedSessionKey,key); //decrypt session key with Private Key (Server)
		SecretKey sessionKey = new SecretKeySpec(decryptedSessionKey, 0, decryptedSessionKey.length, "AES");
		return sessionKey;
	}

	public static byte[] encrypt(byte[] unencrypted, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher rsaCipherEncrypt = Cipher.getInstance("AES/ECB/PKCS5Padding"); // SessionKey AES Encryption
		rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, key);
		return rsaCipherEncrypt.doFinal(unencrypted);

	}

	public static byte[] decrypt(byte[] encrypted, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher rsaCipherDecrypt = Cipher.getInstance("AES/ECB/PKCS5Padding"); // SessionKey AES Decryption
		rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, key);
		return rsaCipherDecrypt.doFinal(encrypted);
	}
}
