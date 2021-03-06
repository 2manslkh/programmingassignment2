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
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.DatatypeConverter;

public class ClientCP1 {

	public static void main(String[] args) throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, IllegalBlockSizeException {
		String unencrypted = "Hello";
		System.out.println("Original String: " + unencrypted);
		byte [] unencryptedBytes = unencrypted.getBytes();
		PublicKey publicKey = Auth.getPublicKey("recv_server.crt");
		PrivateKey privateKey = Auth.readPrivateKey("privateServer.der");

		byte[] encryptedBytes = encrypt(unencryptedBytes,publicKey);
		System.out.println("Number of bytes (unencrypted): " + unencryptedBytes.length);
		System.out.println("Number of bytes (encrypted): " + encryptedBytes.length);
		System.out.println("Encrypted Base64 String: " + DatatypeConverter.printBase64Binary(encryptedBytes));
		byte[] decryptedBytes = decrypt(encryptedBytes,privateKey);

		System.out.println("Number of bytes (decrypted): " + decryptedBytes.length);
		System.out.println("Decrypted String: " + new String(decryptedBytes));

	}

	public static byte[] encrypt(byte[] unencrypted, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher rsaCipherEncrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherEncrypt.init(Cipher.ENCRYPT_MODE, key);
		return rsaCipherEncrypt.doFinal(unencrypted); //now itz encrypted 
				
	}
	public static byte[] decrypt(byte[] encrypted, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, key);
		return rsaCipherDecrypt.doFinal(encrypted);
	}
}
