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
		byte[] decryptedBytes = decrypt(encryptedBytes,privateKey);

		System.out.println("Number of bytes (decrypted): " + decryptedBytes.length);
		System.out.println("Decrypted String: " + new String(decryptedBytes));
		
	
	}

	public static byte[] encryptSessionKey(byte[] unencrypted, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		
		//after client establish connection with the server
		
		//init cipher 
		SecretKey sessionKey = KeyGenerator.getInstance("AES").generateKey();
		Cipher sessionCipher = Cipher.getInstance("AES/ECD/PKCS5Padding");
		sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
	
		//encrypt session key 
		byte[] encryptedsessionKey = sessionCipher.doFinal(unencrypted);
		
		//convert AES session key to bytes
		byte[] secretkeyByte = key.getEncoded();
		
		//encrypt fileName 
		
				
	}
	public static byte[] decrypt(byte[] encrypted, Key key) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException{
		Cipher rsaCipherDecrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		rsaCipherDecrypt.init(Cipher.DECRYPT_MODE, key);
		return rsaCipherDecrypt.doFinal(encrypted);
	}
}
