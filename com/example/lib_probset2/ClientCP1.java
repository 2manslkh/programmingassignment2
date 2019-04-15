package com.example.lib_probset2;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientCP1 {
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
