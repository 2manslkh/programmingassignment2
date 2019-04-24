package com.example.lib_probset2;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Auth {

    public static void main(String[] args) throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        X509Certificate cacert = getX509Certificate(new FileInputStream("cacse.crt"));
        X509Certificate servercert = getX509Certificate(new FileInputStream("server.crt"));
        // get public key of cacert
        PublicKey cakey = cacert.getPublicKey();
        servercert.checkValidity();
        servercert.verify(cakey); // throws error if not valid
        System.out.println("ASD");// can liao just use eclipse to work
    }

    public static boolean verifiedServer(String certname) throws FileNotFoundException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        X509Certificate cacert = getX509Certificate(new FileInputStream("cacse.crt"));
        X509Certificate servercert = getX509Certificate(new FileInputStream(certname));
        // get public key of cacert
        PublicKey cakey = cacert.getPublicKey();
        servercert.checkValidity();
        servercert.verify(cakey); // throws error if not vality
        return true;
    }
    public static boolean verifiedNonce(byte[] encryptedNonce, int nonce, Key publicKey) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
        int decryptedNonce = decryptNonce(encryptedNonce,publicKey);
        return decryptedNonce==nonce;
    }


    // Make X509Certificate from .crt file
    public static X509Certificate getX509Certificate(InputStream input) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate output = (X509Certificate)cf.generateCertificate(input);
        return output;
    }

    public static byte[] encryptString(String input, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Message Encrypted");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(input.getBytes());
    }

    public static byte[] encryptNonce(int input, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Nonce Encrypted");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        ByteBuffer b = ByteBuffer.allocate(4);
        b.putInt(input);
        return cipher.doFinal(b.array());

    }

    public static int decryptNonce(byte[] input, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        System.out.println("Nonce Decrypted");
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] inputDecrypted = cipher.doFinal(input);
        return ByteBuffer.wrap(inputDecrypted).getInt();
    }

    // Get Public Key from X509 Certificate
    public static PublicKey getPublicKey(String certname) throws FileNotFoundException, CertificateException {
        X509Certificate servercert = getX509Certificate(new FileInputStream(certname));
        return servercert.getPublicKey();
    }

    public static PrivateKey readPrivateKey(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
    {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(readFileBytes(filename));
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }

    private static byte[] readFileBytes(String filename) throws IOException
    {
        Path path = Paths.get(filename);
        return Files.readAllBytes(path);
    }

}
