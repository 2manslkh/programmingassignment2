

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

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

    public static boolean verifiedServer(String certname){

        return true;
    }

    // Make X509Certificate from .crt file
    public static X509Certificate getX509Certificate(InputStream input) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate output = (X509Certificate)cf.generateCertificate(input);
        return output;
    }

    public static String encryptString(String input){
        return "";
    }

    // Get Public Key from X509 Certificate
    public static PublicKey getPublicKey(X509Certificate input){
        return input.getPublicKey();
    }



}
