package com.example.lib_probset2;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CertificateChecker {
    public static void main(String[] args) throws Exception {
        InputStream fis_server = new FileInputStream("server.crt");
        InputStream fis_cacse = new FileInputStream("cacse.crt");
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate serverCert = (X509Certificate)cf.generateCertificate(fis_server);
        X509Certificate cacseCert = (X509Certificate)cf.generateCertificate(fis_cacse);
        PublicKey verifykey = cacseCert.getPublicKey();
        serverCert.checkValidity();
        serverCert.verify(verifykey);
    }

}
