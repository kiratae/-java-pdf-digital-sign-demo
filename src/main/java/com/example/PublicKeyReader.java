package com.example;

import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class PublicKeyReader {

    public static X509Certificate get(String filename)
            throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        FileInputStream is = new FileInputStream(filename);

        return (X509Certificate) certFactory.generateCertificate(is);
    }
}
