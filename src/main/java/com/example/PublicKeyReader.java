package com.example;

import java.io.FileInputStream;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.*;

public class PublicKeyReader {

    public static PublicKey get(String filename)
            throws Exception {

        // byte[] keyBytes = Files.readAllBytes(Paths.get(filename));
        // X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        // KeyFactory kf = KeyFactory.getInstance("RSA");
        // return kf.generatePublic(spec);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        FileInputStream is = new FileInputStream(filename);

        X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);

        return cer.getPublicKey();
    }
}
