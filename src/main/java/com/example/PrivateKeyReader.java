package com.example;

import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.PrivateKey;

import java.io.FileReader;
import java.io.IOException;
import java.security.PrivateKey;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class PrivateKeyReader {

    public static PrivateKey get(String filename)
            throws Exception {

        // byte[] keyBytes = Files.readAllBytes(Paths.get(filename));

        // PKCS8EncodedKeySpec spec =
        // new PKCS8EncodedKeySpec(keyBytes);
        // KeyFactory kf = KeyFactory.getInstance("RSA");

        // return kf.generatePrivate(spec);

        try (PEMParser reader = new PEMParser(new FileReader(filename))) {
            PrivateKeyInfo info = null;

            // the return type depends on whether the file contains a single key or a key
            // pair
            Object bouncyCastleResult = reader.readObject();

            if (bouncyCastleResult instanceof PrivateKeyInfo) {
                info = (PrivateKeyInfo) bouncyCastleResult;
            } else if (bouncyCastleResult instanceof PEMKeyPair) {
                PEMKeyPair keys = (PEMKeyPair) bouncyCastleResult;
                info = keys.getPrivateKeyInfo();
            } else {
                throw new Exception("No private key found in the provided file");
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

            return converter.getPrivateKey(info);
        }
    }
}
