package com.example;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;

import org.bouncycastle.util.encoders.Base64;

public class MyExternalSignatureContainer2 implements ExternalSignatureContainer  {

    public MyExternalSignatureContainer2() {
        
    }

    public byte[] sign(InputStream is) throws GeneralSecurityException {
        try {
            String hashAlgorithm = DigestAlgorithms.SHA256;
            BouncyCastleDigest digest = new BouncyCastleDigest();

            byte hash[] = DigestAlgorithms.digest(is, digest.getMessageDigest(hashAlgorithm));
            System.out.println("2: " + Base64.toBase64String(hash));

            return is.readAllBytes();
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    public void modifySigningDictionary(com.itextpdf.text.pdf.PdfDictionary signDic) {
    }
}