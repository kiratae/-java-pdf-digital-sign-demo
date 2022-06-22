package com.example;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import org.bouncycastle.util.encoders.Base64;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;

public class MyExternalSignatureContainer implements ExternalSignatureContainer {

    protected PrivateKey pk;
    protected Certificate[] chain;

    public MyExternalSignatureContainer(PrivateKey pk, Certificate[] chain) {
        this.pk = pk;
        this.chain = chain;
    }

    public byte[] sign(InputStream is) throws GeneralSecurityException {
        try {
            PrivateKeySignature signature = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, "BC");
            BouncyCastleDigest digest = new BouncyCastleDigest();

            PdfPKCS7 sgn = new PdfPKCS7(null, chain, DigestAlgorithms.SHA256, null, digest, false);
            byte hash[] = DigestAlgorithms.digest(is, digest.getMessageDigest(DigestAlgorithms.SHA256));
            System.out.println("1: " + Base64.toBase64String(hash));
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, PdfSigner.CryptoStandard.CMS, null, null);
            byte[] extSignature = signature.sign(sh);
            sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());

            return sgn.getEncodedPKCS7(hash, PdfSigner.CryptoStandard.CMS, null, null, null);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    public void modifySigningDictionary(com.itextpdf.text.pdf.PdfDictionary signDic) {
    }
}