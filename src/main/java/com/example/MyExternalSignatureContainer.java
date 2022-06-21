package com.example;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.PdfPKCS7;
import com.itextpdf.text.pdf.security.PrivateKeySignature;

public class MyExternalSignatureContainer implements IExternalSignatureContainer {

    protected PrivateKey pk;
    protected Certificate[] chain;

    public MyExternalSignatureContainer(PrivateKey pk, Certificate[] chain) {
        this.pk = pk;
        this.chain = chain;
    }

    public byte[] sign(InputStream is) throws GeneralSecurityException {
        try {
            PrivateKeySignature signature = new PrivateKeySignature(pk, "SHA256", "BC");
            String hashAlgorithm = signature.getHashAlgorithm();
            BouncyCastleDigest digest = new BouncyCastleDigest();

            PdfPKCS7 sgn = new PdfPKCS7(null, chain, hashAlgorithm, null, digest, false);
            byte hash[] = DigestAlgorithms.digest(is, digest.getMessageDigest(hashAlgorithm));
            byte[] sh = sgn.getAuthenticatedAttributeBytes(hash, null, null, null);
            byte[] extSignature = signature.sign(sh);
            sgn.setExternalDigest(extSignature, null, signature.getEncryptionAlgorithm());

            return sgn.getEncodedPKCS7(hash);
        } catch (IOException ioe) {
            throw new RuntimeException(ioe);
        }
    }

    @Override public void modifySigningDictionary(PdfDictionary signDic) {
    }
}