package com.example;

import java.io.InputStream;
import java.security.GeneralSecurityException;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.signatures.IExternalSignatureContainer;

public class MyExternalSignatureContainer implements IExternalSignatureContainer {

    protected byte[] signedBytes;

    public MyExternalSignatureContainer(byte[] signedBytes) {
        this.signedBytes = signedBytes;
    }

    public byte[] sign(InputStream is) throws GeneralSecurityException {
        return signedBytes;
    }

    @Override public void modifySigningDictionary(PdfDictionary signDic) {
    }
}