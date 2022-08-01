package com.example;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.font.FontCache;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;

/**
 * Hello world!
 *
 */
public class App {
        public static final String KEYSTORE = "keys\\TanapornKleaklom.pfx";
        public static final char[] PASSWORD = "password".toCharArray();
        public static final String SRC = "C:\\my\\temp\\hello.pdf";
        public static final String TEMP = "C:\\my\\temp\\hello-temp.pdf";
        public static final String TEMP2 = "C:\\my\\temp\\hello-temp2.pdf";
        public static final String DEST = "C:\\my\\temp\\hello_signed%s.pdf";
        public static final String DEST2 = "C:\\my\\temp\\hello_signed.pdf";
        public static final String IMG = "./src/main/resources/img/logo.png";
        public static final String SIGNAME = "signature";
        public static final String INFO_KEY = "doeb_oilstock_uuid";

        public static void main(String[] args) throws Exception {
                System.out.println("Hello World!");
                CreateEmpty();

                File ksFile = new File(KEYSTORE);
                KeyStore keystore = KeyStore.getInstance("PKCS12");
                char[] password = PASSWORD;
                try (InputStream is = new FileInputStream(ksFile)) {
                        keystore.load(is, password);
                }

                File documentFile = new File(SRC);

                CreateVisibleSignature signing = new CreateVisibleSignature(keystore, password.clone());

                File signedDocumentFile;
                int page;
                String name = documentFile.getName();
                String substring = name.substring(0, name.lastIndexOf('.'));
                String ouputFileName = substring + "_signed.pdf";
                try (InputStream imageStream = new FileInputStream(IMG)) {
                        signedDocumentFile = new File(documentFile.getParent(), ouputFileName);
                        // page is 1-based here
                        page = 1;
                        signing.setVisibleSignDesigner(SRC, 0, 0, -50, imageStream, page);
                }
                signing.setVisibleSignatureProperties("name", "location", "Security", 0, page, true);
                signing.setExternalSigning(false);
                signing.signPDF(documentFile, signedDocumentFile, "", SIGNAME);

                // register BouncyCastle provider, needed for "exotic" algorithms
                Security.addProvider(SecurityProvider.getProvider());

                ShowSignature show = new ShowSignature();
                show.showSignature(DEST2);
        }

        static void CreateEmpty() throws IOException {
                // Create a new document with an empty page.
                try (PDDocument document = new PDDocument()) {
                        PDPage page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        PDDocumentInformation docInfo = document.getDocumentInformation();
                        docInfo.setCustomMetadataValue("uuid", "123456");

                        // Add a new AcroForm and add that to the document
                        PDAcroForm acroForm = new PDAcroForm(document);
                        document.getDocumentCatalog().setAcroForm(acroForm);

                        // Create empty signature field, it will get the name "Signature1"
                        PDSignatureField signatureField = new PDSignatureField(acroForm);
                        signatureField.setPartialName(SIGNAME);
                        PDAnnotationWidget widget = signatureField.getWidgets().get(0);
                        PDRectangle rect = new PDRectangle(50, 650, 200, 50);
                        widget.setRectangle(rect);
                        widget.setPage(page);

                        // see thread from PDFBox users mailing list 17.2.2021 - 19.2.2021
                        // https://mail-archives.apache.org/mod_mbox/pdfbox-users/202102.mbox/thread
                        widget.setPrinted(true);

                        page.getAnnotations().add(widget);

                        acroForm.getFields().add(signatureField);

                        document.save(SRC);
                }
        }
}
