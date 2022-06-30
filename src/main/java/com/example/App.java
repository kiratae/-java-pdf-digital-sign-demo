package com.example;

import java.io.ByteArrayOutputStream;
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
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.forms.fields.PdfFormField;
import com.itextpdf.io.image.ImageData;
import com.itextpdf.io.image.ImageDataFactory;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfArray;
import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfDocumentInfo;
import com.itextpdf.kernel.pdf.PdfName;
import com.itextpdf.kernel.pdf.PdfNumber;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfStream;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.annot.PdfAnnotation;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.IExternalSignatureContainer;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;
import com.itextpdf.signatures.PrivateKeySignature;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.SignatureUtil;
import com.itextpdf.text.DocumentException;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.ExternalSignatureContainer;
import com.itextpdf.text.pdf.security.MakeSignature;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

/**
 * Hello world!
 *
 */
public class App {
        public static final String KEYSTORE = "keys\\TanapornKleaklom.pfx";
        public static final String PUB_KEY = "keys\\clicknext.ibs-l.com.crt";
        public static final String PRV_KEY = "keys\\clicknext.ibs-l.com.key";
        public static final char[] PASSWORD = "password".toCharArray();
        public static final String SRC = "C:\\my\\temp\\hello.pdf";
        public static final String TEMP = "C:\\my\\temp\\hello-temp.pdf";
        public static final String TEMP2 = "C:\\my\\temp\\hello-temp2.pdf";
        public static final String DEST = "C:\\my\\temp\\hello_signed%s.pdf";
        public static final String IMG = "./src/main/resources/img/logo.png";
        public static final String SIGNAME = "signature";
        public static final String INFO_KEY = "doeb_oilstock_uuid";

        public static void main(String[] args) throws Exception {
                System.out.println("Hello World!");
                String uuid = UUID.randomUUID().toString();
                System.out.println(String.format("uuid %s", uuid));
                BouncyCastleProvider provider = new BouncyCastleProvider();
                Security.addProvider(provider);
                KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(new FileInputStream(KEYSTORE), PASSWORD);
                String alias = (String) ks.aliases().nextElement();
                PrivateKey pk = (PrivateKey) ks.getKey(alias, PASSWORD);
                Certificate[] chain = ks.getCertificateChain(alias);
                ImageData image = ImageDataFactory.create(IMG);

                PublicKey publicKey = PublicKeyReader.get(PUB_KEY);
                PrivateKey privateKey = PrivateKeyReader.get(PRV_KEY);
                System.out.println(publicKey.getAlgorithm());

                String location = "TH";

                createPdf(SRC, uuid);

                sign(SRC, SIGNAME, String.format(DEST, 1), chain, pk,
                                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                                "Test 1", location, PdfSignatureAppearance.RenderingMode.DESCRIPTION, null);

                sign(SRC, SIGNAME, String.format(DEST, 2), chain, pk,
                                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                                "Test 2", location, PdfSignatureAppearance.RenderingMode.NAME_AND_DESCRIPTION, null);

                sign(SRC, SIGNAME, String.format(DEST, 3), chain, pk,
                                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                                "Test 3", location, PdfSignatureAppearance.RenderingMode.GRAPHIC_AND_DESCRIPTION,
                                image);

                sign(SRC, SIGNAME, String.format(DEST, 4), chain, pk,
                                DigestAlgorithms.SHA256, provider.getName(), PdfSigner.CryptoStandard.CMS,
                                "Test 4", location, PdfSignatureAppearance.RenderingMode.GRAPHIC, image);

                verifySignatures(String.format(DEST, 1), uuid);
                verifySignatures(String.format(DEST, 2), uuid);
                verifySignatures(String.format(DEST, 3), uuid);
                verifySignatures(String.format(DEST, 4), uuid);
        }

        public static void createPdf(String filename, String uuid) throws IOException {
                PdfDocument pdfDoc = new PdfDocument(new PdfWriter(filename));
                PdfDocumentInfo info = pdfDoc.getDocumentInfo();
                Document doc = new Document(pdfDoc);

                info.setMoreInfo(INFO_KEY, uuid);
                doc.add(new Paragraph("Hello World!"));

                // Create a signature form field
                PdfFormField field = PdfFormField.createSignature(pdfDoc, new Rectangle(72, 632, 200, 100));
                field.setFieldName(SIGNAME);
                field.setPage(1);

                // Set the widget properties
                field.getWidgets().get(0).setHighlightMode(PdfAnnotation.HIGHLIGHT_INVERT)
                                .setFlags(PdfAnnotation.PRINT);

                PdfDictionary mkDictionary = field.getWidgets().get(0).getAppearanceCharacteristics();
                if (null == mkDictionary) {
                        mkDictionary = new PdfDictionary();
                }

                PdfArray black = new PdfArray();
                black.add(new PdfNumber(ColorConstants.BLACK.getColorValue()[0]));
                black.add(new PdfNumber(ColorConstants.BLACK.getColorValue()[1]));
                black.add(new PdfNumber(ColorConstants.BLACK.getColorValue()[2]));
                mkDictionary.put(PdfName.BC, black);

                PdfArray white = new PdfArray();
                white.add(new PdfNumber(ColorConstants.WHITE.getColorValue()[0]));
                white.add(new PdfNumber(ColorConstants.WHITE.getColorValue()[1]));
                white.add(new PdfNumber(ColorConstants.WHITE.getColorValue()[2]));
                mkDictionary.put(PdfName.BG, white);

                field.getWidgets().get(0).setAppearanceCharacteristics(mkDictionary);

                PdfAcroForm.getAcroForm(pdfDoc, true).addField(field);

                Rectangle rect = new Rectangle(0, 0, 200, 100);
                PdfFormXObject xObject = new PdfFormXObject(rect);
                PdfCanvas canvas = new PdfCanvas(xObject, pdfDoc);
                canvas
                                .setStrokeColor(ColorConstants.BLUE)
                                .setFillColor(ColorConstants.LIGHT_GRAY)
                                .rectangle(0 + 0.5, 0 + 0.5, 200 - 0.5, 100 - 0.5)
                                .fillStroke()
                                .setFillColor(ColorConstants.BLUE);
                try (Canvas c = new Canvas(canvas, rect)) {
                        c.showTextAligned("SIGN HERE", 100, 50,
                                        TextAlignment.CENTER, (float) Math.toRadians(25));
                }
                // Note that Acrobat doesn't show normal appearance in the highlight mode.
                field.getWidgets().get(0).setNormalAppearance(xObject.getPdfObject());

                doc.close();
        }

        public static void sign(String src, String name, String dest, Certificate[] chain, PrivateKey pk,
                        String digestAlgorithm, String provider, PdfSigner.CryptoStandard subfilter,
                        String reason, String location, PdfSignatureAppearance.RenderingMode renderingMode,
                        ImageData image)
                        throws GeneralSecurityException, IOException {
                PdfReader reader = new PdfReader(src);

                // Pass the temporary file's path to the PdfSigner constructor
                PdfSigner signer = new PdfSigner(reader, new FileOutputStream(dest), new StampingProperties());

                // Create the signature appearance
                PdfSignatureAppearance appearance = signer.getSignatureAppearance();

                appearance.setReason(reason);
                appearance.setLocation(location);

                // This name corresponds to the name of the field that already exists in the
                // document.
                signer.setFieldName(name);

                // Set the custom text and a custom font
                appearance.setLayer2Text("Signed on " + new Date().toString());

                // Set the rendering mode for this signature.
                appearance.setRenderingMode(renderingMode);

                // Set the Image object to render when the rendering mode is set to
                // RenderingMode.GRAPHIC
                // or RenderingMode.GRAPHIC_AND_DESCRIPTION.
                appearance.setSignatureGraphic(image);

                IExternalSignature pks = new PrivateKeySignature(pk, digestAlgorithm, provider);
                IExternalDigest digest = new BouncyCastleDigest();

                // Sign the document using the detached mode, CMS or CAdES equivalent.
                signer.signDetached(digest, pks, chain, null, null, null, 0, subfilter);
        }

        public static boolean verifySignatures(String path, String uuid) throws IOException, GeneralSecurityException {
                boolean isValid = true;
                PdfReader reader = new PdfReader(path);
                PdfDocument pdfDoc = new PdfDocument(reader);
                PdfDocumentInfo info = pdfDoc.getDocumentInfo();
                String docUUID = info.getMoreInfo(INFO_KEY);
                if (!docUUID.equals(uuid)) {
                        System.out.println("UUID is not match. ("+ docUUID +")");
                        isValid = false;
                }
                SignatureUtil signUtil = new SignatureUtil(pdfDoc);
                List<String> names = signUtil.getSignatureNames();

                System.out.println(path);
                for (String name : names) {
                        System.out.println("===== " + name + " =====");
                        PdfPKCS7 pkcs7 = verifySignature(path, signUtil, name);
                        if (pkcs7 != null && pkcs7.verifySignatureIntegrityAndAuthenticity())
                                isValid = isValid && true;
                }

                pdfDoc.close();
                System.out.println("Is valid: " + isValid);
                return isValid;
        }

        public static PdfPKCS7 verifySignature(String path, SignatureUtil signUtil, String name)
                        throws IOException, GeneralSecurityException {
                PdfPKCS7 pkcs7 = signUtil.readSignatureData(name);

                X509Certificate cert = (X509Certificate) pkcs7.getSigningCertificate();

                // try (FileOutputStream os = new FileOutputStream(TEMP2)) {
                // PdfSigner signer = new PdfSigner(new PdfReader(path), os, new
                // StampingProperties());

                // IExternalSignatureContainer external = new MyExternalSignatureContainer2();

                // // Signs a PDF where space was already reserved. The field must cover the
                // whole
                // // document.
                // PdfSigner.signDeferred(signer.getDocument(), SIGNAME, os, external);
                // }

                System.out.println("Signature covers whole document: " + signUtil.signatureCoversWholeDocument(name));
                System.out.println("Document revision: " + signUtil.getRevision(name) + " of "
                                + signUtil.getTotalRevisions());
                System.out.println("Integrity check OK? " + pkcs7.verifySignatureIntegrityAndAuthenticity());

                return pkcs7;
        }
}
