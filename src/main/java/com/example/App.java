package com.example;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Writer;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.io.OutputStreamWriter;
import java.io.StringReader;
import java.security.cert.Certificate;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.KeyStore.LoadStoreParameter;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.Vector;

import javax.net.ssl.KeyManagerFactory;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.font.PDFont;
import org.apache.pdfbox.pdmodel.font.PDType1Font;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDNonTerminalField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.pdmodel.interactive.form.PDTerminalField;
import org.apache.pdfbox.text.PDFTextStripper;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.bc.BcPEMDecryptorProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEInputDecryptorProviderBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.encoders.Hex;

/**
 * Hello world!
 *
 */
public class App {
        public static final String KEYSTORE = "keys\\TanapornKleaklom.pfx";
        public static final String KEYSTORE2 = "keys\\mystore.p12";
        public static final char[] PASSWORD = "password".toCharArray();
        public static final char[] PASSWORD2 = "p12passphrase".toCharArray();
        public static final String SRC = "C:\\my\\temp\\hello.pdf";
        public static final String TEMP = "C:\\my\\temp\\hello-temp.pdf";
        public static final String TEMP2 = "C:\\my\\temp\\hello-temp2.pdf";
        public static final String DEST = "C:\\my\\temp\\hello_signed%s.pdf";
        public static final String DEST2 = "C:\\my\\temp\\hello_signed.pdf";
        public static final String DEST3 = "C:\\my\\temp\\hello_signed2.pdf";
        public static final String IMG = "./src/main/resources/img/sig.png";
        public static final String SIGNAME = "signature";
        public static final String INFO_KEY = "doeb_oilstock_uuid";

        public static void main(String[] args) throws Exception {
                String uuid = UUID.randomUUID().toString();
                System.out.println("Hello World!");
                System.out.println("UUID: " + uuid);
                // register BouncyCastle provider, needed for "exotic" algorithms
                Security.addProvider(SecurityProvider.getProvider());

                keyTest();
                createEmpty(uuid);

                testCreateCert();

                File ksFile = new File(KEYSTORE2);
                KeyStore keystore = KeyStore.getInstance("PKCS12");
                char[] password = PASSWORD2;
                try (InputStream is = new FileInputStream(ksFile)) {
                        keystore.load(is, password);
                }

                File documentFile = new File(SRC);

                int page = 1;
                String tsaUrl = null;
                String name = documentFile.getName();
                String substring = name.substring(0, name.lastIndexOf('.'));
                String ouputFileName = substring + "_signed.pdf";
                File signedDocumentFile = new File(documentFile.getParent(), ouputFileName);

                // sign PDF
                CreateSignature signing = new CreateSignature(keystore, password.clone());
                signing.setExternalSigning(false);
                signing.signDetached(documentFile, signedDocumentFile, tsaUrl);

                ShowSignature show = new ShowSignature();
                show.showSignature(DEST3, "0b7e75c9-07d4-4a49-870b-86f1153d4cca");
                // editUuid(DEST2);
                // show.showSignature("C:\\my\\temp\\hello_signed_wrong.pdf");

                // dumpTextLocation("C:\\my\\temp\\template.pdf");

                // System.out.println("Before sign: " + getDocHash(SRC));
                // System.out.println("After sign: " +
                // getSignedHash(signedDocumentFile.getAbsolutePath()));
        }

        static void keyTest() throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException,
                        IOException, KeyStoreException, CertificateException, UnrecoverableKeyException,
                        InvalidKeyException, NoSuchProviderException {
                File crtFile = new File("C:\\my\\cert\\OilStock\\clicknext.crt");
                File keyFile = new File("C:\\my\\cert\\OilStock\\clicknext.key");
                File p12File = new File("C:\\my\\cert\\OilStock\\clicknext.p12");
                char[] p12Password = "B5bA#gpp2T8&".toCharArray();
                File pfxFile = new File("keys\\TanapornKleaklom.pfx");
                char[] pfxPassword = "password".toCharArray();

                // crtFile
                System.out.println("-----------------------------------------");
                System.out.println("crtFile");
                try (InputStream is = new FileInputStream(crtFile)) {
                        CertificateFactory factory = CertificateFactory.getInstance("X.509");
                        Collection<? extends Certificate> certs = factory.generateCertificates(is);
                        X509Certificate cert = (X509Certificate) certs.iterator().next();

                        System.out.println("CA: " + cert.getSubjectX500Principal());
                        System.out.println("SerialNumber: " + cert.getSerialNumber().toString(16));
                        System.out.println("PublicKey Algorithm: " + cert.getPublicKey().getAlgorithm());
                        String pubKey = new String(Base64.encode(cert.getPublicKey().getEncoded()));
                        String pubKeyText = pubKey.substring(0, 5);
                        pubKeyText += "..." + pubKey.substring(pubKey.length() - 5, pubKey.length());
                        System.out.println("PublicKey (Base64): " + pubKeyText);
                        try {
                                @SuppressWarnings("unchecked")
                                Store<X509CertificateHolder> store = new JcaCertStore(certs);
                                SigUtils.verifyCertificateChain(store, cert, new Date());
                                System.out.println("cert: is valid");
                        } catch (Exception ex) {
                                System.out.println("cert: is not valid");
                        }
                }
                System.out.println("-----------------------------------------");

                // keyFile
                System.out.println("keyFile");
                try (InputStream is = new FileInputStream(keyFile)) {
                        String temp = new String(is.readAllBytes());
                        temp = temp.substring(temp.indexOf("-----BEGIN PRIVATE KEY-----", 0));
                        String privKeyPEM = temp.replace("-----BEGIN PRIVATE KEY-----", "");
                        privKeyPEM = privKeyPEM.replace("-----END PRIVATE KEY-----", "");
                        byte[] decodedBytes = Base64.decode(privKeyPEM);
                        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedBytes);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        PrivateKey privateKey = kf.generatePrivate(spec);
                        System.out.println("PrivateKey Algorithm: " + privateKey.getAlgorithm());
                        String prvKey = new String(Base64.encode(privateKey.getEncoded()));
                        String prvKeyText = prvKey.substring(0, 5);
                        prvKeyText += "..." + prvKey.substring(prvKey.length() - 5, prvKey.length());
                        System.out.println("PrivateKey (Base64): " + prvKeyText);
                }
                System.out.println("-----------------------------------------");

                // p12File
                System.out.println("p12File");
                try (InputStream is = new FileInputStream(p12File)) {
                        KeyStore keystore = KeyStore.getInstance("PKCS12");
                        keystore.load(is, p12Password);
                        String alias = keystore.aliases().asIterator().next();
                        System.out.println("Alias: " + alias);
                        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
                        System.out.println("SerialNumber: " + cert.getSerialNumber().toString(16));
                        System.out.println("PublicKey Algorithm: " + cert.getPublicKey().getAlgorithm());
                        String pubKey = new String(Base64.encode(cert.getPublicKey().getEncoded()));
                        String pubKeyText = pubKey.substring(0, 5);
                        pubKeyText += "..." + pubKey.substring(pubKey.length() - 5, pubKey.length());
                        System.out.println("PublicKey (Base64): " + pubKeyText);
                        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, p12Password);
                        System.out.println("PrivateKey Algorithm: " + privateKey.getAlgorithm());
                        String prvKey = new String(Base64.encode(privateKey.getEncoded()));
                        String prvKeyText = prvKey.substring(0, 5);
                        prvKeyText += "..." + prvKey.substring(prvKey.length() - 5, prvKey.length());
                        System.out.println("PrivateKey (Base64): " + prvKeyText);
                        keystore.deleteEntry(alias);
                }
                System.out.println("-----------------------------------------");

                // pfxFile
                System.out.println("pfxFile");
                try (InputStream is = new FileInputStream(pfxFile)) {
                        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                        KeyStore keystore = KeyStore.getInstance("PKCS12");
                        keystore.load(is, pfxPassword);
                        kmf.init(keystore, pfxPassword);
                        String alias = keystore.aliases().asIterator().next();
                        System.out.println("Alias: " + alias);
                        X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
                        System.out.println("SerialNumber: " + cert.getSerialNumber().toString(16));
                        System.out.println("X500Principal: " + cert.getIssuerX500Principal().getName());
                        System.out.println("PublicKey Algorithm: " + cert.getPublicKey().getAlgorithm());
                        String pubKey = new String(Base64.encode(cert.getPublicKey().getEncoded()));
                        String pubKeyText = pubKey.substring(0, 5);
                        pubKeyText += "..." + pubKey.substring(pubKey.length() - 5, pubKey.length());
                        System.out.println("PublicKey (Base64): " + pubKeyText);
                        PrivateKey privateKey = (PrivateKey) keystore.getKey(alias, pfxPassword);
                        System.out.println("PrivateKey Algorithm: " + privateKey.getAlgorithm());
                        String prvKey = new String(Base64.encode(privateKey.getEncoded()));
                        String prvKeyText = prvKey.substring(0, 5);
                        prvKeyText += "..." + prvKey.substring(prvKey.length() - 5, prvKey.length());
                        System.out.println("PrivateKey (Base64): " + prvKeyText);
                        keystore.deleteEntry(alias);
                }
                System.out.println("-----------------------------------------");
        }

        static void createEmpty(String uuid) throws IOException {
                // Create a new document with an empty page.
                try (PDDocument document = new PDDocument()) {
                        PDPage page = new PDPage(PDRectangle.A4);
                        document.addPage(page);
                        PDDocumentInformation docInfo = document.getDocumentInformation();
                        docInfo.setCustomMetadataValue("uuid", uuid);

                        PDFont font = PDType1Font.HELVETICA_BOLD;

                        PDPageContentStream contentStream = new PDPageContentStream(document, page);

                        // Define a text content stream using the selected font, moving the cursor and
                        // drawing the text "Hello World"
                        String title = "Hello World";

                        List<String> lines = new ArrayList<String>();
                        lines.add("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam blandit ultricies sapien, eget hendrerit leo fermentum id. Morbi a urna a risus consectetur dictum sed at tortor. Integer vestibulum tortor sit amet tortor maximus, vitae sodales leo aliquam. Donec gravida faucibus ante quis tempus. Sed a urna cursus, tincidunt turpis a, tempor orci. In condimentum eu urna quis sodales. Nullam sagittis at purus lacinia convallis. Interdum et malesuada fames ac ante ipsum primis in faucibus. Nullam et purus enim. Nunc vitae fermentum nunc. Vivamus feugiat nibh pulvinar lacus molestie sodales. Nam leo augue, tincidunt vel arcu vitae, ullamcorper auctor velit. Vivamus tincidunt interdum efficitur. Ut sagittis sit amet arcu eu bibendum. Orci varius natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus.");
                        lines.add("Ut leo purus, varius et dapibus quis, imperdiet at eros. Pellentesque sed imperdiet magna. Cras maximus, odio sed imperdiet ornare, velit nunc egestas leo, vel eleifend lacus nunc a enim. Phasellus vitae magna at orci consequat vehicula in lacinia ligula. Quisque nulla sem, congue sed lorem ac, aliquam cursus risus. Quisque vehicula mattis tincidunt. Aenean a ex tincidunt, accumsan nibh ac, auctor enim. Nulla nec eros iaculis libero semper vestibulum ac vitae nisi. Curabitur eu quam egestas, tincidunt arcu in, malesuada urna. Donec turpis mi, maximus sit amet semper eu, scelerisque vel lectus.");
                        lines.add("Nulla efficitur nisl vitae leo elementum, at vulputate orci pellentesque. Cras et porttitor eros. Vestibulum et rhoncus neque. Nunc congue diam ex, eu varius ipsum euismod eu. Suspendisse potenti. Nullam ultricies vel est eget blandit. Integer rutrum nibh urna, vel vehicula felis hendrerit vitae.");

                        PDRectangle mediabox = page.getMediaBox();
                        float margin = 72;
                        int mainWidth = (int)(mediabox.getWidth() - 2 * margin);
                        float startX = mediabox.getLowerLeftX() + margin;
                        float startY = mediabox.getUpperRightY() - margin;

                        float titleWidth = font.getStringWidth(title) / 1000 * 16;
                        float titleHeight = font.getFontDescriptor().getFontBoundingBox().getHeight() / 1000 * 16;

                        contentStream.beginText();
                        contentStream.setFont(font, 16);
                        contentStream.newLineAtOffset((mediabox.getWidth() - titleWidth) / 2, mediabox.getHeight() - 60 - titleHeight);
                        contentStream.showText("Hello World");
                        contentStream.endText();

                        float leading = 2.5f * 12;
                        float height = startY - 50;
                        for (String line : lines) {
                                int start = 0;
                                int end = 0;
                                int index = 0;
                                for (int i : possibleWrapPoints(line)) {
                                        float width = font.getStringWidth(line.substring(start, i)) / 1000 * 12;
                                        if (start < end && width > (mainWidth - (index == 0 ? leading : 0))) {
                                                // Draw partial text and increase height
                                                contentStream.beginText();
                                                contentStream.setFont(font, 12);
                                                contentStream.newLineAtOffset(startX + (index == 0 ? leading : 0), height);
                                                contentStream.showText(line.substring(start, end));
                                                contentStream.endText();
                                                height -= font.getFontDescriptor().getFontBoundingBox().getHeight() / 1000 * 12;
                                                start = end;
                                                index++;
                                        }
                                        end = i;
                                }
                                contentStream.beginText();
                                contentStream.setFont(font, 12);
                                contentStream.newLineAtOffset(startX, height);
                                contentStream.showText(line.substring(start));
                                contentStream.endText();
                                height -= 40;
                        }

                        String signText = "(Sign here)";
                        float rectX = mediabox.getUpperRightX() - margin - 200;
                        float rectY = mediabox.getLowerLeftY() + margin;
                        float sigWidth = font.getStringWidth(signText) / 1000 * 12;

                        contentStream.moveTo(rectX, rectY + 18);
                        contentStream.lineTo(rectX + 200, rectY + 18);
                        contentStream.stroke();

                        contentStream.beginText();
                        contentStream.setFont(font, 12);
                        contentStream.newLineAtOffset(rectX + (200 - sigWidth) / 2, rectY);
                        contentStream.showText(signText);
                        contentStream.endText();

                        // Make sure that the content stream is closed:
                        contentStream.close();

                        // Add a new AcroForm and add that to the document
                        PDAcroForm acroForm = new PDAcroForm(document);
                        document.getDocumentCatalog().setAcroForm(acroForm);

                        // Create empty signature field, it will get the name "Signature1"
                        PDSignatureField signatureField = new PDSignatureField(acroForm);
                        signatureField.setPartialName(SIGNAME);
                        PDAnnotationWidget widget = signatureField.getWidgets().get(0);

                        
                        PDRectangle rect = new PDRectangle(rectX, rectY + 20, 200, 80);
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

        static int[] possibleWrapPoints(String text) {
                String[] split = text.split("(?<=\\W)");
                int[] ret = new int[split.length];
                ret[0] = split[0].length();
                for (int i = 1; i < split.length; i++)
                        ret[i] = ret[i - 1] + split[i].length();
                return ret;
        }

        static void editUuid(String fileName) throws IOException {
                File documentFile = new File(fileName);
                // Create a new document with an empty page.
                try (PDDocument document = PDDocument.load(documentFile)) {
                        PDDocumentInformation docInfo = document.getDocumentInformation();
                        docInfo.setCustomMetadataValue("uuid", "123456789");
                        document.save("C:\\my\\temp\\hello_signed_wrong.pdf");
                        document.close();
                }
        }

        static String getDocHash(String fileName) throws IOException, NoSuchAlgorithmException {
                File documentFile = new File(fileName);
                try (PDDocument document = PDDocument.load(documentFile)) {
                        // removeField(document, SIGNAME);

                        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                        document.saveIncremental(byteArrayOutputStream);
                        document.save(new File(documentFile.getParent(), "getDocHash.pdf"));
                        document.close();
                        InputStream inputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
                        byte[] bytes = IOUtils.toByteArray(inputStream);
                        return getHash(bytes);
                }
        }

        static String getSignedHash(String fileName) throws IOException, NoSuchAlgorithmException {
                try (InputStream inputStream = new ByteArrayInputStream(readFileBetterPerformance(fileName))) {
                        PDDocument document = PDDocument.load(inputStream);
                        byte[] signedPdf = IOUtils.toByteArray(inputStream);
                        byte[] origPDF = document.getSignatureDictionaries().get(0).getSignedContent(signedPdf);
                        byte[] signature = document.getSignatureDictionaries().get(0).getContents(signedPdf);
                        document.close();

                        // removeField(document, SIGNAME);

                        // ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                        // document.saveIncremental(byteArrayOutputStream);
                        // document.save(new File(documentFile.getParent(), "getSignedHash.pdf"));
                        // document.close();
                        // InputStream inputStream = new
                        // ByteArrayInputStream(byteArrayOutputStream.toByteArray());
                        // return getHash(IOUtils.toByteArray(inputStream));
                        return getHash(origPDF);
                }
        }

        private static byte[] readFileBetterPerformance(String fileName) {
                try (FileInputStream fis = new FileInputStream(new File(fileName))) {
                        return fis.readAllBytes();
                } catch (IOException e) {
                        e.printStackTrace();
                }
                return null;
        }

        static String getHash(byte[] bytes) throws IOException, NoSuchAlgorithmException {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] sha256Hash = digest.digest(bytes);
                byte[] encoded = Base64.encode(sha256Hash);
                return new String(encoded);
        }

        static void dumpTextLocation(String fileName) throws IOException {
                PDDocument document = null;
                try {
                        document = PDDocument.load(new File(fileName));
                        PDFTextStripper stripper = new GetCharLocationAndSize();
                        stripper.setSortByPosition(true);
                        stripper.setStartPage(0);
                        stripper.setEndPage(document.getNumberOfPages());

                        Writer dummy = new OutputStreamWriter(new ByteArrayOutputStream(), "UTF-8");
                        stripper.writeText(document, dummy);
                } finally {
                        if (document != null) {
                                document.close();
                        }
                }
        }

        private static void testCreateCert() throws NoSuchAlgorithmException, OperatorCreationException,
                        CertificateException, KeyStoreException, IOException, UnrecoverableKeyException,
                        InvalidKeyException, NoSuchProviderException, SignatureException, InvalidKeySpecException,
                        PKCSException {
                // --- generate a key pair (you did this already it seems)
                KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
                final KeyPair pair = rsaGen.generateKeyPair();

                PKCS10CertificationRequest csr;
                try (FileInputStream is = new FileInputStream("keys\\server.csr")) {
                        String temp = new String(is.readAllBytes());
                        String csrPEM = temp.replace("-----BEGIN CERTIFICATE REQUEST-----", "");
                        csrPEM = csrPEM.replace("-----END CERTIFICATE REQUEST-----", "");
                        byte[] decodedBytes = Base64.decode(csrPEM);
                        csr = new PKCS10CertificationRequest(decodedBytes);
                }

                PrivateKey privateKey;
                try (InputStream is = new FileInputStream("keys\\server.key")) {
                        String temp = new String(is.readAllBytes());
                        // String privKeyPEM = temp.replace("-----BEGIN ENCRYPTED PRIVATE KEY-----",
                        // "");
                        // privKeyPEM = privKeyPEM.replace("-----END ENCRYPTED PRIVATE KEY-----", "");
                        // byte[] decodedBytes = Base64.decode(privKeyPEM);
                        // PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decodedBytes);
                        // KeyFactory kf = KeyFactory.getInstance("RSA");
                        privateKey = stringToPrivateKey(temp, "583c2527-cad5-48bf-a299-786127c2d1a6");
                }

                // --- create the self signed cert
                X509Certificate cert = sign(csr, privateKey, pair);

                // --- create a new pkcs12 key store in memory
                KeyStore pkcs12 = KeyStore.getInstance("PKCS12");
                pkcs12.load(null, null);

                // --- create entry in PKCS12
                pkcs12.setKeyEntry("privatekeyalias", pair.getPrivate(), "p12passphrase".toCharArray(),
                                new Certificate[] { cert });

                // --- store PKCS#12 as file
                try (FileOutputStream p12 = new FileOutputStream("keys\\mystore.p12")) {
                        pkcs12.store(p12, "p12passphrase".toCharArray());
                }
        }

        static public PrivateKey stringToPrivateKey(String s, String password)
                        throws IOException, PKCSException {

                PrivateKeyInfo pki;

                try (PEMParser pemParser = new PEMParser(new StringReader(s))) {

                        Object o = pemParser.readObject();

                        if (o instanceof PKCS8EncryptedPrivateKeyInfo) {

                                PKCS8EncryptedPrivateKeyInfo epki = (PKCS8EncryptedPrivateKeyInfo) o;

                                JcePKCSPBEInputDecryptorProviderBuilder builder = new JcePKCSPBEInputDecryptorProviderBuilder()
                                                .setProvider(SecurityProvider.getProvider());

                                InputDecryptorProvider idp = builder.build(password.toCharArray());

                                pki = epki.decryptPrivateKeyInfo(idp);
                        } else if (o instanceof PEMEncryptedKeyPair) {

                                PEMEncryptedKeyPair epki = (PEMEncryptedKeyPair) o;
                                PEMKeyPair pkp = epki
                                                .decryptKeyPair(new BcPEMDecryptorProvider(password.toCharArray()));

                                pki = pkp.getPrivateKeyInfo();
                        } else {
                                throw new PKCSException(
                                                "Invalid encrypted private key class: " + o.getClass().getName());
                        }

                        JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                                        .setProvider(SecurityProvider.getProvider());
                        return converter.getPrivateKey(pki);
                }
        }

        public static X509Certificate sign(PKCS10CertificationRequest inputCSR, PrivateKey caPrivate, KeyPair pair)
                        throws InvalidKeyException, NoSuchAlgorithmException,
                        NoSuchProviderException, SignatureException, IOException,
                        OperatorCreationException, CertificateException {

                AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
                                .find("SHA1withRSA");
                AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder()
                                .find(sigAlgId);

                AsymmetricKeyParameter foo = PrivateKeyFactory.createKey(pair.getPrivate().getEncoded());
                SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());

                X509v3CertificateBuilder myCertificateGenerator = new X509v3CertificateBuilder(
                                new X500Name("CN=issuer"), new BigInteger("1"), new Date(
                                                System.currentTimeMillis()),
                                new Date(System.currentTimeMillis() + 30 * 365 * 24 * 60 * 60 * 1000),
                                inputCSR.getSubject(), keyInfo);

                ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                                .build(foo);

                X509CertificateHolder holder = myCertificateGenerator.build(sigGen);
                org.bouncycastle.asn1.x509.Certificate eeX509CertificateStructure = holder.toASN1Structure();

                CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

                // Read Certificate
                InputStream is1 = new ByteArrayInputStream(eeX509CertificateStructure.getEncoded());
                X509Certificate theCert = (X509Certificate) cf.generateCertificate(is1);
                is1.close();
                return theCert;
        }
}
