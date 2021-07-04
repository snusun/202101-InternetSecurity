import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/*
carol>
openssl genrsa -out CarolPriv.pem 2048
openssl req -new -key CarolPriv.pem -out CarolCsr.pem -subj /CN=YOUR_NAME/
openssl x509 -req -days 365 -in CarolCsr.pem -signkey CarolPriv.pem -out CarolCert.pem
copy CarolCert.pem ..\Alice\
copy CarolCert.pem ..\Bob\

Alice>
openssl genrsa -out AlicePriv.pem 2048
openssl req -new -key AlicePriv.pem -out AliceCsr.pem -subj /CN=Alice/
copy AliceCsr.pem ..\Carol\

Carol>
openssl x509 -req -days 365 -CA CarolCert.pem -CAkey CarolPriv.pem -in AliceCsr.pem -out AliceCert.pem -CAcreateserial
copy AliceCert.pem ..\Alice\

Bob> openssl verify -CAfile CarolCert.pem AliceCert.pem

# print cert
keytool -printcert -file [x509]
openssl x509 -text -noout -in [x509]

# Convert pkcs1 to pkcs8
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in AlicePriv.pem -out AlicePriv.p8

# X.509 chain verification
openssl verify -CAfile CarolCert.pem AliceCert.pem
*/

public class SignVeri {

    public static void main(String[] args) {
        // TODO modify this if needed
        try {

            if (args.length < 3) {
                System.out.println("Invalid arguments.");
                printHowToUse();
            } else if (args.length == 3 && args[0].equals("sign")) {
                generateSignature(args[1], args[2]);
            } else if (args.length == 4 && args[0].equals("verify")) {
                verifySignature(args[1], args[2], args[3]);
            } else {
                printHowToUse();
            }

        } catch(Exception e) {
            e.printStackTrace();
            printHowToUse();
        }
    }

    private static void verifySignature(String cert, String target, String sign)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IOException {
        // TODO load X.509 cert
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		FileInputStream is = new FileInputStream(cert);
		X509Certificate cer = (X509Certificate) certFactory.generateCertificate(is);
		PublicKey key = cer.getPublicKey();

        // TODO verify SHA256withRSA signature. If ok, print "Signature verification SUCCESS."
        File tarFile = new File(target);
        byte[] tar = Files.readAllBytes(tarFile.toPath());
        File sigFile = new File(sign);
        byte[] sigByte = Files.readAllBytes(sigFile.toPath());

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(key);
        signature.update(tar);
        boolean success = signature.verify(sigByte);
        if(success) System.out.println("Signature verification SUCCESS.");
    }

    private static void generateSignature(String privKeyFile, String targetFile)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException,
            SignatureException, InvalidKeyException {
        // TODO load priv key
        String stringKey = Files.readString(Paths.get(privKeyFile));
        stringKey = stringKey.replaceAll("-----END PRIVATE KEY-----", "")
                             .replaceAll("-----BEGIN PRIVATE KEY-----", "")
                             .replaceAll(System.lineSeparator(), "");
        byte[] privKeyBytes = Base64.getMimeDecoder().decode(stringKey);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privKeyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);
            
        File tarFile = new File(targetFile);
        byte[] tar = Files.readAllBytes(tarFile.toPath());     

        // TODO generate SHA256withRSA signature
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(tar);
        byte[] s = privateSignature.sign();

        // TODO output signature
        writeFile(s, "msg.txt.sign");
    }

    private static boolean writeFile(byte[] data, String fileName) throws IOException {
        // TODO modify this if needed
        File output = new File(fileName);
        FileOutputStream fos = new FileOutputStream(output);
        fos.write(data);
        fos.close();
        return true;
    }

    private static void printHowToUse() {
        // TODO modify this if needed
        System.out.println("* How to Use\n" +
                "java SignVeri sign [privKey] [target]\n" +
                "java SignVeri verify [x509] [target] [signature]\n");
    }
}
