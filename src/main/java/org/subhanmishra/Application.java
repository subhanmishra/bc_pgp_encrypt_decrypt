package org.subhanmishra;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.util.Date;
import java.util.Iterator;
import java.util.Objects;
import java.util.Scanner;

public class Application {
    static final ClassLoader loader = Application.class.getClassLoader();

    /**
     * @param args
     */
    public static void main(String[] args) {
        // get some input
        Scanner scanInput = new Scanner(System.in);
        System.out.println("Enter a string: ");
        String message = scanInput.nextLine();
        System.out.println("The input is : " + message);
        scanInput.close();

        // add Bouncy JCE Provider, http://bouncycastle.org/latest_releases.html
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // hardcoded for demo purpose
        String privateKeyPassword = "hongkong";

        PGPPublicKey pubKey = null;
        // Load public key
        try {
            pubKey = readPublicKey(loader
                    .getResourceAsStream("sign-and-encrypt_pub.asc"));
        } catch (IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (pubKey != null) {
            System.out.println("Successfully read public key: ");
            // System.out.println("Key Owner: "+pubKey.getUserIDs());
            // System.out.println("Key Stength: "+pubKey.getBitStrength());
            // System.out.println("Key Algorithm: "+pubKey.getAlgorithm()+"\n\n");
        }

        // Load private key, **NOTE: still secret, we haven't unlocked it yet**
        PGPSecretKey pgpSec = null;
        try {
            pgpSec = readSecretKey(loader
                    .getResourceAsStream("sign-and-encrypt_priv.asc"));
        } catch (IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // sign our message
        String messageSignature = null;
        try {
            messageSignature = signMessageByteArray(message, pgpSec,
                    privateKeyPassword.toCharArray());
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | SignatureException | IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (messageSignature != null) {
            System.out
                    .println("Successfully signed your message with the private key.\n\n");
            System.out.println(messageSignature + "\n\n");
        }

        System.out.println("Now Encrypting it.");

        String encryptedMessage = null;
        try {
            encryptedMessage = encryptByteArray(message.getBytes(), pubKey,
                    true, true);
        } catch (NoSuchProviderException | IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (encryptedMessage != null) {
            System.out.println("PGP Encrypted Message: ");
            System.out.println(encryptedMessage);

            // Write the encrypted .pgp message file to Resources folder
            try {
                Path write = Files.write(Paths.get("C:\\IntelliJ_Workspace\\pgp-encrypt-decrypt\\src\\main\\resources\\encrypted_msg.pgp"), encryptedMessage.getBytes());
                System.out.println("File written to resources folder: " + write.getFileName());

                byte[] read = Files.readAllBytes(Paths.get("C:\\IntelliJ_Workspace\\pgp-encrypt-decrypt\\src\\main\\resources\\encrypted_msg.pgp"));
                decrypt(new ByteArrayInputStream(read), new FileOutputStream("C:\\IntelliJ_Workspace\\pgp-encrypt-decrypt\\src\\main\\resources\\decrypted_msg.txt"), pgpSec, privateKeyPassword.toCharArray());
            } catch (IOException | PGPException e) {
                throw new RuntimeException(e);
            }

        }

    }

    /**
     * @param message
     * @param pgpSec
     * @param pass
     * @return
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     * @throws PGPException
     * @throws SignatureException
     */
    @SuppressWarnings("rawtypes")
    private static String signMessageByteArray(String message,
                                               PGPSecretKey pgpSec, char pass[]) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException, PGPException,
            SignatureException {
        byte[] messageCharArray = message.getBytes();

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);

        // Unlock the private key using the password
        PGPPrivateKey pgpPrivKey = pgpSec
                .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC").build(pass));

        // Signature generator, we can generate the public key from the private
        // key! Nifty!
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(pgpSec.getPublicKey()
                        .getAlgorithm(), PGPUtil.SHA384).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(comData.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, messageCharArray.length, new Date());

        for (byte c : messageCharArray) {
            lOut.write(c);
            sGen.update(c);
        }

        lOut.close();
        /*
         * while ((ch = message.toCharArray().read()) >= 0) { lOut.write(ch);
         * sGen.update((byte) ch); }
         */
        lGen.close();

        sGen.generate().encode(bOut);

        comData.close();

        out.close();

        return encOut.toString();
    }

    /**
     * @param clearData
     * @param encKey
     * @param withIntegrityCheck
     * @param armor
     * @return
     * @throws IOException
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    @SuppressWarnings("deprecation")
    public static String encryptByteArray(byte[] clearData,
                                          PGPPublicKey encKey, boolean withIntegrityCheck, boolean armor)
            throws IOException, PGPException, NoSuchProviderException {

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();

        OutputStream out = encOut;
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedDataGenerator.ZIP);
        OutputStream cos = comData.open(bOut); // open it with the final

        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();

        OutputStream pOut = lData.open(cos, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, clearData.length, // length of clear
                // data
                new Date() // current time
        );
        pOut.write(clearData);

        lData.close();
        comData.close();

        SecureRandom random = new SecureRandom();

        BcPGPDataEncryptorBuilder bcPGPDataEncryptorBuilder = new BcPGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(true).setSecureRandom(random);

//        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
//                PGPEncryptedData.CAST5, withIntegrityCheck, new SecureRandom(),
//                "BC");
        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(bcPGPDataEncryptorBuilder);

        //cPk.addMethod(encKey);
        // use public key to encrypt data

        BcPublicKeyKeyEncryptionMethodGenerator encKeyGen = new BcPublicKeyKeyEncryptionMethodGenerator(encKey)
                .setSecureRandom(random);

        cPk.addMethod(encKeyGen);

        byte[] bytes = bOut.toByteArray();

        OutputStream cOut = cPk.open(out, bytes.length);

        cOut.write(bytes); // obtain the actual bytes from the compressed stream

        cOut.close();

        out.close();

        return encOut.toString();
    }

    /**
     * A simple routine that opens a key ring file and loads the first available
     * key suitable for encryption.
     *
     * @param input
     * @return
     * @throws IOException
     * @throws PGPException
     */
    @SuppressWarnings("rawtypes")
    public static PGPPublicKey readPublicKey(InputStream input)
            throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find encryption key in key ring.");
    }

    /**
     * A simple routine that opens a key ring file and loads the first available
     * key suitable for signature generation.
     *
     * @param input stream to read the secret key ring collection from.
     * @return a secret key.
     * @throws IOException  on a problem with using the input stream.
     * @throws PGPException if there is an issue parsing the input stream.
     */
    @SuppressWarnings("rawtypes")
    public static PGPSecretKey readSecretKey(InputStream input)
            throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        //
        // we just loop through the collection till we find a key suitable for
        // encryption, in the real
        // world you would probably want to be a bit smarter about this.
        //

        Iterator keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) keyRingIter.next();

            Iterator keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = (PGPSecretKey) keyIter.next();

                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException(
                "Can't find signing key in key ring.");
    }


    public static void decrypt(InputStream encryptedIn, OutputStream clearOut, PGPSecretKey pgpSec, char pass[])
            throws PGPException, IOException {
        // Removing armour and returning the underlying binary encrypted stream
        encryptedIn = PGPUtil.getDecoderStream(encryptedIn);
        JcaPGPObjectFactory pgpObjectFactory = new JcaPGPObjectFactory(encryptedIn);

        Object obj = pgpObjectFactory.nextObject();
        //The first object might be a marker packet
        PGPEncryptedDataList pgpEncryptedDataList = (obj instanceof PGPEncryptedDataList)
                ? (PGPEncryptedDataList) obj : (PGPEncryptedDataList) pgpObjectFactory.nextObject();

        PGPPrivateKey pgpPrivateKey = null;
        PGPPublicKeyEncryptedData publicKeyEncryptedData = null;

        Iterator<PGPEncryptedData> encryptedDataItr = pgpEncryptedDataList.getEncryptedDataObjects();
        while (pgpPrivateKey == null && encryptedDataItr.hasNext()) {
            publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedDataItr.next();
            pgpPrivateKey = pgpSec
                    .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                            .setProvider("BC").build(pass));
        }

        if (Objects.isNull(publicKeyEncryptedData)) {
            throw new PGPException("Could not generate PGPPublicKeyEncryptedData object");
        }

        if (pgpPrivateKey == null) {
            throw new PGPException("Could Not Extract private key");
        }

        PublicKeyDataDecryptorFactory decryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pgpPrivateKey);
        InputStream decryptedCompressedIn = publicKeyEncryptedData.getDataStream(decryptorFactory);

        JcaPGPObjectFactory decCompObjFac = new JcaPGPObjectFactory(decryptedCompressedIn);
        PGPCompressedData pgpCompressedData = (PGPCompressedData) decCompObjFac.nextObject();

        InputStream compressedDataStream = new BufferedInputStream(pgpCompressedData.getDataStream());
        JcaPGPObjectFactory pgpCompObjFac = new JcaPGPObjectFactory(compressedDataStream);

        Object message = pgpCompObjFac.nextObject();

        if (message instanceof PGPLiteralData) {
            PGPLiteralData pgpLiteralData = (PGPLiteralData) message;
            InputStream decDataStream = pgpLiteralData.getInputStream();
            IOUtils.copy(decDataStream, clearOut);
            clearOut.close();
        } else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("Encrypted message contains a signed message not literal data");
        } else {
            throw new PGPException("Message is not a simple encrypted file - Type Unknown");
        }
        // Performing Integrity check
        if (publicKeyEncryptedData.isIntegrityProtected()) {
            if (!publicKeyEncryptedData.verify()) {
                throw new PGPException("Message failed integrity check");
            }
        }
    }
}