package main.java.com.boeani.crypto;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;
import java.util.Objects;

public class CryptoUtil {
    private final KeyGenerator keyGenerator;
    private final KeyPairGenerator keyPairGenerator;
    private SecretKey secretKey;
    private KeyPair keyPair;
    private final Cipher symmetricCipher;
    private final Cipher asymmetricCipher;
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private final MessageDigest digest;


    public CryptoUtil() throws NoSuchAlgorithmException, NoSuchPaddingException {
        this.keyGenerator = KeyGenerator.getInstance("AES");
        this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        this.keyGenerator.init(256);
        this.keyPairGenerator.initialize(4096);

        this.symmetricCipher = Cipher.getInstance("AES/GCM/NoPadding");
        this.asymmetricCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        this.digest = MessageDigest.getInstance("SHA-256");
    }

    public void generateSymmetricKey() {
        this.secretKey = keyGenerator.generateKey();
        System.out.println("Symmetric Key generated.");
    }

    public EncryptedData encryptSymmetric(String message)
            throws
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Objects.requireNonNull(secretKey, "Secret key must be generated before encryption.");
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        symmetricCipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] encryptedMessageBytes = symmetricCipher.doFinal(messageBytes);

        System.out.println("Encrypted Message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessageBytes));
        System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv));

        return new EncryptedData(encryptedMessageBytes, iv);
    }

    public String decryptSymmetric(EncryptedData encryptedData) throws
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Objects.requireNonNull(secretKey, "Secret key must be generated before decryption.");

        byte[] encryptedMessageBytes = encryptedData.encryptedMessage();
        byte[] iv = encryptedData.iv();

        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

        symmetricCipher.init(Cipher.DECRYPT_MODE, secretKey, gcmParameterSpec);

        byte[] decryptedMessageBytes = symmetricCipher.doFinal(encryptedMessageBytes);
        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        System.out.println("Decrypted Message: " + decryptedMessage);
        return decryptedMessage;
    }

    public void generateKeyPair() {
        this.keyPair = keyPairGenerator.generateKeyPair();
        System.out.println("Asymmetric Key generated.");
    }

    public byte[] encryptAsymmetric(String message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Objects.requireNonNull(keyPair, "KeyPair must be generated before encryption.");
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

        asymmetricCipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        byte[] encryptedMessageBytes = asymmetricCipher.doFinal(messageBytes);
        System.out.println("Encrypted Message (Base64): " + Base64.getEncoder().encodeToString(encryptedMessageBytes));
        return encryptedMessageBytes;
    }

    public String decryptAsymmetric(byte[] encryptedMessage) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Objects.requireNonNull(keyPair, "KeyPair must be generated before decryption.");

        asymmetricCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedMessageBytes = asymmetricCipher.doFinal(encryptedMessage);

        String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

        System.out.println("Decrypted Message: " + decryptedMessage);
        return decryptedMessage;
    }

    public String generateHash(String data) throws NoSuchAlgorithmException {
        this.digest.reset();

        byte[] hashBytes = this.digest.digest(data.getBytes(StandardCharsets.UTF_8));

        StringBuilder hexString = new StringBuilder();

        for (byte b : hashBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }

        String hashHex = hexString.toString();
        System.out.println("Generated Hash (SHA-256) for data '" + data + "': " + hashHex);
        return hashHex;
    }

    public byte[] signData(String data) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Objects.requireNonNull(keyPair, "KeyPair must be generated before signing data.");

        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initSign(keyPair.getPrivate());

        signature.update(data.getBytes(StandardCharsets.UTF_8));

        byte[] signedBytes = signature.sign();
        System.out.println("Signed Bytes (Base64): " + Base64.getEncoder().encodeToString(signedBytes));

        return signedBytes;
    }

    public boolean verifySignature(String data, byte[] signatureBytes) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException {
        Objects.requireNonNull(keyPair, "KeyPair must be generated before verifying data.");

        Signature signature = Signature.getInstance("SHA256withRSA");

        signature.initVerify(keyPair.getPublic());
        signature.update(data.getBytes(StandardCharsets.UTF_8));

        boolean isValid = signature.verify(signatureBytes);

        System.out.println("Signature for data + '" + data + "' is valid: " + isValid);
        return isValid;
    }
}

