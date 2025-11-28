package main.java.com.boeani.crypto;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class App {
    public static void main(String[] args) {
        CryptoUtil cryptoUtil;
        try {
            cryptoUtil = new CryptoUtil();
        } catch (NoSuchPaddingException | NoSuchAlgorithmException e) {
            cryptoUtil = null;
            System.err.println("Error occurred while processing with decrypting/encrypting!");
            e.printStackTrace();
            return;
        }

        String message = "Hello, World!";
        System.out.println(message);

        cryptoUtil.generateKeyPair();

        try {
            byte[] signedBytes = cryptoUtil.signData(message);
            cryptoUtil.verifySignature(message, signedBytes);
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            System.err.println("Error while signing Data.");
            e.printStackTrace();
        }
    }
}
