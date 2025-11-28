package main.java.com.boeani.crypto;

public record EncryptedData(byte[] encryptedMessage, byte[] iv) {
}
