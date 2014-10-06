package com.crypto.test;

import org.apache.commons.codec.binary.Base64;

import com.crypto.AESCipher;

public class IntegTest {
    private AESCipher aesCipher;

    public static void main(String[] args) throws Exception {
        IntegTest instance = new IntegTest();
        instance.aesCipher = new AESCipher();

        String plainPassword = "password";

        // Generate a secret key.
        // You need to save this in your code or a vault, use this key to encrypt/decrypt your password
        // Losing this key means you lose the password.
        String secretKey = Base64.encodeBase64String(instance.aesCipher.generateSecretKey().getEncoded());
        System.out.println("secret key ---> " + secretKey);

        // encrypt the given text.
        String encryptedPassword = Base64.encodeBase64String(instance.aesCipher.encrypt(Base64.decodeBase64(secretKey),
                plainPassword));
        System.out.println("encrypted password ---> " + encryptedPassword);

        // decrypt the given encrypted text
        byte[] encPass = Base64.decodeBase64(encryptedPassword);
        byte[] decPass = instance.aesCipher.decrypt(Base64.decodeBase64(secretKey), encPass);
        String decryptedPassword = new String(decPass, "UTF-8");
        System.out.println("decrypted password ---> " + decryptedPassword);
    }
}
