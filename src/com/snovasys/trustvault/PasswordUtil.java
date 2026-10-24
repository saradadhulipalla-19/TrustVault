package com.snovasys.trustvault;

import java.security.MessageDigest;
import java.security.SecureRandom;

public class PasswordUtil {

    private static final SecureRandom RANDOM =
            new SecureRandom();

    public static byte[] newSalt() {
        byte[] salt = new byte[16];
        RANDOM.nextBytes(salt);
        return salt;
    }

    public static byte[] hashPassword(
            char[] password, byte[] salt) throws Exception {

        var spec = new javax.crypto.spec.PBEKeySpec(
                password, salt, 210_000, 256);

        try {
            var factory = javax.crypto.SecretKeyFactory
                    .getInstance("PBKDF2WithHmacSHA256");

            return factory.generateSecret(spec).getEncoded();
        } finally {
            spec.clearPassword();
        }
    }

    public static boolean verifyPassword(
            char[] password, byte[] salt, byte[] expectedHash)
            throws Exception {

        byte[] actualHash = hashPassword(password, salt);

        return MessageDigest.isEqual(actualHash, expectedHash);
    }
}