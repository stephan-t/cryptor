package cryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Encrypts or decrypts a file using AES and a PBKDF2 derived cipher key.
 */
class Cryptor {

    private static final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_SIZE = 16;

    /**
     * Encrypts an input file with password and writes to an output file
     * @param inFile the input plaintext file.
     * @param outFile the output ciphertext file.
     * @param password the password used for encryption.
     */
    static void encrypt(String inFile, String outFile, char[] password)
            throws IOException, GeneralSecurityException {
        try (InputStream in = new FileInputStream(inFile);
             OutputStream out = new FileOutputStream(outFile)) {
            // Derive key from password
            SecretKey key = KeyGenerator.deriveKey(password, out);

            // Generate initialization vector and prepend to output
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[IV_SIZE];
            random.nextBytes(ivBytes);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);
            out.write(ivBytes);

            // Encrypt file
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            byte[] outBytes = cipher.doFinal(in.readAllBytes());

            // Generate and prepend a MAC
            byte[] macBytes = Authenticator.generateMac(key, outBytes);
            out.write(macBytes);

            out.write(outBytes);
        }
    }

    /**
     * Decrypts an input file with password and writes to an output file
     * @param fileIn the input ciphertext file.
     * @param fileOut the output plaintext file.
     * @param password the password used for decryption.
     */
    static void decrypt(String fileIn, String fileOut, char[] password)
            throws IOException, GeneralSecurityException {
        try (InputStream in = new FileInputStream(fileIn)) {
            // Derive key from password
            SecretKey key = KeyGenerator.deriveKey(password, in);

            // Get prepended initialization vector from input
            byte[] ivBytes = in.readNBytes(IV_SIZE);
            IvParameterSpec iv = new IvParameterSpec(ivBytes);

            // Get prepended MAC from input
            byte[] tagMacBytes = Authenticator.getMac(in);

            // Generate MAC from ciphertext and compare with prepended MAC
            byte[] inBytes = in.readAllBytes();
            byte[] genMacBytes = Authenticator.generateMac(key, inBytes);

            // Decrypt file if both MACs match
            if (Authenticator.verifyMAC(tagMacBytes, genMacBytes)) {
                try (OutputStream out = new FileOutputStream(fileOut)) {
                    Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
                    cipher.init(Cipher.DECRYPT_MODE, key, iv);
                    byte[] outBytes = cipher.doFinal(inBytes);
                    out.write(outBytes);
                }
            }
        }
    }
}