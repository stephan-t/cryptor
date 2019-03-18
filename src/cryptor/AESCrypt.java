package cryptor;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Scanner;

/**
 * Encrypts a plaintext file using AES and a PBKDF2 derived cipher key.
 */
public class AESCrypt {
    public static void main(String[] args)
            throws IOException, GeneralSecurityException {
        // Request cipher mode from user
        Scanner scan = new Scanner(System.in);
        System.out.print("Enter cipher mode ([e]ncrypt | [d]ecrypt): ");
        String modeIn = scan.nextLine();

        // Validate and set cipher mode
        int mode;
        if (modeIn.equals("e")) {
            mode = Cipher.ENCRYPT_MODE;
        } else if (modeIn.equals("d")) {
            mode = Cipher.DECRYPT_MODE;
        } else {
            System.err.println("Not a valid mode");
            mode = 0;
            System.exit(1);
        }

        // Request filenames from user
        System.out.print("Enter input filename: ");
        String fileIn = scan.nextLine();

        System.out.print("Enter output filename: ");
        String fileOut = scan.nextLine();

        // Request password from user
        System.out.print("Enter password: ");
        char[] password = scan.next().toCharArray();

        try (InputStream in = new FileInputStream(fileIn);
             OutputStream out = new FileOutputStream(fileOut)) {

            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[16];

            if (modeIn.equals("e")) {
                // Generate salt and prepend to output
                random.nextBytes(salt);
                out.write(salt);
            } else {
                // Get prepended salt from input
                in.read(salt, 0, salt.length);
            }

            // Derive AES key from password using PBKDF2
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            KeySpec spec = new PBEKeySpec(password, salt, 5000, 256);
            SecretKey key = keyFactory.generateSecret(spec);
            key = new SecretKeySpec(key.getEncoded(), "AES");

            if (modeIn.equals("e")) {
                // Generate initialization vector and prepend to output
                byte[] ivBytes = new byte[16];
                random.nextBytes(ivBytes);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);
                out.write(ivBytes);

                // Encrypt file
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(mode, key, iv);
                CryptUtil.crypt(in, out, cipher);
            } else {
                // Get prepended initialization vector from input
                byte[] ivBytes = new byte[16];
                in.read(ivBytes, 0, ivBytes.length);
                IvParameterSpec iv = new IvParameterSpec(ivBytes);

                // Decrypt file
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(mode, key, iv);
                CryptUtil.crypt(in, out, cipher);
            }
        }
    }
}