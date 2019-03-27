package cryptor;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;

/**
 * Generates a PBKDF2 derived key for use in a cipher or hash algorithm.
 */
class KeyGenerator {

    private static final String KEY_ALGORITHM = "PBKDF2WithHmacSHA512";
    private static final String CIPHER_ALGORITHM = "AES";
    private static final int SALT_SIZE = 16;
    private static final int ITERATIONS = 10000;
    private static final int KEY_SIZE = 256;

    /**
     * Derives a key from the provided password using PBKDF2
     * @param password the password to derive a key from.
     * @param stream the stream used to prepend or retrieve the salt.
     *               An <code>InputStream</code> is used for decryption, while an
     *               <code>OutputStream</code> is used for encryption.
     * @return the password derived key.
     * @throws IOException if the salt has not been fully read.
     * @throws GeneralSecurityException if <code>stream</code> is not of type
     * <code>InputStream</code> or <code>OutputStream</code>.
     */
    static SecretKey deriveKey(char[] password, Object stream)
            throws IOException, GeneralSecurityException {
        // Add salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SALT_SIZE];
        if (stream instanceof OutputStream) {
            // Generate salt and prepend to output
            random.nextBytes(salt);
            ((OutputStream) stream).write(salt);
        } else if (stream instanceof InputStream) {
            // Get prepended salt from input
            salt = ((InputStream) stream).readNBytes(SALT_SIZE);
        } else {
            throw new IllegalArgumentException("Argument stream must be of type" +
                    " InputStream or OutputStream");
        }

        // Derive key
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_ALGORITHM);
        KeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);
        SecretKey key = keyFactory.generateSecret(spec);

        return new SecretKeySpec(key.getEncoded(), CIPHER_ALGORITHM);
    }
}
