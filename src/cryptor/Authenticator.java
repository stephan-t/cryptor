package cryptor;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.util.Arrays;

/**
 * Provides authenticated encryption/decryption using an MAC and secret key.
 * An Encrypt-then-MAC (EtM) approach is used, where the plaintext is encrypted
 * and an MAC is generated from the resulting ciphertext.
 */
class Authenticator {

    private static final String MAC_ALGORITHM = "HmacSHA512";
    private static final int MAC_SIZE = 64;

    /**
     * Generates a MAC based on a given secret key and ciphertext.
     * @param key the secret key used in the hash algorithm.
     * @param bytes the ciphertext bytes used to generate a MAC.
     * @return the generated MAC bytes.
     */
    static byte[] generateMac(SecretKey key, byte[] bytes)
            throws GeneralSecurityException {
        // Generate and prepend a MAC for authentication
        Mac mac = Mac.getInstance(MAC_ALGORITHM);
        mac.init(key);
        return mac.doFinal(bytes);
    }

    /**
     * Retrieves a prepended MAC from an input stream of bytes.
     * @param in the input stream to retrieve the MAC from.
     * @return the prepended MAC bytes.
     */
    static byte[] getMac(InputStream in) throws IOException {
        return in.readNBytes(MAC_SIZE);
    }

    /**
     *
     * @param prepended the prepended MAC bytes from the ciphertext.
     * @param generated the generated MAC bytes from the ciphertext.
     * @return <code>true</code> if both MACs match; throws exception otherwise.
     * @throws GeneralSecurityException if there is a mismatch between the
     * prepended and generated MACs.
     */
    static boolean verifyMAC(byte[] prepended, byte[] generated)
            throws GeneralSecurityException {
        if (Arrays.equals(prepended, generated)) {
            return true;
        } else {
            throw new GeneralSecurityException("Password is invalid" +
                    " and/or data integrity check failed");
        }
    }
}
