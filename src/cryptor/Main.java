package cryptor;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * Main entry point for running the Cryptor program.
 */
public class Main {

    /**
     * Calls an encryption or decryption method according to command-line arguments.
     * @param args the command-line arguments.<br>
     *             Arguments for encryption:
     *             <ol>
     *             <li>-encrypt</li>
     *             <li>plaintext filename</li>
     *             <li>encrypted filename</li>
     *             <li>password</li>
     *             </ol>
     *             Arguments for decryption:
     *             <ol>
     *             <li>-decrypt</li>
     *             <li>encrypted filename</li>
     *             <li>decrypted filename</li>
     *             <li>password</li>
     *             </ol>
     */
    public static void main(String[] args)
            throws IOException, GeneralSecurityException {

        String mode = args[0];
        String inFile = args[1];
        String outFile = args[2];
        char[] password = args[3].toCharArray();

        if (mode.equals("-encrypt")) {
            Cryptor.encrypt(inFile, outFile, password);
        } else if (mode.equals("-decrypt")) {
            Cryptor.decrypt(inFile, outFile, password);
        } else {
            throw new GeneralSecurityException("Not a valid cipher mode");
        }
    }
}
