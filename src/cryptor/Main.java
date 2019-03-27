package cryptor;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Scanner;

/**
 * Main entry point for running the Cryptor program.
 */
public class Main {

    /**
     * Calls an encryption or decryption method according to command-line arguments.
     * If no arguments are given then command prompts will be shown.
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

        if (args.length > 0) {
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
        } else {
            Scanner scan = new Scanner(System.in);
            System.out.print("Enter input filename: ");
            String fileIn = scan.nextLine();

            System.out.print("Enter output filename: ");
            String fileOut = scan.nextLine();

            System.out.print("Enter password: ");
            char[] password = scan.nextLine().toCharArray();

            System.out.print("Enter cipher mode [encrypt | decrypt]: ");
            String modeIn = scan.nextLine();

            if (modeIn.equals("encrypt")) {
                Cryptor.encrypt(fileIn, fileOut, password);
            } else if (modeIn.equals("decrypt")) {
                Cryptor.decrypt(fileIn, fileOut, password);
            } else {
                throw new GeneralSecurityException("Not a valid cipher mode");
            }
        }
    }
}
