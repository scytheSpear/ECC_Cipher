package ecc.encrypt;

import ecc.entities.KeyRingECC;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

/**
 * ECC_MAIN is the main class of the encryption system. It mainly takes the command
 * parameters that users input and deals with them.
 *
 * @see ArgsAnalyzer
 */
public class ECC_MAIN {

    final static String KEY_RING_PATH = "keyring";

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception, IOException {

        KeyRingECC keyRing;

        File file = new File(KEY_RING_PATH);

        if (file.exists()) {
            // Restore key ring
            ObjectInputStream ois;
            ois = new ObjectInputStream(new FileInputStream(KEY_RING_PATH));
            keyRing = (KeyRingECC) ois.readObject();
            ois.close();
        } else {
            keyRing = new KeyRingECC();
            // Update key ring
            ObjectOutputStream oos = new ObjectOutputStream(
                    new FileOutputStream(KEY_RING_PATH));
            oos.writeObject(keyRing);
            oos.close();
        }

        Actions actions = new Actions(keyRing);

        // Deal with command line
        int func = ArgsAnalyzer.analyze(args);
        // Generate new key pair
        if (func == 0) {

            String keyId = args[1];
            
            actions.GenerateNewKeyPair(keyId);
            
        } // Output public key to a file
        else if (func == 1) {

            String keyId = args[1];
            String filePath = args[3];
            
            actions.Publish_PublicKey_toFile(keyId, filePath);
        } // Import public key from a file
        else if (func == 2) {

            String filePath = args[2];

            actions.Import_PublicKey_fromFile(filePath);
        } // Encrypt a message
        // Directly map the message to a point on curve
        else if (func == 3) {
            String privateKeyId = args[1];
            String publicKeyId = args[2];
            String filePath = args[4];

            actions.Encrypt_Messages(privateKeyId, publicKeyId, filePath);

        } // Decrypt a message which has been mapped to a point
        else if (func == 4) {
            String privateKeyId = args[1];
            String publicKeyId = args[2];
            String filePath = args[4];

            actions.Decrypt_Messages(privateKeyId, publicKeyId, filePath);
        } // Encrypt file using AES
           //Encrypt AES key using ECC
                else if (func == 5) {
        
                    String privateKeyId = args[1];
                    String publicKeyId = args[2];
                    String inputFilename = args[4];
                    String outputFilename = args[6];
        
                    actions.Encrypt_File(privateKeyId, publicKeyId, inputFilename, outputFilename);
        
                } // Decrypt AES key using ECC
                // Decrypt file key using AES
                else if (func == 6) {
        
                    String privateKeyId = args[1];
                    String publicKeyId = args[2];
                    String inputFilename = args[4];
                    String outputFilename = args[6];
        
                   actions.Decrypt_File(privateKeyId, publicKeyId, inputFilename, outputFilename);
        
                } // Sign digital signature on a file
        //        else if (func == 7) {
        //
        //            String filePath = args[3];
        //            String keyId = args[1];
        //            String signPath = args[5];
        //
        //            // Get key
        //            PrivateKeyECC privateKey = keyRing.getPrivateKey(keyId);
        //
        //            if (privateKey == null) {
        //                System.out.println("no such key(s) exists in key ring!");
        //            } else if (!(new File(filePath)).exists()) {
        //                System.out.println("file does not exist!");
        //            } else {
        //
        //                // Input mask
        //                Console console = System.console();
        //                char[] pwdMask = console
        //                        .readPassword("please input password for your private key: ");
        //                String pwd = new String(pwdMask);
        //
        //                if (!privateKey.verifyPassward(pwd)) {
        //                    System.out.println("invalid password!");
        //                } else {
        //
        //                    System.out.println("password verified.");
        //
        //                    // sign signature
        //                    Point sign = UtilECC.signDigitalSignature(filePath,
        //                            privateKey, pwd);
        //                    // write to file
        //                    ObjectOutputStream oos = new ObjectOutputStream(
        //                            new FileOutputStream(signPath));
        //                    oos.writeObject(sign);
        //                    oos.close();
        //
        //                    System.out
        //                            .println("digital signature signed successfully.");
        //                }
        //            }
        //        } // Verify digital signature of a file
        //        else if (func == 8) {
        //
        //            String filePath = args[3];
        //            String keyId = args[1];
        //            String signPath = args[4];
        //
        //            // get key
        //            PublicKeyECC publicKey = keyRing.getPublicKey(keyId);
        //
        //            if (publicKey == null) {
        //                System.out.println("no such key(s) exist in key ring");
        //            } else {
        //
        //                // Read signature file
        //                ObjectInputStream ois = new ObjectInputStream(
        //                        new FileInputStream(signPath));
        //                Point sign = (Point) ois.readObject();
        //                ois.close();
        //
        //                Boolean verify = util.verifyDigitalSignature(filePath, sign,
        //                        publicKey);
        //                System.out.println("signature valid : " + verify);
        //            }
        //        } // List all keys
        else if (func == 10) {
            keyRing.listAllKeys();
        } // Output help
        else if (func == 9) {
            System.out.println("ECC help:\n\n"
                    + "List all keys in the key ring:\n"
                    + "ECC -list\n\n"
                    + "Generate new key pair:\n"
                    + "ECC -k keyID -g\n\n"
                    + "Export public key to file:\n"
                    + "ECC -k keyID -o filename\n\n"
                    + "Import public key from file:\n"
                    + "ECC -k -i filename\n\n"
                    + "Encrypt entered message and output to file:\n"
                    + "ECC -em pri_keyID pub_keyID -o filename\n\n"
                    + "Decrypt message file and print out:\n"
                    + "ECC -dm pri_keyID pub_keyID -i filename\n\n"
                    + "Encrypt a file:\n"
                    + "ECC -ef pri_keyID pub_keyID -i plainTextFile -o cipherTextFile\n\n"
                    + "Decrypt a file:\n"
                    + "ECC -df pri_keyID pub_keyID -i cipherTextFile -o decryptedFile\n\n"
                    + "Sign a file:\n"
                    + "ECC -s keyID -i filename -o signature\n\n"
                    + "Verify a signature:\n"
                    + "ECC -v keyID -i filename signature\n");
        } else {
            System.out.println("invalid arguments!");
        }
    }
}
