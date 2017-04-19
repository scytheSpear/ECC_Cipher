package ecc.encrypt;

import static ecc.encrypt.ECC_MAIN.KEY_RING_PATH;
import static ecc.entities.Curve.curve;
import ecc.entities.KeyPairECC;
import ecc.entities.KeyRingECC;
import ecc.entities.PrivateKeyECC;
import ecc.entities.PublicKeyECC;
import ecc.method.Decrypt;
import ecc.method.Encrypt;
import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.text.DecimalFormat;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *Actions taken by user with user input 
 * 
 * @author user
 */
public class Actions {

    KeyRingECC keyRing;

    public Actions(KeyRingECC kr) {
        this.keyRing = kr;
    }

    /**
     * Generate a new new ECC key pair stored to file keyRing
     *
     * @param keyId
     */
    public void GenerateNewKeyPair(String keyId) {

        try {
            if (keyRing.keyExist(keyId)) {
                System.out.println("same key id already exists!");
            } else {
                // Input mask
                Console console = System.console();
                char[] pwdMask = console
                        .readPassword("please set password for this key: ");
                String pwd = new String(pwdMask);
                pwdMask = console
                        .readPassword("please input your password again: ");
                if (!pwd.equals(new String(pwdMask))) {
                    System.out.println("passwords entered do not match.");
                } else {

                    KeyPairECC newKeyPair = new KeyPairECC(keyId, curve, pwd);
                    keyRing.add(newKeyPair);

                    // Update key ring
                    ObjectOutputStream oos = new ObjectOutputStream(
                            new FileOutputStream(KEY_RING_PATH));
                    oos.writeObject(keyRing);
                    oos.close();

                    System.out.println("key pair generated successfully.");
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Publish a public key to file so other can encrypt with it
     *
     * @param keyId
     * @param outputFilePath
     */
    public void Publish_PublicKey_toFile(String keyId, String outputFilePath) {

        try {
            PublicKeyECC publicKey = keyRing.getPublicKey(keyId);

            if (publicKey == null) {
                System.out.println("no such key(s) exists in key ring!");
            } else {

                ObjectOutputStream oos = new ObjectOutputStream(
                        new FileOutputStream(outputFilePath));
                oos.writeObject(publicKey);
                oos.close();

                System.out.println("public key output successfully.");
            }
        } catch (IOException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Import a public key from file to encrypt and send to certain people
     *
     * @param inputFilePath
     */
    public void Import_PublicKey_fromFile(String inputFilePath) {

        try {
            if (!(new File(inputFilePath)).exists()) {
                System.out.println("file does not exist!");
            } else {
                ObjectInputStream ois;
                ois = new ObjectInputStream(new FileInputStream(inputFilePath));
                PublicKeyECC key = (PublicKeyECC) ois.readObject();
                ois.close();

                PublicKeyECC exist = keyRing.getPublicKey(key.keyId);
                if (exist != null) {
                    System.out.println("same key already exists!");
                } else {
                    keyRing.add(key);

                    // Update key ring
                    ObjectOutputStream oos = new ObjectOutputStream(
                            new FileOutputStream(KEY_RING_PATH));
                    oos.writeObject(keyRing);
                    oos.close();

                    System.out.println("public key import successfully.");
                }
            }
        } catch (IOException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * Encrypt a user input message
     *
     * @param privateKeyId
     * @param publicKeyId
     * @param outputFilePath
     */
    public void Encrypt_Messages(String privateKeyId, String publicKeyId, String outputFilePath) {

        PrivateKeyECC privateKey = keyRing.getPrivateKey(privateKeyId);
        PublicKeyECC publicKey = keyRing.getPublicKey(publicKeyId);
        try {
            if (publicKey == null || privateKey == null) {
                System.out.println("no such key(s) exists in key ring!");
            } else {

                // Input mask
                Console console = System.console();
                char[] pwdMask = console
                        .readPassword("please input password for your private key: ");
                String pwd = new String(pwdMask);

                if (!privateKey.verifyPassward(pwd)) {
                    System.out.println("invalid password!");
                } else {
                    System.out.println("password verified.");

                    System.out.println("please input your message:");
                    BufferedReader br = new BufferedReader(
                            new InputStreamReader(System.in));
                    String input = br.readLine();

                    Encrypt.Encrypt_String_toFile(privateKey, publicKey, pwd, input, outputFilePath);

                    System.out.println("message encrypted successfully. store at " + outputFilePath);
                }
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Decrypt a user input message from file output in console without file
     *
     * @param privateKeyId
     * @param publicKeyId
     * @param inputFilePath
     */
    public void Decrypt_Messages(String privateKeyId, String publicKeyId, String inputFilePath) {

        PrivateKeyECC privateKey = keyRing.getPrivateKey(privateKeyId);
        PublicKeyECC publicKey = keyRing.getPublicKey(publicKeyId);
        try {
            if (publicKey == null || privateKey == null) {
                System.out.println("no such key(s) exists in key ring!");
            } else if (!(new File(inputFilePath)).exists()) {
                System.out.println("file does not exist!");
            } else {

                // Input mask
                Console console = System.console();
                char[] pwdMask = console
                        .readPassword("please input password for your private key: ");
                String pwd = new String(pwdMask);

                if (!privateKey.verifyPassward(pwd)) {
                    System.out.println("invalid password!");
                } else {
                    System.out.println("password verified.");

                    String msg;

                    msg = Decrypt.Decrypt_String_toFile(privateKey, publicKey, pwd, inputFilePath);

                    System.out.println("message decrypted successfully.");
                    System.out.println("message: " + msg);
                }
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
/**
 * Encrypt a file with AES, the AES key was encrypt by ECC and attached in cipher and output cipher as file
 * 
 * @param privateKeyId
 * @param publicKeyId
 * @param inputFilePath
 * @param outputFilePath 
 */
    public void Encrypt_File(String privateKeyId, String publicKeyId, String inputFilePath, String outputFilePath) {

        PrivateKeyECC privateKey = keyRing.getPrivateKey(privateKeyId);
        PublicKeyECC publicKey = keyRing.getPublicKey(publicKeyId);
        File file = new File(inputFilePath);

        try {

            if (publicKey == null || privateKey == null) {
                System.out.println("no such key(s) exists in key ring!");
            } else if (!file.exists()) {
                System.out.println("file does not exist!");
            } else {
                // Input mask
                Console console = System.console();
                char[] pwdMask = console
                        .readPassword("please input password for your private key: ");
                String pwd = new String(pwdMask);

                if (!privateKey.verifyPassward(pwd)) {
                    System.out.println("invalid password!");
                } else {
                    long size = file.length();
                    System.out.println("password verified.");
                    System.out.println("start file encryption...");

                    long start = System.currentTimeMillis();

                    Encrypt.Encrypt_File_withAES(privateKey, publicKey, pwd, inputFilePath, outputFilePath);

                    long end = System.currentTimeMillis();
                    double time = (end - start) / 1000d;
                    DecimalFormat df = new DecimalFormat();
                    df.setMaximumFractionDigits(2);
                    double speed = (double) size / (double) (1024 * 1024 * time);
                    System.out.println("file encrypted successfully.");
                    System.out.println("time cost: " + df.format(time) + " s.");
                    System.out.println("encryption speed: " + df.format(speed)
                            + " mb/s.");
                }
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Read cipher file and decrypt with AES output file
     * @param privateKeyId
     * @param publicKeyId
     * @param inputFilePath
     * @param outputFilePath 
     */
    public void Decrypt_File(String privateKeyId, String publicKeyId, String inputFilePath, String outputFilePath) {

        PrivateKeyECC privateKey = keyRing.getPrivateKey(privateKeyId);
        PublicKeyECC publicKey = keyRing.getPublicKey(publicKeyId);
        File file = new File(inputFilePath);

        try {

            if (publicKey == null || privateKey == null) {
                System.out.println("no such key(s) exists in key ring!");
            } else if (!file.exists()) {
                System.out.println("file does not exist!");
            } else {
                // Input mask
                Console console = System.console();
                char[] pwdMask = console
                        .readPassword("please input password for your private key: ");
                String pwd = new String(pwdMask);

                if (!privateKey.verifyPassward(pwd)) {
                    System.out.println("invalid password!");
                } else {
                    long size = file.length();

                    System.out.println("password verified.");
                    System.out.println("start file decryption...");

                    long start = System.currentTimeMillis();

                    Decrypt.Decrypt_File_withAES(privateKey, publicKey, pwd, inputFilePath, outputFilePath);

                    long end = System.currentTimeMillis();

                    double time = (end - start) / 1000d;
                    DecimalFormat df = new DecimalFormat();
                    df.setMaximumFractionDigits(2);
                    double speed = (double) size / (double) (1024 * 1024 * time);
                    System.out.println("file decrypted successfully.");
                    System.out.println("time cost: " + df.format(time) + " s.");
                    System.out.println("decryption speed: " + df.format(speed)
                            + " mb/s.");
                }
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ClassNotFoundException ex) {
            Logger.getLogger(Actions.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
