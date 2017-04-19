package ecc.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * UtilAES class include methods used in AES encryption and decryption
 * 
 * 
 */
public abstract class UtilAES {

    public static byte[] encrypt_privateKey(String content, String password) {
        try {

            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, new SecureRandom(password.getBytes()));
            SecretKey secretKey = kgen.generateKey();

            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");

            byte[] byteContent = content.getBytes("utf-8"); //encode keyString to utf-8 byte
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] result = cipher.doFinal(byteContent);

            return result;
        } catch (NoSuchPaddingException | NoSuchAlgorithmException |
                UnsupportedEncodingException | InvalidKeyException |
                IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(UtilAES.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static String decrypt_privateKey(byte[] content, String password) {
        try {
            KeyGenerator kgen = KeyGenerator.getInstance("AES");
            kgen.init(128, new SecureRandom(password.getBytes()));
            SecretKey secretKey = kgen.generateKey();
            byte[] enCodeFormat = secretKey.getEncoded();
            SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] resultByte = cipher.doFinal(content);

            String result = new String(resultByte, "utf-8");

            return result;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                InvalidKeyException | IllegalBlockSizeException |
                BadPaddingException | UnsupportedEncodingException ex) {
            Logger.getLogger(UtilAES.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public static byte[] FileBytes_encrypt(byte[] inputBytes, SecretKey skey) {

        byte[] cipherBytes = null;
        try {
            Cipher AesCipher = Cipher.getInstance("AES");
            AesCipher.init(Cipher.ENCRYPT_MODE, skey);
            cipherBytes = AesCipher.doFinal(inputBytes);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException 
                | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(UtilAES.class.getName()).log(Level.SEVERE, null, ex);
        }

        return cipherBytes;

    }

}
