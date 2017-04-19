package ecc.method;

import ecc.entities.AesTransfer;
import ecc.entities.Point;
import ecc.entities.Curve;
import ecc.entities.PrivateKeyECC;
import ecc.entities.PublicKeyECC;
import ecc.util.UtilECC;
import java.io.*;
import java.math.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public abstract class Decrypt {

    static final BigInteger Zero = new BigInteger("0");
    static final BigInteger One = new BigInteger("1");
    static final BigInteger MinusOne = new BigInteger("-1");

    static final int MAX_BUFFER_SIZE = 2048;
    static final int MAX_KEY_SIZE = 160;
    static final int MAX_ASCII = 255;

    static Curve C = Curve.curve;
    static BigInteger p = C.p;
    static BigInteger A = C.A;
    static BigInteger B = C.B;
    static BigInteger q = C.q;
    static BigInteger h = C.h;
    static Point G = new Point(C.x, C.y);

    public static String Decrypt_String_toFile(PrivateKeyECC recipient_PrivateKeyECC, PublicKeyECC sender_PublicKeyECC,
            String send_Pkey_pw, String inputFilePath) throws FileNotFoundException, IOException, ClassNotFoundException {

        Function f = new Function();

        BigInteger Bs = recipient_PrivateKeyECC.getKeyValue(send_Pkey_pw);

        Point Ap = new Point(BigInteger.ZERO, BigInteger.ZERO);
        Ap = sender_PublicKeyECC.keyValue;

        FileInputStream fin = new FileInputStream(inputFilePath);
        ObjectInputStream ois = new ObjectInputStream(fin);
        Point[] readFile = (Point[]) ois.readObject();

        char[] msg = new char[readFile.length];
        Point[] Msg = new Point[readFile.length];

        for (int i = 0; i < readFile.length; i++) {

            Msg[i] = f.decryptM(Bs, Ap, readFile[i]);
            msg[i] = f.Decoding(Msg[i], C);

        }

        String Pm = String.valueOf(msg);

        return Pm;
    }

    public static void Decrypt_File_withAES(PrivateKeyECC recipient_PrivateKeyECC, PublicKeyECC sender_PublicKeyECC,
            String recipient_Pkey_pw, String inputFilePath, String outputFilePath) throws IOException, ClassNotFoundException {

//        int BLOCK_SIZE = 1;
        FileInputStream fin = new FileInputStream(inputFilePath);
        ObjectInputStream ois = new ObjectInputStream(fin);
        AesTransfer aesData = (AesTransfer) ois.readObject();

        byte[] pwBlockLength = aesData.getPwBlockLength();
        int pwBlockLengthInt = UtilECC.ByteToInt(pwBlockLength);
        byte[] pwCipherBytes = aesData.getPasswordCipher();
        byte[] cipherBytes = aesData.getFileCipherText();

        Function f = new Function();
        BigInteger recipientPKey = recipient_PrivateKeyECC.getKeyValue(recipient_Pkey_pw);
        Point senderPubkey = new Point(BigInteger.ZERO, BigInteger.ZERO);
        senderPubkey = sender_PublicKeyECC.keyValue;

        try {

            Point[] pwECCPoints = UtilECC.DeserializeBytes(pwCipherBytes);
            byte[] pwBytes = new byte[0];
            ByteBuffer byteBuffer = ByteBuffer.allocate(pwECCPoints.length);

            for (int i = 0; i < pwECCPoints.length; i++) {

                Point pwB1Points = f.decryptM(recipientPKey, senderPubkey, pwECCPoints[i]);
                byte[] block = f.Decode_Point_toBytes(pwB1Points, C);
                byteBuffer.put(block);
            }

            pwBytes = byteBuffer.array();

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom(pwBytes));
            SecretKey originalKey = keyGen.generateKey();

            Cipher AesCipher = Cipher.getInstance("AES");
            AesCipher.init(Cipher.DECRYPT_MODE, originalKey);
            byte[] bytePlainText = AesCipher.doFinal(cipherBytes);

            FileOutputStream fout = new FileOutputStream(outputFilePath);
            fout.write(bytePlainText);
            fout.close();

        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
            Logger.getLogger(Decrypt.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
