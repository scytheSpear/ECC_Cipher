package ecc.method;

import ecc.entities.AesTransfer;
import ecc.entities.Point;
import ecc.entities.Curve;
import ecc.entities.PrivateKeyECC;
import ecc.entities.PublicKeyECC;
import ecc.util.UtilAES;
import ecc.util.UtilECC;
import java.io.*;
import java.math.*;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public abstract class Encrypt {

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

    public static void Encrypt_String_toFile(PrivateKeyECC sender_PrivateKeyECC, PublicKeyECC recipient_PublicKeyECC,
            String send_Pkey_pw, String messageString, String outputFilePath) {

        Function f = new Function();

        //Take input and encoding to a Point array Ma[] 
        String mes1 = "0";
        char[] Mes;
        Point[] Ma;
        Point[] Ca;
        BigInteger As;

        Point Bp = new Point(BigInteger.ZERO, BigInteger.ZERO);

        try {
            As = sender_PrivateKeyECC.getKeyValue(send_Pkey_pw);
            Bp = recipient_PublicKeyECC.keyValue;
            mes1 = messageString;

            Mes = new char[mes1.length()];
            Ca = new Point[mes1.length()];
            Ma = new Point[mes1.length()];

            for (int i = 0; i < mes1.length(); i++) {

                Mes[i] = mes1.charAt(i);

//            System.out.println("Message char Array: " + Mes[i]);
                //System.out.println(Encoding (Mes[i], C));
                //Take public key of B point Bp and private key of A big int As as input and encrpt message to point array Ma
                Ma[i] = f.Encoding(Mes[i], C);

                if (f.PointOnCurve(Ma[i], C)) {
//                System.out.println("MArray y: " + Ma[i].y);

                    Point C2 = f.encryptBPM(Ma[i], As, Bp);

                    //System.out.println("C2 y: "+C2.y);
                    Ca[i] = C2;
//                System.out.println("C2Array y: " + Ca[i].y);
                } else {
                    System.out.println("M is not on C");
                }

                FileOutputStream fout = new FileOutputStream(outputFilePath);
                ObjectOutputStream oos = new ObjectOutputStream(fout);
                oos.writeObject(Ca);
                oos.flush();
                oos.close();
                fout.close();
            }
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void Encrypt_File_withAES(PrivateKeyECC sender_PrivateKeyECC, PublicKeyECC recipient_PublicKeyECC,
            String send_Pkey_pw, String inputFilePath, String outputFilePath) throws NoSuchAlgorithmException {

        int BLOCK_SIZE = 1;

        byte[] keyBytes = UtilECC.GenerateRandomString(128).getBytes();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128, new SecureRandom(keyBytes));
        SecretKey secretKey = keyGen.generateKey();

        Function f = new Function();

        //Take input and encoding to a Point array Ma[] 
        byte[] Mes;
        Point[] Ma;
        Point[] Ca;
        BigInteger As;

        Point Bp = new Point(BigInteger.ZERO, BigInteger.ZERO);

        try {
            As = sender_PrivateKeyECC.getKeyValue(send_Pkey_pw);
            Bp = recipient_PublicKeyECC.keyValue;

            Mes = keyBytes;
            int length = Mes.length;
//            System.out.println("key l " + length);
//            System.out.println("key = " + secretKey.toString());

            double ld = length;
            double bd = BLOCK_SIZE;

            int pLength = (int) Math.ceil(ld / bd);

            Ca = new Point[pLength];
            Ma = new Point[pLength];
            int count = 0;

            // Divide message into 1-byte blocks
            for (int i = 0; i < length; i = i + BLOCK_SIZE) {
                byte[] block = Arrays.copyOfRange(Mes, i, Math.min(i + BLOCK_SIZE, length));

                Ma[count] = f.Encode_Byte_toPoint(block, C);

                if (f.PointOnCurve(Ma[count], C)) {
                    Point C2 = f.encryptBPM(Ma[count], As, Bp);
                    Ca[count] = C2;
                } else {
                    System.out.println("M is not on C");
                }
                count++;
            }

            byte[] pwCipher = UtilECC.SerializeObject(Ca);
//            byte[] lengthBytes = ByteBuffer.allocate(4).putInt(cipherLength).array();
            byte[] lengthBytes = UtilECC.IntToByte(BLOCK_SIZE);
            byte[] cipherBytes = UtilAES.FileBytes_encrypt(UtilECC.ReadFile(inputFilePath), secretKey);

            AesTransfer aesData = new AesTransfer();
            aesData.setPwBlockLength(lengthBytes);
            aesData.setPasswordCipher(pwCipher);
            aesData.setFileCipherText(cipherBytes);

            FileOutputStream fout = new FileOutputStream(outputFilePath);
            ObjectOutputStream oos = new ObjectOutputStream(fout);
            oos.writeObject(aesData);
            oos.flush();
            oos.close();
            fout.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(Encrypt.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
}
