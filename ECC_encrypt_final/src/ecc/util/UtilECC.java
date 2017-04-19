package ecc.util;

import ecc.entities.Point;
import ecc.entities.PrivateKeyECC;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * UtilECC is a class that holds all the utility functions using in ECC. It has
 * a static member representing the elliptic curve being using.
 *
 */
public abstract class UtilECC {

    /**
     * Read whole file into a byte array
     *
     * @param filePath the absolute path of the file being read
     * @return result byte array
     * @throws IOException
     */
    public static byte[] ReadFile(String filePath) throws IOException {
        File file = new File(filePath);
        InputStream in = new FileInputStream(file);

        long length = file.length();
        byte[] bytes = new byte[(int) length];

        int offset = 0;
        int numRead = 0;
        while (offset < bytes.length
                && (numRead = in.read(bytes, offset, bytes.length - offset)) >= 0) {
            offset += numRead;
        }

        if (offset < bytes.length) {
            throw new IOException("cannot read complete file: "
                    + file.getName());
        }
        in.close();
        return bytes;
    }

    /**
     * Verify privateKeys password
     *
     * @param keyId
     * @param pkey
     * @return
     * @throws UnsupportedEncodingException
     */
    public static boolean VerifyPrivateKeyPw(String keyId, PrivateKeyECC pkey) throws UnsupportedEncodingException {

        Console console = System.console();
        char[] pwdMask = console
                .readPassword("please input password for your private key: ");
        String pwd = new String(pwdMask);

        if (!pkey.verifyPassward(pwd)) {
            System.out.println("invalid password!");
            return false;
        } else {
            System.out.println("password verified.");
            return true;
        }

    }

    /**
     * Generate a random integer between the specified range. Use random seed
     * provided by java library.
     *
     * @param min the bottom of integer range
     * @param max the top of integer range
     * @return a BigInteger generated
     */
    public static BigInteger GenerateRandomBigInteger(BigInteger min,
            BigInteger max) {
        BigInteger result;
        Random rnd = new Random();

        do {
            result = new BigInteger(max.bitLength(), rnd);
            if (result.compareTo(max) <= 0 && result.compareTo(min) >= 0) {
                return result;
            }
        } while (true);
    }

    /**
     * Generate a random string for aes key
     *
     * @param lenght
     * @return
     */
    public static String GenerateRandomString(int lenght) {

        SecureRandom random = new SecureRandom();

        String randomString = new BigInteger(lenght, random).toString(64);

        return randomString;

    }

    /**
     * SHA-1 hash function. Convert a byte array into another fix-length byte
     * array.
     *
     * @param convert byte array that would be converted
     * @return the result hash value in byte array
     */
    public static byte[] ToSHA1(byte[] convert) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return md.digest(convert);
    }

    /**
     * Convert byte[] to hex string
     *
     * @param src hex byte array
     * @return hex string
     */
    public static String BytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder(src.length);
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        String temp = stringBuilder.toString();
        if (temp.charAt(0) == '0') {
            temp = temp.substring(1);
        }

        return temp;
    }

    /**
     * Convert hex string to byte[]
     *
     * @param hexString string being converted
     * @return hex byte array
     */
    public static byte[] HexStringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        int reminder = hexChars.length - hexChars.length / 2 * 2;
        if (reminder == 1) {
            hexString = '0' + hexString;
            hexChars = hexString.toCharArray();
            length++;
        }
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (CharToByte(hexChars[pos]) << 4 | CharToByte(hexChars[pos + 1]));
        }
        return d;
    }

    /**
     * Convert char to byte
     *
     * @param char char being converted
     *
     * @return converted byte
     */
    private static byte CharToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    /**
     * Encode byte array to Point object
     *
     * @param bytes
     * @return
     * @throws IOException
     * @throws ClassNotFoundException
     */
    public static Point[] DeserializeBytes(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream bytesIn = new ByteArrayInputStream(bytes);
        ObjectInputStream ois = new ObjectInputStream(bytesIn);
        Point[] points = (Point[]) ois.readObject();
        ois.close();
        return points;
    }

    /**
     * Decode point object to byte array
     *
     * @param points
     * @return
     * @throws IOException
     */
    public static byte[] SerializeObject(Point[] points) throws IOException {
        ByteArrayOutputStream bytesOut = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bytesOut);
        oos.writeObject(points);
        oos.flush();
        byte[] bytes = bytesOut.toByteArray();
        bytesOut.close();
        oos.close();
        return bytes;
    }

    public static byte[] BytesConcatenate(byte[] a, byte[] b) {
        if (a == null && b == null) {
            return null;
        } else if (a == null && b != null) {
            return b;
        } else if (a != null && b == null) {
            return a;
        } else if (a != null && b != null) {
            byte[] c = new byte[a.length + b.length];
            System.arraycopy(a, 0, c, 0, a.length);
            System.arraycopy(b, 0, c, a.length, b.length);
            return c;
        }
        return null;
    }

    /**
     * Convert Int to byte array
     *
     * @param res
     * @return
     */
    public static byte[] IntToByte(int res) {
        byte[] targets = new byte[4];

        targets[0] = (byte) (res & 0xff);
        targets[1] = (byte) ((res >> 8) & 0xff);
        targets[2] = (byte) ((res >> 16) & 0xff);
        targets[3] = (byte) (res >>> 24);
        return targets;
    }

    /**
     * convert byte array to int
     *
     * @param res
     * @return
     */
    public static int ByteToInt(byte[] res) {
        int targets = (res[0] & 0xff) | ((res[1] << 8) & 0xff00)
                | ((res[2] << 24) >>> 8) | (res[3] << 24);
        return targets;
    }

}
