package ecc.method;

import ecc.entities.Point;
import ecc.entities.Curve;
import ecc.entities.PrivateKeyECC;
import ecc.entities.PublicKeyECC;
import ecc.util.UtilECC;
import java.io.*;
import java.math.*;

public abstract class Singnature {

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

    /**
     * Sign digital signature on file. Based on Elliptic Curve Digital Signature
     * Algorithm (ECDSA).
     *
     * @param filePath the absolute path of file being signed
     * @param key the private key id that used to sign the file
     * @param pwd the password for the private key
     * @return a Point representing signature (r,s)
     * @throws IOException
     *
     * @see Point
     */
    public static Point Sign_Signature(String filePath, PrivateKeyECC key, String pwd) throws IOException {
        Function f = new Function();
        // Read file
        byte[] file = UtilECC.ReadFile(filePath);

        // SHA-1
        byte[] hash = UtilECC.ToSHA1(file);
        // e = HASH(M)
        BigInteger e = new BigInteger(hash);

        String binary = e.toString(2);

        // let z be the q bit-length leftmost bits of e.
        BigInteger z = e;
        if (binary.length() > C.q.bitLength()) {
            binary = binary.substring(binary.length() - 1 - C.q.bitLength(),
                    binary.length() - 1);
            z = new BigInteger(binary, 2);
        }

        BigInteger As = key.getKeyValue(pwd);

        Point signed = f.SignDigSingnature(As, z);

        return signed;
    }

    /**
     * Verify digital signature of ECC Based on Elliptic Curve Digital Signature
     * Algorithm (ECDSA).
     *
     * @param filePath the absolute path of file being verified
     * @param sign the signature being verified
     * @param key the public key used to verify
     * @return true if signature is verified valid, false if invalid
     * @throws IOException
     */
    public static Boolean Verify_Signature(String filePath, Point sign, PublicKeyECC key) throws IOException {

        Function f = new Function();
        Point Ap = key.keyValue;

        // Verify Signature
        // Check r and s in [1, q-1]
        BigInteger r = sign.x;
        BigInteger s = sign.y;

        if (r.compareTo(C.q) >= 0) {
            return false;
        } else if (s.compareTo(C.q) >= 0) {
            return false;
        }

        // Read file
        byte[] file = UtilECC.ReadFile(filePath);

        // SHA-1
        byte[] hash = UtilECC.ToSHA1(file);
        // e = HASH(M)
        BigInteger e = new BigInteger(hash);

        String binary = e.toString(2);

        // let z be the q bit-length leftmost bits of e.
        BigInteger z = e;
        if (binary.length() > C.q.bitLength()) {
            binary = binary.substring(
                    binary.length() - 1 - C.q.bitLength(),
                    binary.length() - 1);
            z = new BigInteger(binary, 2);
        }

        boolean result = f.verifyingDigSingnature(sign, Ap, z);

        return result;
    }
}
