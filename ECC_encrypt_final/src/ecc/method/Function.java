package ecc.method;

import ecc.entities.Point;
import ecc.entities.Curve;
import java.math.BigInteger;
import java.util.Random;

public class Function {

    /**
     *
     */
    //private static final long serialVersionUID = 1L;
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

    public BigInteger RandomNum() {
        Random r = new Random();
        BigInteger K = new BigInteger(MAX_KEY_SIZE, r);
        return K;
    }

    public BigInteger RandomR() {
        Random r = new Random();
        BigInteger R = new BigInteger(q.bitLength(), r);
        return R;
    }

    public Point encryptASG(BigInteger As) {
        Point C1 = G.multiply(As);

        return C1;

    }

    public Point encryptBPM(Point M, BigInteger As, Point Bp) {
        Point C2 = new Point(BigInteger.ZERO, BigInteger.ZERO);
        Point c2 = Bp.multiply(As);

        if (c2.y == M.y && c2.x == M.x) {
            C2 = M.twice();
        } else {
            C2 = (c2.add(M));
        }
        return C2;
    }

    public Point decryptM(BigInteger Bs, Point C1, Point C2) {
        Point M = C2.subtract(C1.multiply(Bs));
        return M;
    }

    public Point SignDigSingnature(BigInteger As, BigInteger z) {

        Point V = new Point(BigInteger.valueOf(0), BigInteger.valueOf(0));
        BigInteger v = BigInteger.valueOf(0);
        BigInteger x1 = BigInteger.valueOf(0);
        BigInteger y1 = BigInteger.valueOf(0);

        try {
            do {
                v = RandomR();
                V = G.multiply(v);
                x1 = V.x.mod(q);
                y1 = ((z.add(x1.multiply(As)).mod(q)).multiply(v.modPow(MinusOne, q))).mod(q);
            } while (V.x == BigInteger.valueOf(0) || y1 == BigInteger.valueOf(0));
        } catch (Exception e) {
        }

        Point S = new Point(x1, y1);
        return S;
    }

    public boolean verifyingDigSingnature(Point S, Point Ap, BigInteger signedBytes) {
        boolean ver = false;

        try {
            if (S.x.compareTo(q) + S.y.compareTo(q) > -2 || S.x.compareTo(BigInteger.valueOf(0)) + S.y.compareTo(BigInteger.valueOf(0)) < 2) {
                ver = false;
            } else {
                BigInteger w = S.y.modPow(MinusOne, q);

                BigInteger u1 = signedBytes.multiply(w).mod(q);
                BigInteger u2 = S.x.multiply(w).mod(q);

                Point U1 = G.multiply(u1);
                Point U2 = Ap.multiply(u2);

                Point U = U1.add(U2);
                if (U.x.mod(q).equals(S.x)) {
                    ver = true;
                } else {
                    ver = false;
                }
            }
        } catch (Exception e) {
        }

        return ver;
    }

    public Point Encoding(char mes, Curve C) {
        int m1 = (int) mes;

        BigInteger m = BigInteger.valueOf(m1);

        Point M = G.multiply(m);

        return M;
    }

    public char Decoding(Point M, Curve C) {
        int ms = 0;
        BigInteger m = BigInteger.valueOf(1);

        //Point M1 = G.multiply(m);
        int i = 1;

        try {
            while ((G.multiply(m).x.toString()).compareTo(M.x.toString()) != 0
                    && (G.multiply(m).y.toString()).compareTo(M.y.toString()) != 0) {

                m = BigInteger.valueOf(i);
                i++;
            }
        } catch (Exception e) {
            System.err.println(e);
        }

        ms = m.intValue();
        char mes = (char) ms;

        return mes;
    }

    public Point Encode_Byte_toPoint(byte[] bytes, Curve C) {

        BigInteger m = new BigInteger(bytes);

        Point M = G.multiply(m);

        return M;

    }

    public byte[] Decode_Point_toBytes(Point point, Curve C) {

        byte[] ms;
        BigInteger m = BigInteger.valueOf(1);

        //Point M1 = G.multiply(m);
        int i = 1;

        try {
            while ((G.multiply(m).x.toString()).compareTo(point.x.toString()) != 0
                    && (G.multiply(m).y.toString()).compareTo(point.y.toString()) != 0) {

                m = BigInteger.valueOf(i);
                i++;
            }
        } catch (Exception e) {
            System.err.println(e);
        }

        ms = m.toByteArray();
        if (ms[0] == 0) {
            byte[] tmp = new byte[ms.length - 1];
            System.arraycopy(ms, 1, tmp, 0, tmp.length);
            ms = tmp;
        }

        return ms;
    }

    public boolean PointOnCurve(Point P, Curve C) {
        try {
            BigInteger x1, y1, tmp;
            x1 = BigInteger.ZERO;
            y1 = BigInteger.ZERO;
            tmp = BigInteger.ZERO;
            x1 = x1.add(P.x);
            x1 = x1.multiply(P.x);
            x1 = x1.multiply(P.x);
            tmp = tmp.add(C.A);
            tmp = tmp.multiply(P.x);
            x1 = x1.add(tmp);

            x1 = x1.add(C.B);
            x1 = x1.mod(C.p);

            y1 = y1.add(P.y);
            y1 = y1.multiply(P.y);
            y1 = y1.mod(C.p);
            if (x1.compareTo(y1) == 0) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

}
