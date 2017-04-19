package ecc.entities;

import java.io.*;
import java.math.*;

public class Point implements Serializable {

    private static final long serialVersionUID = 1L;
    static final BigInteger Zero = new BigInteger("0");
    static final BigInteger One = new BigInteger("1");
    static final BigInteger MinusOne = new BigInteger("-1");

    Curve curve;
    public BigInteger x;
    public BigInteger y;

    public Point(BigInteger x1, BigInteger y1) {
        x = x1;
        y = y1;
    }

    public static Curve C = Curve.curve;
    public static BigInteger p = C.p;
    public static BigInteger A = C.A;
    public static BigInteger B = C.B;
    public static BigInteger q = C.q;
    public static BigInteger h = C.h;
    public static Point G = new Point(C.x, C.y);

    public Point add(Point p1) {

        BigInteger k = ((p1.y.subtract(y)).mod(p).multiply((p1.x.subtract(x)).modPow(MinusOne, p))).mod(p);
        BigInteger x3 = (k.multiply(k).subtract(x).subtract(p1.x)).mod(p);
        BigInteger y3 = (k.multiply(x.subtract(x3)).subtract(y)).mod(p);

        return new Point(x3, y3);
    }

    public Point twice() {
        BigInteger TWO = BigInteger.valueOf(2);
        BigInteger THREE = BigInteger.valueOf(3);
        BigInteger k = (((x.multiply(x).multiply(THREE).add(A)).mod(p)).multiply((y.multiply(TWO)).modPow(MinusOne, p))).mod(p);

        BigInteger x3 = (k.multiply(k).subtract(x.multiply(TWO))).mod(p);
        BigInteger y3 = (k.multiply(x.subtract(x3)).subtract(y)).mod(p);

        return new Point(x3, y3);
    }

    public Point subtract(Point p1) {
        return add(new Point(p1.x, p1.y.negate()));
    }

    public Point multiply(BigInteger k) {
        BigInteger e = k;

        BigInteger h = e.multiply(BigInteger.valueOf(3));

        Point L = this;

        for (int i = h.bitLength() - 2; i > 0; i--) {
            L = L.twice();

            if (h.testBit(i) && !e.testBit(i)) {
                L = L.add(this);
            } else if (!h.testBit(i) && e.testBit(i)) {
                L = L.subtract(this);
            }
        }
        return L;
    }

}
