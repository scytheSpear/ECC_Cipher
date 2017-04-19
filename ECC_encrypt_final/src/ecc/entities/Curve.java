package ecc.entities;

import java.math.BigInteger;

public class Curve {

    public static final BigInteger cp = new BigInteger("E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16);
    public static final BigInteger cA = new BigInteger("340E7BE2A280EB74E2BE61BADA745D97E8F7C300", 16);
    public static final BigInteger cB = new BigInteger("1E589A8595423412134FAA2DBDEC95C8D8675E58", 16);
    public static final BigInteger cx = new BigInteger("BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", 16);
    public static final BigInteger cy = new BigInteger("1667CB477A1A8EC338F94741669C976316DA6321", 16);
    public static final BigInteger cq = new BigInteger("E95E4A5F737059DC60DF5991D45029409E60FC09", 16);
    public static final BigInteger ch = new BigInteger("1", 16);

    public BigInteger p, A, B, x, y, q, h;

    public Curve(BigInteger p1, BigInteger A1, BigInteger B1, BigInteger x1, BigInteger y1, BigInteger q1, BigInteger h1) {
        p = p1;
        A = A1;
        B = B1;
        x = x1;
        y = y1;
        q = q1;
        h = h1;
    }

    public static Curve curve = new Curve(cp, cA, cB, cx,
            cy, cq, ch);
}
