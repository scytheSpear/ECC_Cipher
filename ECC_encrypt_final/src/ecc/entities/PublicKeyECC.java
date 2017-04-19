package ecc.entities;

import java.io.Serializable;
import java.math.BigInteger;

/**
 * PublicKeyECC is a class that has the storing structure of ECC public key.
 *
 * It implements Serializable interface.
 */
public class PublicKeyECC implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 2809028937109839037L;
    final public Point keyValue;
    final public String keyId;

    /**
     * Class constructor
     *
     * @param id specified key id
     * @param c curve used
     * @param k the private key value to construct this public key
     */
    public PublicKeyECC(String id, Curve c, BigInteger k) {
        final Point G = new Point(c.x, c.y);
        Point kG = G.multiply(k);
        this.keyValue = kG;

        this.keyId = id;
    }
}
