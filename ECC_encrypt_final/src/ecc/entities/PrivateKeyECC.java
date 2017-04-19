package ecc.entities;

import ecc.util.UtilAES;
import ecc.util.UtilECC;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

/**
 * PrivateKeyECC is a class that has the storing structure of ECC private key.
 * Only the encrypted key and the hash value (here SHA-1) of the password would
 * be stored on the local file so that nobody would have access to the key value
 * without knowing the password.
 *
 * It implements Serializable interface.
 *
 */
public class PrivateKeyECC implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 3198055154682204576L;
    final public byte[] encryptKey;
    final public String keyId;
    final private String pwdHash;

    /**
     * Class constructor
     *
     * @param id specified key id
     * @param c curve used
     * @param password the user specified password
     * @throws UnsupportedEncodingException
     */
    public PrivateKeyECC(String id, Curve c, String password)
            throws UnsupportedEncodingException {
        BigInteger keyValue = UtilECC.GenerateRandomBigInteger(BigInteger.ONE,
                c.q.subtract(BigInteger.ONE));

        this.encryptKey = UtilAES.encrypt_privateKey(keyValue.toString(2), password);

        this.keyId = id;
        pwdHash = new String(UtilECC.ToSHA1(password.getBytes("UTF-8")));
    }

    /**
     * Verify if the hash value of the input password is consistent with the
     * stored member value of class.
     *
     * @param password the input password value
     * @return true if consistent, false if not
     * @throws UnsupportedEncodingException
     */
    public Boolean verifyPassward(String password)
            throws UnsupportedEncodingException {
        String verify = new String(UtilECC.ToSHA1(password.getBytes("UTF-8")));
        if (verify.equals(pwdHash)) {
            return true;
        }
        return false;
    }

    /**
     * Using password to calculate private key value. When one requires using
     * the key, he has to provide the correct password, which would be verified
     * hash value and then used to decrypt the key value.
     *
     * @param password the input password value
     * @return key value in BigInter, or null if password is incorrect
     * @throws UnsupportedEncodingException
     */
    public BigInteger getKeyValue(String password)
            throws UnsupportedEncodingException {
        String verify = new String(UtilECC.ToSHA1(password.getBytes("UTF-8")));
        if (verify.equals(pwdHash)) {
            String temp = UtilAES.decrypt_privateKey(encryptKey, password);
            BigInteger keyValue = new BigInteger(temp, 2);
            return keyValue;
        }
        return null;
    }

}
