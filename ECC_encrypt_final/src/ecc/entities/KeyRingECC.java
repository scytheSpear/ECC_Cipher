package ecc.entities;

import java.io.Serializable;
import java.util.*;

/**
 * KeyRingECC is a class that has a structure of storing public and private keys
 * of ECC. It has two member vectors which holds private and public keys
 * respectively.
 *
 * @see PublicKeyECC
 * @see PrivateKeyECC
 */
public class KeyRingECC implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 6496868094088874287L;

    final private Vector<PublicKeyECC> keyRingPublic;
    final private Vector<PrivateKeyECC> keyRingPrivate;

    /**
     * Class constructor.
     */
    public KeyRingECC() {
        keyRingPublic = new Vector<PublicKeyECC>();
        keyRingPrivate = new Vector<PrivateKeyECC>();
    }

    /**
     * Add a pair of key to the key ring. Actually add private and public key to
     * their vectors respectively.
     *
     * @param keyPair the pair of key being added.
     *
     * @see KeyPairECC
     * @see PublicKeyECC
     * @see PrivateKeyECC
     */
    public void add(KeyPairECC keyPair) {
        keyRingPublic.add(keyPair.publicKey);
        keyRingPrivate.add(keyPair.privateKey);
    }

    /**
     * Add a public key to the public key ring.
     *
     * @param key the public key being added.
     *
     * @see PublicKeyECC
     */
    public void add(PublicKeyECC key) {
        keyRingPublic.add(key);
    }

    /**
     * Get private key object by key id. If no key of such id exists, return
     * null.
     *
     * @param id the id of key which is required
     * @return private key object or null if not exists
     *
     * @see PrivateKeyECC
     */
    public PrivateKeyECC getPrivateKey(String id) {

        for (int i = 0; i < keyRingPrivate.size(); i++) {
            PrivateKeyECC key = keyRingPrivate.get(i);
            if (key.keyId.equals(id)) {
                return key;
            }
        }

        return null;
    }

    /**
     * Get public key object by key id. If no key of such id exists, return
     * null.
     *
     * @param id the id of key which is required
     * @return public key object or null if not exists
     *
     * @see PublicKeyECC
     */
    public PublicKeyECC getPublicKey(String id) {

        for (int i = 0; i < keyRingPublic.size(); i++) {
            PublicKeyECC key = keyRingPublic.get(i);
            if (key.keyId.equals(id)) {
                return key;
            }
        }

        return null;
    }

    /**
     * Check if key(s) already exist in the key ring with the same id
     *
     * @param keyId the id of key(s) being checked
     * @return true if exists, false if not
     *
     * @see PublicKeyECC
     * @see PrivateKeyECC
     */
    public Boolean keyExist(String keyId) {
        PrivateKeyECC privateKey = getPrivateKey(keyId);
        PublicKeyECC publicKey = getPublicKey(keyId);

        if (privateKey == null && publicKey == null) {
            return false;
        }

        return true;
    }

    /**
     * Output all id of keys in the private and public key ring respectively.
     *
     * @see PublicKeyECC
     * @see PrivateKeyECC
     */
    public void listAllKeys() {
        System.out.println("private key(s):");
        int size = keyRingPrivate.size();
        for (int i = 0; i < size; i++) {
            System.out.println(keyRingPrivate.get(i).keyId);
        }

        System.out.println("public key(s):");
        size = keyRingPublic.size();
        for (int i = 0; i < size; i++) {
            System.out.println(keyRingPublic.get(i).keyId);
        }
    }
}
