package ecc.entities;

import java.io.IOException;

/**
 * KeyPairECC is a class which is only used when generated new key pairs. It
 * assures the pair of keys created is consistent. After the pair of keys is
 * added to key ring, this object is not used anymore.
 * 
 * @see PrivateKeyECC
 * @see PublicKeyECC
 * @see KeyRingECC
 */
public class KeyPairECC {

	final public String keyId;
	final public PublicKeyECC publicKey;
	final public PrivateKeyECC privateKey;

	/**
	 * Class constructor specifying parameters. First create a PrivateKeyECC,
	 * and then use its key value to create a public key.
	 * 
	 * @param id
	 *            the user specified key id
	 * @param c
	 *            the elliptic curve using
	 * @param pwd
	 *            the user specified password for ECC private key
	 * @throws IOException 
	 * 
	 * @see PrivateKeyECC
	 * @see PublicKeyECC
	 */
	public KeyPairECC(String id, Curve c, String pwd) throws IOException {
		this.keyId = id;
		this.privateKey = new PrivateKeyECC(id, c, pwd);
		this.publicKey = new PublicKeyECC(id, c,
				this.privateKey.getKeyValue(pwd));
	}

}
