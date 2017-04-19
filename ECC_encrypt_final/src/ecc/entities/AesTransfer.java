package ecc.entities;

import java.io.Serializable;

public class AesTransfer implements Serializable {

    private byte[] pwBlockLength;
    private byte[] passwordCipher;
    private byte[] fileCipherText;

    public byte[] getPwBlockLength() {
        return pwBlockLength;
    }

    public byte[] getPasswordCipher() {
        return passwordCipher;
    }

    public byte[] getFileCipherText() {
        return fileCipherText;
    }

    public void setPwBlockLength(byte[] passwordLength) {
        this.pwBlockLength = passwordLength;
    }

    public void setPasswordCipher(byte[] passwordCipher) {
        this.passwordCipher = passwordCipher;
    }

    public void setFileCipherText(byte[] fileCipherText) {
        this.fileCipherText = fileCipherText;
    }

}
