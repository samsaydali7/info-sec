package samsaydali.infosec.rsa;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyPair;

import static samsaydali.infosec.utils.Base64Utils.b64StringToBytes;
import static samsaydali.infosec.utils.Base64Utils.bytesToB64String;


public class RSAManager {

    private static final String RSA = "RSA";
    private static final String ALGORITHM = "RSA/ECB/PKCS1Padding";

    private final String algorithm;

    public RSAManager() {
        this.algorithm = ALGORITHM;
    }

    public RSAManager(String algorithm) {
        this.algorithm = algorithm;
    }

    public KeyPair generateRSAKeyPair() throws Exception {
        KeyPairManager keyPairGenerator = new KeyPairManager(RSA);
        return keyPairGenerator.generateRSAKeyPair();

    }

    public String encrypt(String plainText, Key key) throws Exception{
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = plainText.getBytes();
        byte[] encryptedBytes = cipher.doFinal(bytes);
        return bytesToB64String(encryptedBytes);
    }

    public String decrypt(String cipherText, Key key) throws Exception{
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] encryptedBytes = b64StringToBytes(cipherText);
        byte[] bytes = cipher.doFinal(encryptedBytes);
        return new String(bytes);
    }
}
