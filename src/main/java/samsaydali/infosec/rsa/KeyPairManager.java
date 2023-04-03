package samsaydali.infosec.rsa;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;

import static samsaydali.infosec.utils.Base64Utils.b64StringToBytes;

public class KeyPairManager {

    private static final String RSA = "RSA";
    private static final SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");

    private final String algorithm;

    public KeyPairManager(String algorithm) {
        this.algorithm = algorithm;
    }

    public KeyPairManager() {
        this.algorithm = RSA;
    }

    public KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        SecureRandom secureRandom = new SecureRandom();
        java.security.KeyPairGenerator keyPairGenerator = java.security.KeyPairGenerator.getInstance(algorithm);
        keyPairGenerator.initialize(4096, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public PublicKey transformPublic(String publicKeyString) throws Exception {
        byte[] publicBytes = b64StringToBytes(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePublic(keySpec);
    }

    public PrivateKey transformPrivate(String privateKeyString) throws Exception {
        byte[] privateBytes = b64StringToBytes(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
        return keyFactory.generatePrivate(keySpec);
    }

}
