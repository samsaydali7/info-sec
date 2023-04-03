package samsaydali.infosec.hash;

import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class HashManager {

    private static final String SHA2_ALGORITHM = "SHA-256";
    private final String algorithm;

    public HashManager() {
        this.algorithm = SHA2_ALGORITHM;
    }

    public HashManager(String algorithm) {
        this.algorithm = algorithm;
    }

    public byte[] generateRandomSalt(){
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);
        return salt;
    }


    public byte[] createSHA2Hash(String input, byte[] salt) throws Exception{
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        byteStream.write(salt);
        byteStream.write(input.getBytes());
        byte[] valueToHash = byteStream.toByteArray();

        MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        return messageDigest.digest(valueToHash);
    }

    public boolean verify(String input, byte[] hash, byte[] salt) throws Exception {
        byte[] digest = createSHA2Hash(input, salt);
        String digestChecksum = DatatypeConverter.printHexBinary(digest).toUpperCase();
        String hashChecksum = DatatypeConverter.printHexBinary(hash).toUpperCase();
        return digestChecksum.equals(hashChecksum);
    }

}
