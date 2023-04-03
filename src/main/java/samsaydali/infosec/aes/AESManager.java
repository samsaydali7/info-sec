package samsaydali.infosec.aes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;

import static samsaydali.infosec.utils.Base64Utils.b64StringToBytes;
import static samsaydali.infosec.utils.Base64Utils.bytesToB64String;

public class AESManager {

    private static IvParameterSpec createIV() {
        byte[] iv = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        return new IvParameterSpec(iv);
    }

    private static SecretKeySpec createSecretKeySpec(String secretKey) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        String salt = "THE_SALT";
        KeySpec spec = new PBEKeySpec(secretKey.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    public static String encrypt(String strToEncrypt, String key) throws Exception {

        // secret key
        SecretKeySpec secretKeySpec = createSecretKeySpec(key);

        // iv Parameter
        IvParameterSpec ivSpec = createIV();

        //Cipher ENCRYPT_MODE
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivSpec);

        byte[] bytes = strToEncrypt.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = cipher.doFinal(bytes);
        return bytesToB64String(encrypted);
    }

    public static String decrypt(String strToDecrypt, String key) throws Exception {

        // secret key
        SecretKeySpec secretKeySpec = createSecretKeySpec(key);

        //iv Parameter
        IvParameterSpec ivSpec = createIV();

        //Cipher DECRYPT_MODE
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivSpec);
        byte[] encrypted = b64StringToBytes(strToDecrypt);
        byte[] bytes = cipher.doFinal(encrypted);
        return new String(bytes);
    }


}
