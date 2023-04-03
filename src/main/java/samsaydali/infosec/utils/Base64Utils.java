package samsaydali.infosec.utils;

import java.util.Base64;

public class Base64Utils {

    public static String bytesToB64String(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] b64StringToBytes(String string) {
        return Base64.getDecoder().decode(string);
    }

}
