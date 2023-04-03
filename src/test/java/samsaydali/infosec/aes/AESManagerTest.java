package samsaydali.infosec.aes;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import samsaydali.infosec.aes.AESManager;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AESManagerTest {

    String key = "THE KEY";
    String plainText = "THE PLAIN TEXT";

    @Test
    @DisplayName("Decrypting an encrypted AES string, encrypted with the same decryption key, should return the original plan text")
    public void testAESManager() throws Exception {

        String encrypted = AESManager.encrypt(plainText, key);

        String decrypted = AESManager.decrypt(encrypted, key);

        assertEquals(plainText, decrypted);
    }
}