package samsaydali.infosec.rsa;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;

class RSAManagerTest {

    RSAManager manager = new RSAManager();

    @Test
    void encryptPublicAndDecryptPrivate() {
        assertAll(() -> {
            KeyPair pair = manager.generateRSAKeyPair();
            String message = "THE_MESSAGE";
            String encMessage = manager.encrypt(message, pair.getPublic());
            String decMessage = manager.decrypt(encMessage, pair.getPrivate());
            assertEquals(message, decMessage);
        });

    }

    @Test
    void encryptPrivateAndDecryptPublic() {
        assertAll(() -> {
            KeyPair pair = manager.generateRSAKeyPair();
            String message = "THE_MESSAGE_2";
            String encMessage = manager.encrypt(message, pair.getPrivate());
            String decMessage = manager.decrypt(encMessage, pair.getPublic());
            assertEquals(message, decMessage);
        });
    }
}