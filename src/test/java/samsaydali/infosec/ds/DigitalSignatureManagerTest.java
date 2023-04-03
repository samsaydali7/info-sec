package samsaydali.infosec.ds;

import org.junit.jupiter.api.Test;
import samsaydali.infosec.rsa.KeyPairManager;

import java.security.KeyPair;

import static org.junit.jupiter.api.Assertions.*;

class DigitalSignatureManagerTest {

    @Test
    void createAndVerifyDigitalSignature() {
        assertAll(() -> {

            KeyPairManager keyPairManager = new KeyPairManager();
            KeyPair pair = keyPairManager.generateRSAKeyPair();

            DigitalSignatureManager manager = new DigitalSignatureManager();
            String message = "The message must be signed";

            String signature = manager.createDigitalSignature(message, pair.getPrivate());

            assertTrue(manager.verifyDigitalSignature(message, signature, pair.getPublic()));
        });
    }
}