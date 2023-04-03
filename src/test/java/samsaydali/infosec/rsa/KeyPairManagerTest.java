package samsaydali.infosec.rsa;

import org.junit.jupiter.api.Test;
import samsaydali.infosec.utils.Base64Utils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class KeyPairManagerTest {

    KeyPairManager generator = new KeyPairManager();

    @Test
    void generateRSAKeyPair() {
        assertAll(() -> {
            KeyPair pair = generator.generateRSAKeyPair();
            String pbkStr = Base64Utils.bytesToB64String(pair.getPublic().getEncoded());
            String prkStr = Base64Utils.bytesToB64String(pair.getPrivate().getEncoded());

            System.out.printf("Public: %s\nPrivate: %s\n", pbkStr, prkStr);
        });
    }

    @Test
    void transformPublic() {

        assertAll(() -> {
            KeyPair pair = generator.generateRSAKeyPair();
            PublicKey publicKey = pair.getPublic();
            String pbKeyStr = Base64Utils.bytesToB64String(publicKey.getEncoded());
            PublicKey publicKey2 = generator.transformPublic(pbKeyStr);
            assertEquals(publicKey, publicKey2);
        });
    }

    @Test
    void transformPrivate() {
        assertAll(() -> {
            KeyPair pair = generator.generateRSAKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            String prKeyStr = Base64Utils.bytesToB64String(privateKey.getEncoded());
            PrivateKey privateKey2 = generator.transformPrivate(prKeyStr);
            assertEquals(privateKey, privateKey2);
        });
    }
}