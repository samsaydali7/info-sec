package samsaydali.infosec.hash;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HashManagerTest {

    @Test
    void createSHA2Hash() {
        assertAll(() -> {
            HashManager manager = new HashManager();
            String input1 = "String to hash";
            String input2 = "Another string to hash";

            byte[] salt = manager.generateRandomSalt();

            byte[] input1hash = manager.createSHA2Hash(input1, salt);
            byte[] input2hash = manager.createSHA2Hash(input2, salt);

            assertTrue(manager.verify(input1, input1hash, salt));
            assertTrue(manager.verify(input2, input2hash, salt));
            assertFalse(manager.verify(input1, input2hash, salt));
            assertFalse(manager.verify(input2, input1hash, salt));
        });
    }
}