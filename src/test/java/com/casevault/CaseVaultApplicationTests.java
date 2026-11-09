package com.casevault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class CaseVaultApplicationTests {

    @Test
    @DisplayName("TEST-BASE-001: Application context loads successfully")
    void contextLoads() {
        assertTrue(true, "Application context loaded without errors");
    }
}
