package com.casevault.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Synthetic Antivirus Scanner Stub.
 *
 * Hard Rule 1 & SR-11 Compliance:
 * CaseVault strictly operates on synthetic test data. Real malware and EICAR test strings
 * are strictly prohibited anywhere in the repository, tests, or runtime environment.
 * Live integration with third-party antivirus engines is replaced with this documented STUB
 * that always returns CLEAN.
 */
@Component
public class StubAntivirusScanner implements AntivirusScanner {

    private static final Logger logger = LoggerFactory.getLogger(StubAntivirusScanner.class);

    @Override
    public ScanResult scan(byte[] fileContent, String filename) {
        // Documented STUB: Always returns CLEAN per Hard Rule 1 and SR-11.
        // Avoid logging untrusted filename directly to prevent CRLF injection in logs.
        logger.debug("Antivirus Stub: Synthetic scan executed successfully, result=CLEAN");
        return ScanResult.clean();
    }
}
