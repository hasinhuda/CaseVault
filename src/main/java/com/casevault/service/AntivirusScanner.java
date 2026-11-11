package com.casevault.service;

/**
 * Antivirus scanner abstraction for uploaded evidence artifacts (Hard Rule 1, SR-11).
 * Implementations inspect uploaded binary content prior to persistence and encryption.
 */
public interface AntivirusScanner {

    ScanResult scan(byte[] fileContent, String filename);

    record ScanResult(boolean isClean, String signatureName, String details) {

        public static ScanResult clean() {
            return new ScanResult(true, "CLEAN", "No threats detected");
        }

        public static ScanResult infected(String signatureName, String details) {
            return new ScanResult(false, signatureName, details);
        }
    }
}

