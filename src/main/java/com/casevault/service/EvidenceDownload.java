package com.casevault.service;

/** In-memory plaintext returned only after service-layer authorization and integrity verification. */
public record EvidenceDownload(String originalName, byte[] content) {
    public EvidenceDownload {
        content = content.clone();
    }

    @Override
    public byte[] content() {
        return content.clone();
    }
}
