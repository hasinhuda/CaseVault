package com.casevault.service;

/** Service-only abstraction for encrypted evidence storage. */
public interface EvidenceStore {
    void encryptAndStore(String storedName, byte[] plaintext, byte[] associatedData);

    byte[] decryptAndRetrieve(String storedName, byte[] associatedData);

    void discardQuietly(String storedName);

    /** True when the storage directory exists (or can be created) and is writable. Never throws, writes nothing. */
    default boolean isWritable() {
        return false;
    }
}
