package com.casevault.service;

import com.casevault.exception.BadRequestException;
import com.casevault.exception.ResourceNotFoundException;
import com.google.crypto.tink.Aead;
import com.google.crypto.tink.CleartextKeysetHandle;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.JsonKeysetReader;
import com.google.crypto.tink.JsonKeysetWriter;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.AeadKeyTemplates;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.util.Objects;
import java.util.Set;

/** Tink AEAD filesystem boundary. Stored names are generated UUIDs, never user input. */
@Service
public final class EvidenceStorageService implements EvidenceStore {
    private final Path storageDir;
    private final Path keysetPath;
    private final Aead aead;

    public EvidenceStorageService(@Value("${casevault.storage.evidence-dir:.local-data/evidence}") String evidenceDir,
                                  @Value("${casevault.storage.keyset-path:.local-data/keys/evidence-keyset.json}") String keyset) {
        try {
            AeadConfig.register();
            this.storageDir = Path.of(evidenceDir).toAbsolutePath().normalize();
            this.keysetPath = Path.of(keyset).toAbsolutePath().normalize();
            Path parent = this.keysetPath.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            this.aead = Objects.requireNonNull(loadOrCreateKeyset(), "aead not initialised");
        } catch (IOException | GeneralSecurityException exception) {
            throw new IllegalArgumentException("Evidence encryption configuration is unavailable", exception);
        }
    }

    @Override
    public void encryptAndStore(String storedName, byte[] plaintext, byte[] associatedData) {
        Path target = resolveStoredPath(storedName);
        try {
            Files.createDirectories(storageDir);
            byte[] ciphertext = aead().encrypt(plaintext, associatedData);
            Files.write(target, ciphertext, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (IOException | GeneralSecurityException exception) {
            throw new BadRequestException("Evidence file could not be stored.");
        }
    }

    @Override
    public byte[] decryptAndRetrieve(String storedName, byte[] associatedData) {
        Path target = resolveStoredPath(storedName);
        if (!Files.exists(target)) {
            throw new ResourceNotFoundException("Evidence file not found.");
        }
        try {
            return aead().decrypt(Files.readAllBytes(target), associatedData);
        } catch (GeneralSecurityException | IOException exception) {
            throw new ResourceNotFoundException("Evidence decryption failed.");
        }
    }

    @Override
    public void discardQuietly(String storedName) {
        try {
            Files.deleteIfExists(resolveStoredPath(storedName));
        } catch (IOException | RuntimeException ignored) {
            // A later operational recovery process must handle failed cleanup; never expose paths to clients.
        }
    }

    public void write(String storedName, byte[] plaintext, byte[] associatedData) {
        encryptAndStore(storedName, plaintext, associatedData);
    }

    public byte[] read(String storedName, byte[] associatedData) {
        return decryptAndRetrieve(storedName, associatedData);
    }

    public void deleteQuietly(String storedName) {
        discardQuietly(storedName);
    }

    private Aead loadOrCreateKeyset() throws IOException, GeneralSecurityException {
        KeysetHandle handle;
        if (Files.exists(keysetPath)) {
            handle = CleartextKeysetHandle.read(JsonKeysetReader.withPath(keysetPath));
        } else {
            handle = KeysetHandle.generateNew(AeadKeyTemplates.AES256_GCM);
            CleartextKeysetHandle.write(handle, JsonKeysetWriter.withPath(keysetPath));
            restrictPermissions(keysetPath);
        }
        return handle.getPrimitive(Aead.class);
    }

    private Aead aead() {
        return Objects.requireNonNull(aead, "aead not initialised");
    }

    private Path resolveStoredPath(String storedName) {
        if (storedName == null || !storedName.matches("[0-9a-fA-F-]{36}")) {
            throw new IllegalArgumentException("Invalid evidence storage name");
        }
        Path resolved = storageDir.resolve(storedName).normalize();
        if (!resolved.startsWith(storageDir)) {
            throw new IllegalArgumentException("Invalid evidence storage path");
        }
        return resolved;
    }

    private void restrictPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows ACLs and non-POSIX stores may not support this API.
        }
    }
}
