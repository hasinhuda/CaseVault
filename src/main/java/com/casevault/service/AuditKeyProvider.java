package com.casevault.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;

/**
 * Supplies the HMAC-SHA256 key of the audit chain. The key is generated lazily on first use (never at startup, so
 * unrelated contexts do not create files), stored Base64-encoded in a git-ignored location and never logged.
 */
@Component
public class AuditKeyProvider {

    private static final int KEY_BYTES = 32;
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path keyPath;
    private volatile SecretKey cachedKey;

    public AuditKeyProvider(@Value("${casevault.audit.key-path:.local-data/keys/audit-hmac.key}") String keyPath) {
        this.keyPath = Path.of(keyPath).toAbsolutePath().normalize();
    }

    /** Returns the audit HMAC key, creating the key file on first use. */
    public SecretKey key() {
        SecretKey key = cachedKey;
        if (key == null) {
            synchronized (this) {
                key = cachedKey;
                if (key == null) {
                    key = loadOrCreate();
                    cachedKey = key;
                }
            }
        }
        return key;
    }

    private SecretKey loadOrCreate() {
        try {
            if (!Files.exists(keyPath)) {
                create();
            }
            byte[] decoded = Base64.getDecoder().decode(Files.readString(keyPath, StandardCharsets.US_ASCII).trim());
            if (decoded.length < KEY_BYTES) {
                throw new IllegalStateException("Audit key file is invalid");
            }
            return new SecretKeySpec(decoded, HMAC_ALGORITHM);
        } catch (IOException e) {
            throw new UncheckedIOException("Audit key could not be read or created", e);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Audit key file is invalid");
        }
    }

    private void create() throws IOException {
        byte[] raw = new byte[KEY_BYTES];
        RANDOM.nextBytes(raw);
        String encoded = Base64.getEncoder().encodeToString(raw);
        Path parent = keyPath.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        try {
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                Files.createFile(keyPath, PosixFilePermissions.asFileAttribute(
                        Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            } else {
                Files.createFile(keyPath);
                restrictNonPosix();
            }
            Files.writeString(keyPath, encoded, StandardCharsets.US_ASCII);
        } catch (FileAlreadyExistsException concurrentCreator) {
            // Another instance created the key first; it is read by the caller.
        }
    }

    /** Best effort owner-only access where POSIX permissions do not exist (for example Windows). */
    private boolean restrictNonPosix() {
        java.io.File file = keyPath.toFile();
        boolean readable = file.setReadable(false, false) && file.setReadable(true, true);
        boolean writable = file.setWritable(false, false) && file.setWritable(true, true);
        // Not fatal when false: the directory is git-ignored; documented as a residual risk in ADR 0005.
        return readable && writable;
    }
}
