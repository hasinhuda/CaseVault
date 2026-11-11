package com.casevault.evidence;

import com.casevault.exception.ResourceNotFoundException;
import com.casevault.service.EvidenceStorageService;
import com.casevault.service.EvidenceValidator;
import com.casevault.service.StubAntivirusScanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EvidenceStorageServiceTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void encryptionStoresCiphertextAndRoundTripsWithAssociatedData() throws Exception {
        Path storage = temporaryDirectory.resolve("evidence");
        EvidenceStorageService service = storageService(storage);
        String storedName = UUID.randomUUID().toString();
        byte[] plaintext = "synthetic confidential evidence".getBytes(StandardCharsets.UTF_8);
        byte[] aad = "case-a:evidence-a".getBytes(StandardCharsets.UTF_8);

        service.write(storedName, plaintext, aad);

        Path ciphertextPath = storage.resolve(storedName);
        byte[] ciphertext = Files.readAllBytes(ciphertextPath);
        assertFalse(new String(ciphertext, StandardCharsets.ISO_8859_1).contains("synthetic confidential evidence"),
                "SEC-EVID-ENC-01: plaintext must not be present on disk");
        assertFalse(ciphertextPath.toString().contains("report.pdf"));
        assertTrue(storedName.matches("[0-9a-f-]{36}"));
        assertArrayEquals(plaintext, service.read(storedName, aad));
        assertTrue(EvidenceValidator.computeSha256Hex(plaintext).matches("[0-9a-f]{64}"));
    }

    @Test
    void tamperingAndCiphertextSwappingAreDetected() throws Exception {
        Path storage = temporaryDirectory.resolve("evidence");
        EvidenceStorageService service = storageService(storage);
        String first = UUID.randomUUID().toString();
        String second = UUID.randomUUID().toString();
        byte[] firstAad = "case-a:evidence-a".getBytes(StandardCharsets.UTF_8);
        byte[] secondAad = "case-a:evidence-b".getBytes(StandardCharsets.UTF_8);
        service.write(first, "first synthetic payload".getBytes(StandardCharsets.UTF_8), firstAad);
        service.write(second, "second synthetic payload".getBytes(StandardCharsets.UTF_8), secondAad);

        byte[] tampered = Files.readAllBytes(storage.resolve(first));
        tampered[tampered.length - 1] ^= 1;
        Files.write(storage.resolve(first), tampered);
        assertThrows(ResourceNotFoundException.class, () -> service.read(first, firstAad),
                "SEC-EVID-TAMPER-01: AEAD tag failure must be safe");

        Files.delete(storage.resolve(first));
        service.write(first, "first synthetic payload".getBytes(StandardCharsets.UTF_8), firstAad);
        Files.move(storage.resolve(second), storage.resolve(first), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        assertThrows(ResourceNotFoundException.class, () -> service.read(first, firstAad),
                "SEC-EVID-TAMPER-02: ciphertext is bound to case/evidence associated data");
    }

    @Test
    void traversalInputIsRejectedBeforeItCanBecomeAStoragePath() {
        EvidenceValidator validator = new EvidenceValidator(new StubAntivirusScanner());
        byte[] pdf = "%PDF-1.5\n%%EOF".getBytes(StandardCharsets.US_ASCII);
        assertThrows(RuntimeException.class, () -> validator.validate(pdf, "../../evil.pdf"));
        assertThrows(RuntimeException.class, () -> validator.validate(pdf, "..\\..\\evil.pdf"));
        assertDoesNotThrow(() -> storageService(temporaryDirectory.resolve("evidence")));
    }

    private EvidenceStorageService storageService(Path storage) {
        return new EvidenceStorageService(storage.toString(), temporaryDirectory.resolve("keys/evidence-keyset.json").toString());
    }
}
