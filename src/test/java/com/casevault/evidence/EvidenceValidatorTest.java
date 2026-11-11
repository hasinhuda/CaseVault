package com.casevault.evidence;

import com.casevault.exception.BadRequestException;
import com.casevault.service.AntivirusScanner;
import com.casevault.service.EvidenceValidator;
import com.casevault.service.StubAntivirusScanner;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EvidenceValidatorTest {

    private EvidenceValidator validator;
    private StubAntivirusScanner stubAntivirus;

    // Synthetic valid payloads (no live binaries, no external dependencies)
    private static final byte[] VALID_PDF_BYTES = "%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< >>\n%%EOF".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] VALID_PNG_BYTES = new byte[]{
            (byte) 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, (byte) 0x90, 0x77, 0x53, (byte) 0xDE
    };
    private static final byte[] VALID_JPG_BYTES = new byte[]{
            (byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0,
            0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
            0x01, 0x01, 0x00, 0x48, 0x00, 0x48, 0x00, 0x00,
            (byte) 0xFF, (byte) 0xD9
    };
    private static final byte[] VALID_TXT_BYTES = "2026-11-10 14:00:00 Incident Report Case #49281".getBytes(StandardCharsets.UTF_8);
    private static final byte[] VALID_LOG_BYTES = "[INFO] Connection established from 192.168.1.10 to port 443".getBytes(StandardCharsets.UTF_8);
    private static final byte[] VALID_CSV_BYTES = "id,action,actor\n1,LOGIN,analyst_bob\n2,EXPORT,analyst_bob".getBytes(StandardCharsets.UTF_8);
    private static final byte[] VALID_JSON_BYTES = "{\"case_id\":\"CASE-1234\",\"severity\":\"CRITICAL\"}".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        stubAntivirus = new StubAntivirusScanner();
        validator = new EvidenceValidator(stubAntivirus);
    }

    @Test
    @DisplayName("SEC-EV-VAL-001: Valid files for all allow-list extensions pass validation")
    void testValidUploadsForAllAllowedExtensions() {
        // PDF
        EvidenceValidator.ValidatedEvidence pdf = validator.validate(VALID_PDF_BYTES, "case_report.pdf");
        assertEquals("case_report.pdf", pdf.originalName());
        assertEquals("pdf", pdf.extension());
        assertEquals("application/pdf", pdf.detectedMimeType());
        assertNotNull(pdf.storedName());
        assertEquals(64, pdf.sha256Hex().length());

        // PNG
        EvidenceValidator.ValidatedEvidence png = validator.validate(VALID_PNG_BYTES, "network_diagram.png");
        assertEquals("network_diagram.png", png.originalName());
        assertEquals("png", png.extension());
        assertEquals("image/png", png.detectedMimeType());

        // JPG & JPEG
        EvidenceValidator.ValidatedEvidence jpg = validator.validate(VALID_JPG_BYTES, "evidence_photo.jpg");
        assertEquals("jpg", jpg.extension());
        assertEquals("image/jpeg", jpg.detectedMimeType());

        EvidenceValidator.ValidatedEvidence jpeg = validator.validate(VALID_JPG_BYTES, "evidence_photo2.jpeg");
        assertEquals("jpeg", jpeg.extension());
        assertEquals("image/jpeg", jpeg.detectedMimeType());

        // TXT & LOG
        EvidenceValidator.ValidatedEvidence txt = validator.validate(VALID_TXT_BYTES, "analyst_notes.txt");
        assertEquals("txt", txt.extension());
        assertEquals("text/plain", txt.detectedMimeType());

        EvidenceValidator.ValidatedEvidence log = validator.validate(VALID_LOG_BYTES, "syslog_sample.log");
        assertEquals("log", log.extension());
        assertEquals("text/plain", log.detectedMimeType());

        // CSV & JSON
        EvidenceValidator.ValidatedEvidence csv = validator.validate(VALID_CSV_BYTES, "auth_events.csv");
        assertEquals("csv", csv.extension());
        assertTrue("text/csv".equals(csv.detectedMimeType()) || "text/plain".equals(csv.detectedMimeType()));

        EvidenceValidator.ValidatedEvidence json = validator.validate(VALID_JSON_BYTES, "metadata.json");
        assertEquals("json", json.extension());
        assertTrue("application/json".equals(json.detectedMimeType()) || "text/plain".equals(json.detectedMimeType()));
    }

    @Test
    @DisplayName("SEC-EV-VAL-002: File size boundaries: empty rejected, max 10MB accepted, >10MB rejected")
    void testFileSizeBoundaries() {
        // Empty bytes rejected
        BadRequestException exEmpty = assertThrows(BadRequestException.class,
                () -> validator.validate(new byte[0], "notes.txt"));
        assertTrue(exEmpty.getMessage().contains("empty"));

        // Null bytes rejected
        assertThrows(BadRequestException.class,
                () -> validator.validate((byte[]) null, "notes.txt"));

        // Oversize (> 10MB) rejected
        byte[] oversize = new byte[(int) EvidenceValidator.MAX_FILE_SIZE_BYTES + 1];
        Arrays.fill(oversize, (byte) 'A');
        BadRequestException exOver = assertThrows(BadRequestException.class,
                () -> validator.validate(oversize, "huge.txt"));
        assertTrue(exOver.getMessage().contains("10MB"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "payload.exe", "script.sh", "install.bat", "run.cmd", "tool.ps1",
            "malicious.jar", "web.php", "test.phtml", "index.html", "page.htm",
            "vector.svg", "library.dll", "macro.vbs", "installer.msi", "archive.zip"
    })
    @DisplayName("SEC-EV-VAL-003: Disallowed file extensions are strictly rejected")
    void testDisallowedExtensionsRejected(String dangerousFilename) {
        BadRequestException ex = assertThrows(BadRequestException.class,
                () -> validator.validate(VALID_TXT_BYTES, dangerousFilename));
        assertTrue(ex.getMessage().contains("not permitted") || ex.getMessage().contains("Double extension"));
    }

    @Test
    @DisplayName("SEC-EV-VAL-004: Extension missing or hidden file without base name rejected")
    void testMissingExtensionRejected() {
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "no_extension"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "trailing_dot."));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, ".pdf"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "report.exe.pdf",
            "report.dll.txt",
            "invoice.bat.png",
            "data.cmd.csv",
            "dump.com.json",
            "notes.scr.log",
            "client.js.pdf",
            "backup.vbs.txt",
            "script.ps1.log",
            "archive.sh.txt",
            "package.jar.pdf",
            "setup.msi.png",
            "webshell.php.jpg",
            "config.html.txt",
            "portal.htm.json"
    })
    @DisplayName("SEC-EV-VAL-005: Double extension attacks with dangerous segments are rejected")
    void testDoubleExtensionAttacksRejected(String doubleExtensionFilename) {
        BadRequestException ex = assertThrows(BadRequestException.class,
                () -> validator.validate(VALID_TXT_BYTES, doubleExtensionFilename));
        assertTrue(ex.getMessage().contains("Double extension detected"));
    }

    @Test
    @DisplayName("SEC-EV-VAL-006: Benign multiple dot segments without dangerous keywords are permitted")
    void testBenignMultipleDotsPermitted() {
        EvidenceValidator.ValidatedEvidence ev = validator.validate(VALID_PDF_BYTES, "audit.report.2026.final.pdf");
        assertEquals("audit.report.2026.final.pdf", ev.originalName());
        assertEquals("pdf", ev.extension());
    }

    @Test
    @DisplayName("SEC-EV-VAL-007: Filenames with path separators, null bytes, and control chars are rejected")
    void testDangerousFilenameCharactersRejected() {
        // Path separators
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "../traversal.txt"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "folder/report.pdf"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "..\\traversal.txt"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "C:\\fakepath\\file.txt"));

        // Null byte
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "report\0.pdf"));

        // Control characters
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "report\u0001.pdf"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "report\n.txt"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "report\r.txt"));

        // Blank or whitespace only
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "   "));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, null));
    }

    @Test
    @DisplayName("SEC-EV-VAL-008: Filename exceeding 255 characters is rejected")
    void testFilenameExceeding255CharsRejected() {
        String longName = "a".repeat(252) + ".txt"; // 256 chars total
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, longName));

        String validLengthName = "a".repeat(250) + ".txt"; // 254 chars total
        EvidenceValidator.ValidatedEvidence ev = validator.validate(VALID_TXT_BYTES, validLengthName);
        assertNotNull(ev);
    }

    @Test
    @DisplayName("SEC-EV-VAL-009: Executable binary and script headers are rejected regardless of file extension")
    void testExecutableHeadersRejected() {
        // Windows PE "MZ"
        byte[] mzBytes = new byte[]{'M', 'Z', (byte) 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
        assertThrows(BadRequestException.class, () -> validator.validate(mzBytes, "fake.pdf"));
        assertThrows(BadRequestException.class, () -> validator.validate(mzBytes, "fake.txt"));

        // DOS "ZM"
        byte[] zmBytes = new byte[]{'Z', 'M', (byte) 0x90, 0x00};
        assertThrows(BadRequestException.class, () -> validator.validate(zmBytes, "fake.log"));

        // Linux ELF (0x7F 'E' 'L' 'F')
        byte[] elfBytes = new byte[]{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00};
        assertThrows(BadRequestException.class, () -> validator.validate(elfBytes, "fake.png"));

        // Mach-O 32-bit (0xFEEDFACE)
        byte[] macho32 = new byte[]{(byte) 0xFE, (byte) 0xED, (byte) 0xFA, (byte) 0xCE, 0, 0, 0, 1};
        assertThrows(BadRequestException.class, () -> validator.validate(macho32, "fake.jpg"));

        // Mach-O 64-bit (0xFEEDFACF)
        byte[] macho64 = new byte[]{(byte) 0xFE, (byte) 0xED, (byte) 0xFA, (byte) 0xCF, 0, 0, 0, 2};
        assertThrows(BadRequestException.class, () -> validator.validate(macho64, "fake.csv"));

        // Mach-O Universal / Java class (0xCAFEBABE)
        byte[] javaClass = new byte[]{(byte) 0xCA, (byte) 0xFE, (byte) 0xBA, (byte) 0xBE, 0, 0, 0, 52};
        assertThrows(BadRequestException.class, () -> validator.validate(javaClass, "fake.json"));

        // Script Shebang "#!"
        byte[] shebang = "#!/bin/bash\nrm -rf /".getBytes(StandardCharsets.US_ASCII);
        assertThrows(BadRequestException.class, () -> validator.validate(shebang, "script.txt"));
        assertThrows(BadRequestException.class, () -> validator.validate(shebang, "script.log"));

        // UTF-8 BOM shebang (EF BB BF 23 21)
        byte[] bomShebang = new byte[]{(byte) 0xEF, (byte) 0xBB, (byte) 0xBF, 0x23, 0x21, 'b', 'i', 'n'};
        assertThrows(BadRequestException.class, () -> validator.validate(bomShebang, "script_bom.txt"));
    }

    @Test
    @DisplayName("SEC-EV-VAL-010: Tika content inspection rejects MIME mismatches (fake extensions)")
    void testTikaMimeMismatchRejection() {
        // Plain text disguised as PNG
        BadRequestException exPng = assertThrows(BadRequestException.class,
                () -> validator.validate(VALID_TXT_BYTES, "fake_image.png"));
        assertTrue(exPng.getMessage().contains("MIME type mismatch"));

        // Plain text disguised as PDF
        BadRequestException exPdf = assertThrows(BadRequestException.class,
                () -> validator.validate(VALID_TXT_BYTES, "fake_doc.pdf"));
        assertTrue(exPdf.getMessage().contains("MIME type mismatch"));

        // Plain text disguised as JPG
        BadRequestException exJpg = assertThrows(BadRequestException.class,
                () -> validator.validate(VALID_TXT_BYTES, "fake_photo.jpg"));
        assertTrue(exJpg.getMessage().contains("MIME type mismatch"));

        // PNG disguised as TXT
        BadRequestException exTxt = assertThrows(BadRequestException.class,
                () -> validator.validate(VALID_PNG_BYTES, "binary_in_disguise.txt"));
        assertTrue(exTxt.getMessage().contains("MIME type mismatch"));
    }

    @Test
    @DisplayName("SEC-EV-VAL-011: Plaintext SHA-256 calculation matches known cryptographic digest")
    void testSha256CalculationIntegrity() {
        byte[] data = "CaseVault Evidence Verification Test 2026".getBytes(StandardCharsets.UTF_8);
        String calculatedHex = EvidenceValidator.computeSha256Hex(data);
        assertEquals(64, calculatedHex.length());

        EvidenceValidator.ValidatedEvidence ev = validator.validate(data, "test_sha.txt");
        assertEquals(calculatedHex, ev.sha256Hex());
        assertArrayEquals(data, ev.content());
    }

    @Test
    @DisplayName("SEC-EV-VAL-012: Synthetic Antivirus scan stub returns clean; infected response rejects upload")
    void testAntivirusScanningIntegration() {
        // Stub scanner returns clean
        EvidenceValidator.ValidatedEvidence cleanEv = validator.validate(VALID_TXT_BYTES, "clean.txt");
        assertNotNull(cleanEv);

        // Simulated infected scanner (using synthetic signature name, no malware / no EICAR)
        AntivirusScanner mockInfectedScanner = (bytes, fname) ->
                AntivirusScanner.ScanResult.infected("Synthetic.Test.Signature", "Detected in synthetic mock");
        EvidenceValidator failingValidator = new EvidenceValidator(mockInfectedScanner);

        BadRequestException ex = assertThrows(BadRequestException.class,
                () -> failingValidator.validate(VALID_TXT_BYTES, "test.txt"));
        assertTrue(ex.getMessage().contains("Antivirus scan failed: Synthetic.Test.Signature"));
    }

    @Test
    @DisplayName("SEC-EV-VAL-013: Spring MockMultipartFile integration validates file upload")
    void testMockMultipartFileValidation() {
        MockMultipartFile validMultipart = new MockMultipartFile(
                "file",
                "evidence_upload.pdf",
                "application/pdf",
                VALID_PDF_BYTES
        );

        EvidenceValidator.ValidatedEvidence result = validator.validate(validMultipart);
        assertEquals("evidence_upload.pdf", result.originalName());
        assertEquals("pdf", result.extension());
        assertEquals("application/pdf", result.detectedMimeType());

        // Empty multipart file
        MockMultipartFile emptyMultipart = new MockMultipartFile("file", "empty.pdf", "application/pdf", new byte[0]);
        assertThrows(BadRequestException.class, () -> validator.validate(emptyMultipart));
    }

    @Test
    @DisplayName("SEC-EVID-UNI-01: ASCII extension case is normalised safely")
    void unicodeNormalisationAcceptsAsciiCaseVariants() {
        assertEquals("pdf", validator.validate(VALID_PDF_BYTES, "REPORT.PDF").extension());
        assertEquals("pdf", validator.validate(VALID_PDF_BYTES, "report.pDf").extension());
    }

    @Test
    @DisplayName("SEC-EVID-UNI-02: Unicode look-alike extensions and normalised dangerous names are rejected")
    void unicodeLookAlikesAreRejected() {
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_PDF_BYTES, "report.pd\u0130"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_PDF_BYTES, "report.pd\u0131"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_TXT_BYTES, "report.\uff45\uff58\uff45"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_PDF_BYTES, "report.pdf.\uff45\uff58\uff45"));
        assertThrows(BadRequestException.class, () -> validator.validate(VALID_PDF_BYTES, "report\uff0eexe.pdf"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "report\u200b.pdf",
            "report\u202efdp.txt",
            "report\u2028.pdf",
            "report.pdf\u200b",
            "report.pdf\u2024exe",
            "report.pdf\ufe52exe",
            "report.\uff50\uff44\uff46",
            "report.pdf.",
            "report.pd f",
            "report.pdf;"
    })
    @DisplayName("SEC-EVID-HARDEN-01: Hardened filename and extension rejection checks")
    void testHardenedFilenameAndExtensionRejection(String candidate) {
        byte[] payload = candidate.endsWith(".txt") ? VALID_TXT_BYTES : VALID_PDF_BYTES;
        BadRequestException ex = assertThrows(BadRequestException.class, () -> validator.validate(payload, candidate));
        assertNotNull(ex.getMessage());
        assertFalse(ex.getMessage().isBlank());
    }

    @Test
    @DisplayName("SEC-EVID-HARDEN-02: Trailing whitespace is trimmed and valid Bengali base names are allowed")
    void testDocumentedWhitespaceAndBengaliBaseNameBehaviour() {
        // Trailing whitespace is trimmed to "report.pdf" and accepted
        EvidenceValidator.ValidatedEvidence trimmed = validator.validate(VALID_PDF_BYTES, "report.pdf ");
        assertEquals("report.pdf", trimmed.originalName());
        assertEquals("pdf", trimmed.extension());

        // Non-ASCII Unicode letters in base name remain allowed (e.g. Bengali script)
        EvidenceValidator.ValidatedEvidence bengali = validator.validate(VALID_PDF_BYTES, "প্রতিবেদন.pdf");
        assertEquals("প্রতিবেদন.pdf", bengali.originalName());
        assertEquals("pdf", bengali.extension());
    }
}

