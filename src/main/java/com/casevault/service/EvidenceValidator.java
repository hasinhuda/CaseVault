package com.casevault.service;

import com.casevault.exception.BadRequestException;
import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Validates uploaded evidence artifacts according to strict security rules (SR-11, FR-08, ADR 0004).
 * Enforces:
 * - Maximum size 10MB (and rejection of empty files)
 * - Extension allow-list (lower-cased): pdf, png, jpg, jpeg, txt, log, csv, json
 * - Double extension rejection if any non-final dot-segment is an executable/script-like extension
 * - Rejection of names with path separators, null bytes, control characters, or > 255 chars
 * - Apache Tika content-based MIME inspection against an explicit extension mapping table
 * - Rejection of executable/script binary headers regardless of extension (MZ, ELF, Mach-O, shebang '#!')
 * - Sanitised display-only original name and cryptographically random UUID stored name
 * - Synthetic antivirus scan verification
 * - Plaintext SHA-256 calculation
 */
@Component
public class EvidenceValidator {

    private static final Logger logger = LoggerFactory.getLogger(EvidenceValidator.class);

    public static final long MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024L; // 10 MB = 10,485,760 bytes

    public static final Set<String> ALLOWED_EXTENSIONS = Set.of(
            "pdf", "png", "jpg", "jpeg", "txt", "log", "csv", "json"
    );

    public static final Set<String> DANGEROUS_SEGMENTS = Set.of(
            "exe", "dll", "bat", "cmd", "com", "scr", "js",
            "vbs", "ps1", "sh", "jar", "msi", "php", "phtml",
            "jsp", "html", "htm", "svg"
    );

    public static final Map<String, Set<String>> EXTENSION_TO_ALLOWED_MIME = Map.of(
            "pdf", Set.of("application/pdf"),
            "png", Set.of("image/png"),
            "jpg", Set.of("image/jpeg"),
            "jpeg", Set.of("image/jpeg"),
            "txt", Set.of("text/plain"),
            "log", Set.of("text/plain"),
            "csv", Set.of("text/csv", "text/plain"),
            "json", Set.of("application/json", "text/plain")
    );

    private final AntivirusScanner antivirusScanner;
    private final Tika tika;

    public EvidenceValidator(AntivirusScanner antivirusScanner) {
        this.antivirusScanner = Objects.requireNonNull(antivirusScanner, "antivirusScanner must not be null");
        this.tika = new Tika();
    }

    /**
     * Validates a Spring MultipartFile upload.
     */
    public ValidatedEvidence validate(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new BadRequestException("Uploaded evidence file is empty or missing.");
        }
        byte[] content;
        try {
            content = file.getBytes();
        } catch (IOException e) {
            logger.warn("Failed to read uploaded multipart file bytes", e);
            throw new BadRequestException("Failed to read uploaded file payload.");
        }
        return validate(content, file.getOriginalFilename());
    }

    /**
     * Core validation method enforcing all evidence upload rules.
     */
    public ValidatedEvidence validate(byte[] content, String rawFilename) {
        // 1. File size checks (empty or oversize)
        if (content == null || content.length == 0) {
            throw new BadRequestException("Evidence file is empty.");
        }
        if (content.length > MAX_FILE_SIZE_BYTES) {
            throw new BadRequestException("Evidence file exceeds maximum allowed size of 10MB.");
        }

        // 2. Filename validation and sanitisation
        String sanitizedName = sanitizeOriginalName(rawFilename);
        String normalizedName = normalizeForSecurityChecks(sanitizedName);

        // 3. Extension allow-list verification with ASCII case-folding and character restrictions
        int lastDot = normalizedName.lastIndexOf('.');
        if (lastDot <= 0 || lastDot == normalizedName.length() - 1) {
            throw new BadRequestException("Evidence filename must have an allowed extension.");
        }
        String extension = normalizedName.substring(lastDot + 1);
        if (!extension.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
            throw new BadRequestException("Evidence filename extension must contain ASCII characters only.");
        }
        if (!ALLOWED_EXTENSIONS.contains(extension)) {
            throw new BadRequestException("File extension '" + extension + "' is not permitted.");
        }

        // 4. Double extension rejection (any non-final dot-segment matching dangerous extensions)
        String[] segments = normalizedName.split("\\.");
        for (int i = 0; i < segments.length - 1; i++) {
            String segment = segments[i];
            if (DANGEROUS_SEGMENTS.contains(segment)) {
                throw new BadRequestException("Double extension detected with dangerous extension: '" + segment + "'.");
            }
        }

        // 5. Executable header rejection regardless of extension
        if (isExecutableHeader(content)) {
            throw new BadRequestException("Executable binary or script header detected; file rejected.");
        }

        // 6. Apache Tika content inspection (detected strictly from payload bytes)
        String detectedMime = detectMimeType(content);
        Set<String> allowedMimes = EXTENSION_TO_ALLOWED_MIME.get(extension);
        if (allowedMimes == null || !allowedMimes.contains(detectedMime)) {
            throw new BadRequestException("MIME type mismatch: extension '." + extension
                    + "' does not match detected content type '" + detectedMime + "'.");
        }

        // 7. Synthetic Antivirus scan
        AntivirusScanner.ScanResult scanResult = antivirusScanner.scan(content, sanitizedName);
        if (!scanResult.isClean()) {
            throw new BadRequestException("Antivirus scan failed: " + scanResult.signatureName());
        }

        // 8. Plaintext SHA-256 hash calculation (64-character lowercase hex string)
        String sha256Hex = computeSha256Hex(content);

        // 9. Generate stored UUID name
        String storedName = UUID.randomUUID().toString();

        return new ValidatedEvidence(
                sanitizedName,
                storedName,
                extension,
                detectedMime,
                content.length,
                sha256Hex,
                content
        );
    }

    /**
     * Sanitises and validates the original filename.
     * Rejects names with path separators ('/' or '\'), null bytes, control characters,
     * or length > 255 characters. Strips leading/trailing whitespace.
     */
    public static String sanitizeOriginalName(String filename) {
        if (filename == null || filename.isBlank()) {
            throw new BadRequestException("Evidence filename must not be blank.");
        }

        // Check for null bytes
        if (filename.indexOf('\0') != -1) {
            throw new BadRequestException("Evidence filename must not contain null bytes.");
        }

        // Reject path separators
        if (filename.contains("/") || filename.contains("\\")) {
            throw new BadRequestException("Evidence filename must not contain path separators.");
        }

        // Check for control characters
        for (char c : filename.toCharArray()) {
            if (Character.isISOControl(c)) {
                throw new BadRequestException("Evidence filename must not contain control characters.");
            }
        }

        // Strip directory prefixes if any passed through edge cases
        String stripped = stripDirectoryPart(filename).trim();
        if (stripped.isEmpty()) {
            throw new BadRequestException("Evidence filename is empty after sanitisation.");
        }

        if (stripped.length() > 255) {
            throw new BadRequestException("Evidence filename exceeds maximum allowed length of 255 characters.");
        }

        return stripped;
    }

    private static String normalizeForSecurityChecks(String filename) {
        if (filename.indexOf('\0') != -1 || filename.contains("/") || filename.contains("\\")) {
            throw new BadRequestException("Evidence filename must not contain path separators or null bytes.");
        }
        for (int i = 0; i < filename.length(); ) {
            int codePoint = filename.codePointAt(i);
            int type = Character.getType(codePoint);
            if (Character.isISOControl(codePoint)) {
                throw new BadRequestException("Evidence filename must not contain control characters.");
            }
            if (type == Character.FORMAT
                    || type == Character.LINE_SEPARATOR
                    || type == Character.PARAGRAPH_SEPARATOR) {
                throw new BadRequestException("Evidence filename must not contain format or separator characters.");
            }
            if (codePoint == '\uff0e' || codePoint == '\u3002' || codePoint == '\uff0f' || codePoint == '\uff3c') {
                throw new BadRequestException("Evidence filename must not contain look-alike punctuation.");
            }
            i += Character.charCount(codePoint);
        }
        int dot = filename.lastIndexOf('.');
        if (dot >= 0) {
            for (int index = dot + 1; index < filename.length(); index++) {
                if (filename.charAt(index) > 0x7f) {
                    throw new BadRequestException("Evidence filename extension must contain ASCII characters only.");
                }
            }
        }
        String[] parts = filename.split("\\.");
        for (String part : parts) {
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c >= 0xff01 && c <= 0xff5e) {
                    throw new BadRequestException("Evidence filename must not contain fullwidth characters.");
                }
            }
        }
        return asciiLowerCase(filename);
    }

    private static String asciiLowerCase(String value) {
        StringBuilder result = new StringBuilder(value.length());
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            result.append(character >= 'A' && character <= 'Z' ? (char) (character + ('a' - 'A')) : character);
        }
        return result.toString();
    }

    /**
     * Extracts basename by stripping any directory path prefix.
     */
    public static String stripDirectoryPart(String filename) {
        if (filename == null) {
            return "";
        }
        int lastSlash = Math.max(filename.lastIndexOf('/'), filename.lastIndexOf('\\'));
        return lastSlash >= 0 ? filename.substring(lastSlash + 1) : filename;
    }

    /**
     * Checks if content begins with executable binary or script magic headers:
     * - Windows PE / DOS: MZ (0x4D, 0x5A) or ZM (0x5A, 0x4D)
     * - Linux / Unix ELF: 0x7F 'E' 'L' 'F'
     * - Mach-O / Java Class: 0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xCAFEBABF (big and little endian)
     * - Script Shebang: '#!' (0x23, 0x21) including UTF-8 BOM shebang
     */
    public static boolean isExecutableHeader(byte[] data) {
        if (data == null || data.length < 2) {
            return false;
        }

        // 1. Windows PE / DOS: MZ or ZM
        if ((data[0] == 0x4D && data[1] == 0x5A) || (data[0] == 0x5A && data[1] == 0x4D)) {
            return true;
        }

        // 2. Script shebang: '#!'
        if (data[0] == 0x23 && data[1] == 0x21) {
            return true;
        }

        // UTF-8 BOM + shebang: EF BB BF 23 21
        if (data.length >= 5
                && (data[0] & 0xFF) == 0xEF
                && (data[1] & 0xFF) == 0xBB
                && (data[2] & 0xFF) == 0xBF
                && data[3] == 0x23
                && data[4] == 0x21) {
            return true;
        }

        if (data.length >= 4) {
            // 3. Linux / Unix ELF: 0x7F, 'E', 'L', 'F'
            if (data[0] == 0x7F && data[1] == 0x45 && data[2] == 0x4C && data[3] == 0x46) {
                return true;
            }

            // 4. Mach-O & Universal Binaries
            int b0 = data[0] & 0xFF;
            int b1 = data[1] & 0xFF;
            int b2 = data[2] & 0xFF;
            int b3 = data[3] & 0xFF;

            // 0xFEEDFACE (32-bit Mach-O)
            if ((b0 == 0xFE && b1 == 0xED && b2 == 0xFA && b3 == 0xCE)
                    || (b0 == 0xCE && b1 == 0xFA && b2 == 0xED && b3 == 0xFE)) {
                return true;
            }

            // 0xFEEDFACF (64-bit Mach-O)
            if ((b0 == 0xFE && b1 == 0xED && b2 == 0xFA && b3 == 0xCF)
                    || (b0 == 0xCF && b1 == 0xFA && b2 == 0xED && b3 == 0xFE)) {
                return true;
            }

            // 0xCAFEBABE (Mach-O Universal / Java class file)
            if ((b0 == 0xCA && b1 == 0xFE && b2 == 0xBA && b3 == 0xBE)
                    || (b0 == 0xBE && b1 == 0xBA && b2 == 0xFE && b3 == 0xCA)) {
                return true;
            }

            // 0xCAFEBABF (Mach-O Universal 64-bit)
            if ((b0 == 0xCA && b1 == 0xFE && b2 == 0xBA && b3 == 0xBF)
                    || (b0 == 0xBF && b1 == 0xBA && b2 == 0xFE && b3 == 0xCA)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Inspects binary content using Apache Tika strictly from byte array payload.
     * Strips MIME parameters (e.g. '; charset=UTF-8') and converts to lowercase.
     */
    public String detectMimeType(byte[] content) {
        String detected = tika.detect(content);
        if (detected == null || detected.isBlank()) {
            return "application/octet-stream";
        }
        int paramIndex = detected.indexOf(';');
        if (paramIndex != -1) {
            detected = detected.substring(0, paramIndex);
        }
        return asciiLowerCase(detected.trim());
    }

    /**
     * Computes the SHA-256 cryptographic digest of the plaintext bytes,
     * returning a 64-character lowercase hexadecimal string.
     */
    public static String computeSha256Hex(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data for SHA-256 computation must not be null.");
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 message digest algorithm not available", e);
        }
    }

    /**
     * Immutable result holding validated evidence metadata and defensively copied content.
     */
    public record ValidatedEvidence(
            String originalName,
            String storedName,
            String extension,
            String detectedMimeType,
            long sizeBytes,
            String sha256Hex,
            byte[] content
    ) {
        public ValidatedEvidence {
            content = content != null ? content.clone() : new byte[0];
        }

        @Override
        public byte[] content() {
            return content.clone();
        }
    }
}
