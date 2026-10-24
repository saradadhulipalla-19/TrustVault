
package com.snovasys.trustvault;

import java.io.IOException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class AuditLog {

    private static final Path LOG_FILE =
            Path.of(System.getProperty("user.home"),
                    "TrustVaultPrivateFiles", "audit.log");

    public static synchronized void record(
            String username, String action,
            String documentId, String result) {

        String safeUser = clean(username);
        String safeAction = clean(action);
        String safeId = clean(documentId);
        String safeResult = clean(result);

        String timestamp = ZonedDateTime.now(ZoneId.of("Asia/Kolkata"))
                .format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

        String line = timestamp + " | "
                + safeUser + " | "
                + safeAction + " | "
                + safeId + " | "
                + safeResult + System.lineSeparator();
        try {
            Files.createDirectories(LOG_FILE.getParent());

            Files.writeString(LOG_FILE, line,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            System.err.println("Audit log write failed: "
                    + e.getMessage());
            e.printStackTrace();
        }
    }

    private static String clean(String value) {
        if (value == null) {
            return "unknown";
        }

        return value.replace("\r", "_")
                    .replace("\n", "_")
                    .replace("|", "_");
    }
}