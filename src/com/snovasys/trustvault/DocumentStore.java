
package com.snovasys.trustvault;

import java.io.IOException;

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class DocumentStore {

    private static final long MAX_SIZE = 5L * 1024 * 1024;

    private static final Path STORAGE_DIR =
            Paths.get(
                    System.getProperty("user.home"),
                    "TrustVaultPrivateFiles"
            ).toAbsolutePath().normalize();

    private final Map<String, DocumentInfo> documents =
            new ConcurrentHashMap<>();

    public static class DocumentInfo {
        private final String id;
        private final String originalName;
        private final String owner;
        private final Path storedPath;
        private final Set<String> sharedUsers =
                ConcurrentHashMap.newKeySet();

        public DocumentInfo(
                String id,
                String originalName,
                String owner,
                Path storedPath) {

            this.id = id;
            this.originalName = originalName;
            this.owner = owner;
            this.storedPath = storedPath;
        }

        public String getId() {
            return id;
        }

        public String getOriginalName() {
            return originalName;
        }

        public String getOwner() {
            return owner;
        }

        public Path getStoredPath() {
            return storedPath;
        }

        public Set<String> getSharedUsers() {
            return Collections.unmodifiableSet(
                    new HashSet<>(sharedUsers)
            );
        }
    }

    public DocumentStore() {
        try {
            Files.createDirectories(STORAGE_DIR);
            setOwnerOnlyPermissions(STORAGE_DIR);
            loadExistingDocuments();
        } catch (IOException e) {
            throw new IllegalStateException(
                    "Could not initialize document storage.", e
            );
        }
    }

    public DocumentInfo savePdf(
            String originalName,
            String owner,
            byte[] data) throws IOException {

        if (originalName == null || originalName.isBlank()) {
            throw new IllegalArgumentException(
                    "A filename is required."
            );
        }

        // Remove client-supplied directory components.
        String safeName = originalName.replace('\\', '/');
        safeName = safeName.substring(
                safeName.lastIndexOf('/') + 1
        );

        if (safeName.isBlank()
                || safeName.equals(".")
                || safeName.equals("..")
                || !safeName.toLowerCase(Locale.ROOT).endsWith(".pdf")) {
            throw new IllegalArgumentException(
                    "PDF files only are allowed."
            );
        }

        if (owner == null || owner.isBlank()) {
            throw new IllegalArgumentException(
                    "Document owner is required."
            );
        }

        if (data == null || data.length == 0
                || data.length > MAX_SIZE) {
            throw new IllegalArgumentException(
                    "PDF must be between 1 byte and 5 MB."
            );
        }

        if (!hasPdfSignature(data)) {
            throw new IllegalArgumentException(
                    "The file does not have a valid PDF signature."
            );
        }

        Files.createDirectories(STORAGE_DIR);

        String id = UUID.randomUUID().toString();
        Path destination = getPdfPath(id);
        Path metadataPath = getMetadataPath(id);

        Files.write(
                destination,
                data,
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
        );

        setOwnerOnlyPermissions(destination);

        DocumentInfo info = new DocumentInfo(
                id, safeName, owner, destination
        );

        try {
            saveMetadata(info);
            documents.put(id, info);
            return info;
        } catch (IOException e) {
            Files.deleteIfExists(destination);
            Files.deleteIfExists(metadataPath);
            throw e;
        }
    }

    private boolean hasPdfSignature(byte[] data) {
        byte[] signature = {'%', 'P', 'D', 'F', '-'};

        int limit = Math.min(data.length - signature.length, 1024);

        for (int i = 0; i <= limit; i++) {
            boolean match = true;

            for (int j = 0; j < signature.length; j++) {
                if (data[i + j] != signature[j]) {
                    match = false;
                    break;
                }
            }

            if (match) {
                return true;
            }
        }

        return false;
    }

    public DocumentInfo findById(String id) {
        if (!isValidId(id)) {
            return null;
        }

        return documents.get(id);
    }

    // Retained for compatibility with your existing server.
    public DocumentInfo findByIdForOwner(
            String id, String username) {

        DocumentInfo document = findById(id);

        if (document == null || username == null
                || !document.getOwner().equals(username)) {
            return null;
        }

        return document;
    }

    // Owner and explicitly shared users can access the document.
    public DocumentInfo findByIdForUser(
            String id, String username) {

        if (username == null || username.isBlank()) {
            return null;
        }

        DocumentInfo document = findById(id);

        if (document == null) {
            return null;
        }

        if (document.getOwner().equals(username)
                || document.sharedUsers.contains(username)) {
            return document;
        }

        return null;
    }

    public List<DocumentInfo> findAllForOwner(String username) {
        List<DocumentInfo> result = new ArrayList<>();

        if (username == null || username.isBlank()) {
            return result;
        }

        for (DocumentInfo document : documents.values()) {
            if (username.equals(document.getOwner())) {
                result.add(document);
            }
        }

        return result;
    }

    public List<DocumentInfo> findAllAccessibleToUser(
            String username) {

        List<DocumentInfo> result = new ArrayList<>();

        if (username == null || username.isBlank()) {
            return result;
        }

        for (DocumentInfo document : documents.values()) {
            if (document.getOwner().equals(username)
                    || document.sharedUsers.contains(username)) {
                result.add(document);
            }
        }

        return result;
    }

    // Only the document owner may grant access.
    public synchronized boolean grantAccess(
            String id, String owner, String usernameToShare) {

        DocumentInfo document = findByIdForOwner(id, owner);

        if (document == null
                || usernameToShare == null
                || usernameToShare.isBlank()
                || usernameToShare.equals(owner)) {
            return false;
        }

        if (!document.sharedUsers.add(usernameToShare)) {
            return true;
        }

        try {
            saveMetadata(document);
            return true;
        } catch (IOException e) {
            document.sharedUsers.remove(usernameToShare);
            return false;
        }
    }

    // Only the document owner may revoke access.
    public synchronized boolean revokeAccess(
            String id, String owner, String usernameToRevoke) {

        DocumentInfo document = findByIdForOwner(id, owner);

        if (document == null || usernameToRevoke == null) {
            return false;
        }

        if (!document.sharedUsers.remove(usernameToRevoke)) {
            return false;
        }

        try {
            saveMetadata(document);
            return true;
        } catch (IOException e) {
            document.sharedUsers.add(usernameToRevoke);
            return false;
        }
    }

    private boolean isValidId(String id) {
        if (id == null) {
            return false;
        }

        try {
            UUID.fromString(id);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private Path getPdfPath(String id) {
        if (!isValidId(id)) {
            throw new IllegalArgumentException("Invalid document ID.");
        }

        return STORAGE_DIR.resolve(id + ".pdf").normalize();
    }

    private Path getMetadataPath(String id) {
        if (!isValidId(id)) {
            throw new IllegalArgumentException("Invalid document ID.");
        }

        return STORAGE_DIR.resolve(id + ".meta").normalize();
    }

    private synchronized void saveMetadata(
            DocumentInfo document) throws IOException {

        Properties properties = new Properties();

        properties.setProperty("id", document.id);
        properties.setProperty("originalName", document.originalName);
        properties.setProperty("owner", document.owner);
        properties.setProperty(
                "sharedCount",
                Integer.toString(document.sharedUsers.size())
        );

        int index = 0;
        for (String username : document.sharedUsers) {
            properties.setProperty("shared." + index, username);
            index++;
        }

        Path target = getMetadataPath(document.id);
        Path temporary = Files.createTempFile(
                STORAGE_DIR, "metadata-", ".tmp"
        );

        try {
            try (OutputStream output = Files.newOutputStream(
                    temporary,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                properties.store(output, "TrustVault document metadata");
            }

            setOwnerOnlyPermissions(temporary);

            try {
                Files.move(
                        temporary,
                        target,
                        StandardCopyOption.ATOMIC_MOVE,
                        StandardCopyOption.REPLACE_EXISTING
                );
            } catch (IOException atomicMoveFailure) {
                Files.move(
                        temporary,
                        target,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }

            setOwnerOnlyPermissions(target);
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private void loadExistingDocuments() throws IOException {
        try (java.util.stream.Stream<Path> paths =
                     Files.list(STORAGE_DIR)) {

            paths.filter(path ->
                    path.getFileName().toString().endsWith(".meta")
            ).forEach(path -> {
                try {
                    Properties properties = new Properties();

                    try (InputStream input = Files.newInputStream(path)) {
                        properties.load(input);
                    }

                    String id = properties.getProperty("id");
                    String name = properties.getProperty("originalName");
                    String owner = properties.getProperty("owner");

                    if (!isValidId(id)
                            || name == null || name.isBlank()
                            || owner == null || owner.isBlank()
                            || !path.equals(getMetadataPath(id))) {
                        return;
                    }

                    Path pdfPath = getPdfPath(id);

                    if (!Files.isRegularFile(pdfPath)) {
                        return;
                    }

                    DocumentInfo info = new DocumentInfo(
                            id, name, owner, pdfPath
                    );

                    int count = Integer.parseInt(
                            properties.getProperty("sharedCount", "0")
                    );

                    if (count < 0 || count > 10000) {
                        return;
                    }

                    for (int i = 0; i < count; i++) {
                        String sharedUser =
                                properties.getProperty("shared." + i);

                        if (sharedUser != null
                                && !sharedUser.isBlank()) {
                            info.sharedUsers.add(sharedUser);
                        }
                    }

                    documents.put(id, info);
                } catch (Exception e) {
                    System.err.println(
                            "Skipping unreadable document metadata: "
                                    + path.getFileName()
                    );
                }
            });
        }
    }

    private void setOwnerOnlyPermissions(Path path) {
        // POSIX permissions are not supported on every operating system.
        try {
            Set<PosixFilePermission> permissions = new HashSet<>();
            permissions.add(PosixFilePermission.OWNER_READ);
            permissions.add(PosixFilePermission.OWNER_WRITE);

            if (Files.isDirectory(path)) {
                permissions.add(PosixFilePermission.OWNER_EXECUTE);
            }

            Files.setPosixFilePermissions(path, permissions);
        } catch (UnsupportedOperationException | IOException e) {
            // Windows and some file systems do not support POSIX permissions.
        }
    }
}
