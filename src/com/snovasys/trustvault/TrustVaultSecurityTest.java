
package com.snovasys.trustvault;

import java.nio.charset.StandardCharsets;

public class TrustVaultSecurityTest {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {

        DocumentStore store = new DocumentStore();

        test("Valid PDF is saved", () -> {
            byte[] pdf = (
                "%PDF-1.4\nTest document\n%%EOF"
            ).getBytes(StandardCharsets.UTF_8);

            DocumentStore.DocumentInfo info =
                store.savePdf("test-document.pdf", "ownerA", pdf);

            check(info != null, "Document should be saved");
            check(info.getId() != null, "Document ID is required");
        });

        test("Non-PDF extension is rejected", () -> {
            byte[] data = (
                "%PDF-1.4\nTest\n%%EOF"
            ).getBytes(StandardCharsets.UTF_8);

            expectIllegalArgument(() ->
                store.savePdf("malware.exe", "ownerA", data)
            );
        });

        test("Invalid PDF signature is rejected", () -> {
            byte[] data = "This is not a PDF".getBytes(
                StandardCharsets.UTF_8);

            expectIllegalArgument(() ->
                store.savePdf("fake.pdf", "ownerA", data)
            );
        });

        test("Empty file is rejected", () -> {
            expectIllegalArgument(() ->
                store.savePdf("empty.pdf", "ownerA", new byte[0])
            );
        });

        test("Wrong owner cannot find document", () -> {
            byte[] pdf = (
                "%PDF-1.4\nPrivate document\n%%EOF"
            ).getBytes(StandardCharsets.UTF_8);

            DocumentStore.DocumentInfo info =
                store.savePdf("private.pdf", "ownerA", pdf);

            DocumentStore.DocumentInfo result =
                store.findByIdForOwner(info.getId(), "ownerB");

            check(result == null,
                "Another user must not access this document");
        });

        System.out.println("\n--- TEST SUMMARY ---");
        System.out.println("Passed: " + passed);
        System.out.println("Failed: " + failed);

        if (failed > 0) {
            throw new AssertionError("Some security tests failed");
        }
    }

    private static void test(String name, RunnableTest action) {
        try {
            action.run();
            passed++;
            System.out.println("[PASS] " + name);
        } catch (Throwable e) {
            failed++;
            System.out.println("[FAIL] " + name + ": "
                + e.getMessage());
        }
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
    private static void expectIllegalArgument(
            RunnableTest action) throws Exception {

        try {
            action.run();
        } catch (IllegalArgumentException expected) {
            return;
        }

        throw new AssertionError(
            "Expected IllegalArgumentException");
    }

    

    @FunctionalInterface
    interface RunnableTest {
        void run() throws Exception;
    }
}