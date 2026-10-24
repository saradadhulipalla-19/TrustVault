
package com.snovasys.trustvault;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public class TrustVaultHttpSecurityTest {

    private static final String BASE_URL =
            "http://127.0.0.1:8083";

    private static final HttpClient CLIENT =
            HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {

        System.out.println(
                "TrustVault HTTP Security Tests Started");

        testLoginPage();

        testProtectedPage("/dashboard", 401);
        testProtectedPage("/documents", 401);
        testProtectedPage("/upload", 401);

        System.out.println("\n--- TEST SUMMARY ---");
        System.out.println("Passed: " + passed);
        System.out.println("Failed: " + failed);

        if (failed > 0) {
            throw new AssertionError(
                    "Some HTTP security tests failed");
        }
    }

    private static void check(
            String name, boolean success) {

        if (success) {
            passed++;
            System.out.println("[PASS] " + name);
        } else {
            failed++;
            System.out.println("[FAIL] " + name);
        }
    }

    private static void testProtectedPage(
            String path, int expectedStatus) throws Exception {

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + path))
                .GET()
                .build();

        HttpResponse<String> response = CLIENT.send(
                request,
                HttpResponse.BodyHandlers.ofString());

        int actualStatus = response.statusCode();

        check(
                path + " returned HTTP " + actualStatus,
                actualStatus == expectedStatus);
    }

    private static void testLoginPage() throws Exception {

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/"))
                .GET()
                .build();

        HttpResponse<String> response = CLIENT.send(
                request,
                HttpResponse.BodyHandlers.ofString());

        boolean success =
                response.statusCode() == 200
                && response.body().contains("TrustVault Login");

        check("Login page is accessible", success);
    }
}