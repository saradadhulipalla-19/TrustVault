
package com.snovasys.trustvault;

import java.net.URI;

import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

public class TrustVaultLoginSessionTest {

    private static final String BASE_URL =
            "http://127.0.0.1:8083";

    private static final HttpClient CLIENT =
            HttpClient.newBuilder()
                    .followRedirects(HttpClient.Redirect.NEVER)
                    .build();

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);

        System.out.print("Username (owner): ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine();

        testLogin(username, password);

        System.out.println("\n--- TEST SUMMARY ---");
        System.out.println("Passed: " + passed);
        System.out.println("Failed: " + failed);

        if (failed > 0) {
            throw new AssertionError("Some tests failed");
        }
    }

    private static void testLogin(
            String username, String password) throws Exception {

        String form = "username="
                + URLEncoder.encode(
                        username, StandardCharsets.UTF_8)
                + "&password="
                + URLEncoder.encode(
                        password, StandardCharsets.UTF_8);

        HttpRequest loginRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/login"))
                .header("Content-Type",
                        "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();

        HttpResponse<String> loginResponse = CLIENT.send(
                loginRequest,
                HttpResponse.BodyHandlers.ofString());

        String cookie = loginResponse.headers()
                .firstValue("Set-Cookie")
                .orElse("");

        check("Login redirects to dashboard",
                loginResponse.statusCode() == 303
                && "/dashboard".equals(
                    loginResponse.headers()
                        .firstValue("Location").orElse("")));

        check("Session cookie is issued",
                cookie.startsWith("TVSESSION=")
                && !cookie.startsWith("TVSESSION=;"));

        if (!cookie.startsWith("TVSESSION=")
                || cookie.startsWith("TVSESSION=;")) {
            return;
        }

        String sessionCookie = cookie.split(";", 2)[0];

        HttpRequest dashboardRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/dashboard"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();

        HttpResponse<String> dashboardResponse = CLIENT.send(
                dashboardRequest,
                HttpResponse.BodyHandlers.ofString());

        check("Session can access dashboard",
                dashboardResponse.statusCode() == 200
                && dashboardResponse.body()
                        .contains("Welcome to TrustVault"));

        HttpRequest logoutRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/logout"))
                .header("Cookie", sessionCookie)
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        HttpResponse<String> logoutResponse = CLIENT.send(
                logoutRequest,
                HttpResponse.BodyHandlers.ofString());

        check("Logout redirects to login page",
                logoutResponse.statusCode() == 303
                && "/".equals(logoutResponse.headers()
                    .firstValue("Location").orElse("")));

        HttpRequest afterLogoutRequest = HttpRequest.newBuilder()
                .uri(URI.create(BASE_URL + "/dashboard"))
                .header("Cookie", sessionCookie)
                .GET()
                .build();

        HttpResponse<String> afterLogout = CLIENT.send(
                afterLogoutRequest,
                HttpResponse.BodyHandlers.ofString());

        check("Old session denied after logout",
                afterLogout.statusCode() == 401);
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
}