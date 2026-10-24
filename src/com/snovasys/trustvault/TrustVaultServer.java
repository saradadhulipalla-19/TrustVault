package com.snovasys.trustvault;

import com.sun.net.httpserver.HttpServer;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
//import java.nio.file.StandardCopyOption;
//import java.util.UUID;

public class TrustVaultServer {
	private static final Path STORAGE_DIR = Paths.get(System.getProperty("user.home"), "TrustVaultPrivateFiles")
			.toAbsolutePath().normalize();

	private static final UserStore userStore = createUserStore();

	private static final Map<String, Session> sessions = new ConcurrentHashMap<>();

	private static final SecureRandom random = new SecureRandom();

	private static final long SESSION_TIME = 30 * 60 * 1000;

	
private static UserStore createUserStore() {
    try {
        UserStore store = new UserStore();

        System.out.println("DEBUG users initialized:"
                + " admin=" + store.userExists("admin")
                + ", owner=" + store.userExists("owner")
                + ", viewer=" + store.userExists("viewer"));

        return store;
    } catch (Exception e) {
        throw new IllegalStateException("Could not initialize users", e);
    }
}


	private static class Session {
		final User user;
		final long expiresAt;

		Session(User user) {
			this.user = user;
			this.expiresAt = System.currentTimeMillis() + SESSION_TIME;
		}
	}

	private static final DocumentStore documentStore = new DocumentStore();

	
public static void main(String[] args) throws IOException {
    Files.createDirectories(STORAGE_DIR);
    System.out.println("Private storage folder ready!");

    int port = Integer.parseInt(
        System.getenv().getOrDefault("PORT", "8083")
    );

    HttpServer server = HttpServer.create(
        new InetSocketAddress("0.0.0.0", port), 0
    );

    server.createContext("/", TrustVaultServer::handleRequest);
    server.start();

    System.out.println("TrustVault started on port " + port);
    System.out.println("Server is ready!");
}


	private static void handleRequest(HttpExchange exchange) throws IOException {

		try {
			String path = exchange.getRequestURI().getPath();
			String method = exchange.getRequestMethod();

			// PDF upload page
			if (path.equals("/upload") && method.equals("GET")) {
				User user = getLoggedInUser(exchange);

				if (user == null) {
					send(exchange, 401, "Please login first.");
					return;
				}

				send(exchange, 200, """
						<!DOCTYPE html>
						<html>
						<body>
						    <h2>Upload PDF</h2>
						    <form method="POST" action="/upload"
						          enctype="multipart/form-data">
						        <input type="file" name="file"
						               accept=".pdf,application/pdf" required>
						        <button type="submit">Upload PDF</button>
						    </form>
						    <a href="/dashboard">Back to Dashboard</a>
						</body>
						</html>
						""");
				return;
			}

			if (path.equals("/upload") && method.equals("POST")) {
				handlePdfUpload(exchange);
				return;
			}

			if (path.equals("/") && method.equals("GET")) {
				send(exchange, 200, loginPage());
				return;
			}

			if (path.equals("/login") && method.equals("POST")) {
				handleLogin(exchange);
				return;
			}

			if (path.equals("/logout") && method.equals("POST")) {
				String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");

				if (cookieHeader != null) {
					for (String cookie : cookieHeader.split(";")) {
						String[] parts = cookie.trim().split("=", 2);

						if (parts.length == 2 && parts[0].equals("TVSESSION")) {
							Session removed = sessions.remove(parts[1]);

							if (removed != null) {
								AuditLog.record(removed.user.getUsername(), "LOGOUT", "session", "SUCCESS");
							}
						}
					}
				}

				exchange.getResponseHeaders().add("Set-Cookie",
						"TVSESSION=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");

				exchange.getResponseHeaders().add("Location", "/");
				exchange.sendResponseHeaders(303, -1);
				return;
			}

			if (path.equals("/dashboard") && method.equals("GET")) {
				User user = getLoggedInUser(exchange);

				if (user == null) {
					send(exchange, 401, "Login required. Please return to the home page.");
					return;
				}

				send(exchange, 200, "<h2>Welcome to TrustVault</h2>" + "<p>User: " + escape(user.getUsername()) + "</p>"
						+ "<p>Role: " + escape(user.getRole()) + "</p>" + "<p>Login successful.</p>"
						+ ("ADMIN".equals(user.getRole()) ? "<p><a href='/admin/users'>Create Viewer Account</a></p>"
								: "")
						+ (("OWNER".equals(user.getRole()) || "ADMIN".equals(user.getRole()))
								? "<p><a href='/upload'>Upload PDF</a></p>"
								: "")
						// + "<p><a href='/upload'>Upload PDF</a></p>"
						+ "<p><a href='/documents'>My Documents</a></p>" + """
								<form method="POST" action="/logout">
								    <button type="submit">Logout</button>
								</form>
								"""
				// + "<p><a href='/upload'>Upload PDF</a></p>"
				// + "<p><a href='/download?id=4bd2f6e8-51da-47aa-934d-163ecccf889f'>Download
				// PDF</a></p>"
				);
				return;
			}

			if (path.equals("/documents") && method.equals("GET")) {
				User user = getLoggedInUser(exchange);

				if (user == null) {
					AuditLog.record("unknown", "LIST_DOCUMENTS", "unknown", "DENIED");
					send(exchange, 401, "Please login first.");
					return;
				}

				var documents = documentStore.findAllAccessibleToUser(user.getUsername());

				StringBuilder html = new StringBuilder();

				html.append("""
						<!DOCTYPE html>
						<html>
						<head>
						    <meta charset="UTF-8">
						    <title>My Documents - TrustVault</title>
						</head>
						<body>
						    <h2>My Documents</h2>
						""");

				if (documents.isEmpty()) {
					html.append("<p>No documents uploaded yet.</p>");
				} else {
					html.append("<ul>");

					for (DocumentStore.DocumentInfo document : documents) {
						String id = escape(document.getId());

						html.append("<li>").append(escape(document.getOriginalName()))
								.append(" — <a href='/download?id=").append(id).append("'>Download PDF</a>");

						if ("OWNER".equals(user.getRole())) {
							html.append("""
									<form method="POST" action="/share">
									    <input type="hidden" name="id" value="
									""").append(id).append("""
									">
									    <input name="username"
									           placeholder="Username to share with"
									           minlength="3" maxlength="30" required>
									    <button type="submit">Share</button>
									</form>

									<form method="POST" action="/revoke">
									    <input type="hidden" name="id" value="
									""").append(id).append("""
									">
									    <input name="username"
									           placeholder="Username to revoke"
									           minlength="3" maxlength="30" required>
									    <button type="submit">Revoke Access</button>
									</form>
									""");
						}

						html.append("</li>");
					}
					html.append("</ul>");
				}

				html.append("""
						    <p><a href="/upload">Upload another PDF</a></p>
						    <p><a href="/dashboard">Back to Dashboard</a></p>
						</body>
						</html>
						""");

				AuditLog.record(user.getUsername(), "LIST_DOCUMENTS", "own-documents", "SUCCESS");

				send(exchange, 200, html.toString());
				return;
			}
			if (path.equals("/download") && method.equals("GET")) {
				handlePdfDownload(exchange);
				return;
			}

			if (path.equals("/admin/users") && method.equals("GET")) {
				User currentUser = getLoggedInUser(exchange);

				if (currentUser == null) {
					send(exchange, 401, "Please login first.");
					return;
				}

				if (!currentUser.getRole().equals("ADMIN")) {
					send(exchange, 403, "Admin access required.");
					return;
				}

				send(exchange, 200, """
						<!DOCTYPE html>
						<html>
						<head><meta charset="UTF-8"></head>
						<body>
						    <h2>Create Viewer Account</h2>
						    <form method="POST" action="/admin/users">
						        <label>New Username:</label>
						        <input name="username" required
						               minlength="3" maxlength="30">
						        <br><br>

						        <label>New Password:</label>
						        <input type="password" name="password"
						               required minlength="12" maxlength="128">
						        <br><br>

						        <button type="submit">Create User</button>
						    </form>
						    <a href="/dashboard">Dashboard</a>
						</body>
						</html>
						""");
				return;
			}

			if (path.equals("/admin/users") && method.equals("POST")) {
				handleCreateViewer(exchange);
				return;
			}
			if (path.equals("/share") && method.equals("POST")) {
				handleShareDocument(exchange);
				return;
			}

			if (path.equals("/revoke") && method.equals("POST")) {
				handleRevokeDocument(exchange);
				return;
			}
			send(exchange, 404, "Page not found");

		} catch (Exception e) {
			e.printStackTrace();

			if (exchange.getResponseCode() == -1) {
				send(exchange, 500, "Internal server error");
			}
		} finally {
			exchange.close();
		}
	}

	private static void handleCreateViewer(HttpExchange exchange) throws IOException {

		User admin = getLoggedInUser(exchange);

		if (admin == null) {
			send(exchange, 401, "Please login first.");
			return;
		}

		if (!"ADMIN".equals(admin.getRole())) {
			AuditLog.record(admin.getUsername(), "CREATE_USER", "unknown", "DENIED");
			send(exchange, 403, "Admin access required.");
			return;
		}

		String contentType = exchange.getRequestHeaders().getFirst("Content-Type");

		if (contentType == null || !contentType.startsWith("application/x-www-form-urlencoded")) {
			send(exchange, 415, "Unsupported content type.");
			return;
		}

		byte[] body = exchange.getRequestBody().readNBytes(4097);

		if (body.length > 4096) {
			send(exchange, 413, "Request too large.");
			return;
		}

		Map<String, String> fields = parseForm(new String(body, StandardCharsets.UTF_8));

		String username = fields.getOrDefault("username", "").trim();
		char[] password = fields.getOrDefault("password", "").toCharArray();

		try {
			userStore.registerViewer(username, password);

			AuditLog.record(admin.getUsername(), "CREATE_USER", username, "SUCCESS");

			send(exchange, 200,
					"<h2>Viewer account created successfully!</h2>" + "<a href='/dashboard'>Back to Dashboard</a>");

		} catch (IllegalArgumentException e) {
			AuditLog.record(admin.getUsername(), "CREATE_USER", username, "REJECTED");

			send(exchange, 400, escape(e.getMessage()));

		} catch (Exception e) {
			AuditLog.record(admin.getUsername(), "CREATE_USER", username, "ERROR");

			send(exchange, 500, "Could not create user.");

		} finally {
			java.util.Arrays.fill(password, '\0');
		}
	}

	private static void handleLogin(HttpExchange exchange) throws Exception {

		String contentType = exchange.getRequestHeaders().getFirst("Content-Type");

		if (contentType == null || !contentType.startsWith("application/x-www-form-urlencoded")) {
			send(exchange, 415, "Unsupported content type");
			return;
		}

		byte[] body = exchange.getRequestBody().readNBytes(4097);

		if (body.length > 4096) {
			send(exchange, 413, "Request too large");
			return;
		}

		String form = new String(body, StandardCharsets.UTF_8);
		Map<String, String> fields = parseForm(form);

		String username = fields.getOrDefault("username", "");
		String password = fields.getOrDefault("password", "");

		if (username.length() > 100 || password.length() > 200) {
			send(exchange, 400, "Invalid input");
			return;
		}

		User user = userStore.authenticate(username, password.toCharArray());
		System.out.println("DEBUG login username=[" + username
		        + "], userFound=" + (user != null));


		if (user == null) {
			AuditLog.record(username, "LOGIN_FAILED", "session", "DENIED");
			AuditLog.record(username, "LOGIN_SUCCESS", "session", "SUCCESS");

			send(exchange, 401, "<h3>Login failed</h3>" + "<p>Username or password is incorrect.</p>"
					+ "<a href='/'>Try again</a>");
			return;
		}

		byte[] tokenBytes = new byte[32];
		random.nextBytes(tokenBytes);

		String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

		sessions.put(token, new Session(user));
		AuditLog.record(user.getUsername(), "LOGIN_SUCCESS", "session", "SUCCESS");

		exchange.getResponseHeaders().add("Set-Cookie", "TVSESSION=" + token + "; Path=/; HttpOnly; SameSite=Lax");

		exchange.getResponseHeaders().add("Location", "/dashboard");
		exchange.sendResponseHeaders(303, -1);
	}

	private static User getLoggedInUser(HttpExchange exchange) {

		String cookieHeader = exchange.getRequestHeaders().getFirst("Cookie");

		if (cookieHeader == null) {
			return null;
		}

		for (String cookie : cookieHeader.split(";")) {
			String[] parts = cookie.trim().split("=", 2);

			if (parts.length == 2 && parts[0].equals("TVSESSION")) {

				Session session = sessions.get(parts[1]);

				if (session == null) {
					return null;
				}

				if (System.currentTimeMillis() > session.expiresAt) {
					sessions.remove(parts[1], session);
					return null;
				}

				return session.user;
			}
		}

		return null;
	}

	private static Map<String, String> parseForm(String form) {
		Map<String, String> result = new ConcurrentHashMap<>();

		for (String pair : form.split("&")) {
			String[] parts = pair.split("=", 2);

			String key = decode(parts[0]);
			String value = parts.length == 2 ? decode(parts[1]) : "";

			result.put(key, value);
		}

		return result;
	}

	private static String decode(String value) {
		return URLDecoder.decode(value, StandardCharsets.UTF_8);
	}

	private static String loginPage() {
		return """
				<!DOCTYPE html>
				<html>
				<head>
				    <meta charset="UTF-8">
				    <title>TrustVault Login</title>
				</head>
				<body>
				    <h2>TrustVault Login</h2>
				    <form method="POST" action="/login">
				        <label>Username:</label>
				        <input name="username" required>
				        <br><br>
				        <label>Password:</label>
				        <input type="password" name="password"
				               required>
				        <br><br>
				        <button type="submit">Login</button>
				    </form>
				</body>
				</html>
				""";
	}

	private static String escape(String value) {
		return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
				.replace("'", "&#39;");
	}

	private static void send(HttpExchange exchange, int status, String message) throws IOException {

		byte[] data = message.getBytes(StandardCharsets.UTF_8);

		exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");

		exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");

		exchange.sendResponseHeaders(status, data.length);

		try (var output = exchange.getResponseBody()) {
			output.write(data);
		}
	}

	private static void handlePdfUpload(HttpExchange exchange) throws IOException {

		User user = getLoggedInUser(exchange);

		if (user == null) {
			AuditLog.record("unknown", "UPLOAD", "unknown", "DENIED");
			send(exchange, 401, "Please login first.");
			return;
		}

		if (!user.getRole().equals("OWNER") && !user.getRole().equals("ADMIN")) {
			AuditLog.record(user.getUsername(), "UPLOAD", "unknown", "DENIED");
			send(exchange, 403, "Upload permission denied.");
			return;
		}

		String contentType = exchange.getRequestHeaders().getFirst("Content-Type");

		if (contentType == null || !contentType.toLowerCase().startsWith("multipart/form-data;")) {
			AuditLog.record(user.getUsername(), "UPLOAD", "unknown", "INVALID_CONTENT_TYPE");
			send(exchange, 415, "Please upload a PDF file.");
			return;
		}

		byte[] body = exchange.getRequestBody().readNBytes(5 * 1024 * 1024 + 16384);

		if (body.length > 5 * 1024 * 1024 + 16383) {
			AuditLog.record(user.getUsername(), "UPLOAD", "unknown", "TOO_LARGE");
			send(exchange, 413, "Upload request is too large.");
			return;
		}

		String boundaryMarker = "boundary=";
		int boundaryPosition = contentType.indexOf(boundaryMarker);

		if (boundaryPosition < 0) {
			send(exchange, 400, "Invalid upload request.");
			return;
		}

		String boundary = contentType.substring(boundaryPosition + boundaryMarker.length()).trim();

		if (boundary.startsWith("\"") && boundary.endsWith("\"") && boundary.length() >= 2) {
			boundary = boundary.substring(1, boundary.length() - 1);
		}

		if (boundary.isEmpty() || boundary.length() > 200 || !boundary.matches("[A-Za-z0-9'()+_,./:=?-]+")) {
			send(exchange, 400, "Invalid upload boundary.");
			return;
		}

		byte[] marker = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);

		byte[] separator = "\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1);

		int markerAt = indexOf(body, marker, 0);

		if (markerAt < 0) {
			send(exchange, 400, "Invalid multipart request.");
			return;
		}

		int headerStart = markerAt + marker.length;

		if (headerStart + 2 > body.length || body[headerStart] != '\r' || body[headerStart + 1] != '\n') {
			send(exchange, 400, "Invalid multipart headers.");
			return;
		}

		headerStart += 2;

		int headerEnd = indexOf(body, separator, headerStart);

		if (headerEnd < 0 || headerEnd - headerStart > 8192) {
			send(exchange, 400, "Invalid file headers.");
			return;
		}

		String headers = new String(body, headerStart, headerEnd - headerStart, StandardCharsets.ISO_8859_1);

		if (!headers.toLowerCase().contains("content-disposition: form-data;") || !headers.contains("name=\"file\"")) {
			send(exchange, 400, "Please select a file.");
			return;
		}

		int fileStart = headerEnd + separator.length;
		int fileEnd = indexOf(body, marker, fileStart);

		if (fileEnd < 0 || fileEnd < fileStart + 5) {
			send(exchange, 400, "Invalid PDF upload.");
			return;
		}

		int dataEnd = fileEnd;

		if (dataEnd >= 2 && body[dataEnd - 2] == '\r' && body[dataEnd - 1] == '\n') {
			dataEnd -= 2;
		}

		byte[] pdf = java.util.Arrays.copyOfRange(body, fileStart, dataEnd);

		String originalName = "document.pdf";

		java.util.regex.Matcher filenameMatcher = java.util.regex.Pattern.compile("filename=\"([^\"]{1,255})\"")
				.matcher(headers);

		if (filenameMatcher.find()) {
			originalName = filenameMatcher.group(1);
		}

		if (!originalName.toLowerCase().endsWith(".pdf")) {
			AuditLog.record(user.getUsername(), "UPLOAD", "unknown", "INVALID_EXTENSION");
			send(exchange, 400, "PDF files only.");
			return;
		}

		try {
			DocumentStore.DocumentInfo info = documentStore.savePdf(originalName, user.getUsername(), pdf);

			AuditLog.record(user.getUsername(), "UPLOAD", info.getId(), "SUCCESS");

			send(exchange, 200, "<h2>PDF uploaded successfully!</h2>" + "<p>Document ID: " + escape(info.getId())
					+ "</p>" + "<a href='/dashboard'>Back to Dashboard</a>");

		} catch (IllegalArgumentException e) {
			AuditLog.record(user.getUsername(), "UPLOAD", "unknown", "REJECTED");
			send(exchange, 400, "Invalid PDF or file size.");
		}
	}

	private static int indexOf(byte[] data, byte[] target, int start) {
		for (int i = start; i <= data.length - target.length; i++) {
			boolean match = true;

			for (int j = 0; j < target.length; j++) {
				if (data[i + j] != target[j]) {
					match = false;
					break;
				}
			}

			if (match) {
				return i;
			}
		}

		return -1;

	}

	private static void handlePdfDownload(HttpExchange exchange) throws IOException {
		System.out.println("DEBUG: handlePdfDownload called");
		User user = getLoggedInUser(exchange);

		if (user == null) {
			send(exchange, 401, "Please login first.");
			return;
		}

		String query = exchange.getRequestURI().getRawQuery();

		String id = query == null ? null : parseForm(query).get("id");

		if (id == null || id.isBlank()) {
			send(exchange, 400, "Document ID is required.");
			return;
		}

		DocumentStore.DocumentInfo document = documentStore.findByIdForUser(id, user.getUsername());

		if (document == null) {
		    System.out.println("DEBUG: Document not found or access denied: " + id);

		    AuditLog.record(
		            user.getUsername(),
		            "DOWNLOAD",
		            id,
		            "DENIED"
		    );

		    System.out.println("DEBUG: DENIED audit record attempted");

		    send(exchange, 404,
		            "Document not found or access denied.");
		    return;
		}

		Path file = document.getStoredPath().toAbsolutePath().normalize();

		if (!Files.isRegularFile(file) || !file.startsWith(STORAGE_DIR)) {
			send(exchange, 404, "Document unavailable.");
			return;
		}

		exchange.getResponseHeaders().set("Content-Type", "application/pdf");

		exchange.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"document.pdf\"");

		exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");

		exchange.sendResponseHeaders(200, Files.size(file));

		try (var output = exchange.getResponseBody()) {
			Files.copy(file, output);
		}

		AuditLog.record(user.getUsername(), "DOWNLOAD", id, "SUCCESS");
	}

	private static void handleShareDocument(HttpExchange exchange) throws IOException {

		User user = getLoggedInUser(exchange);

		if (user == null) {
			send(exchange, 401, "Please login first.");
			return;
		}

		if (!"OWNER".equals(user.getRole()) && !"ADMIN".equals(user.getRole())) {
			AuditLog.record(user.getUsername(), "SHARE_DOCUMENT", "unknown", "DENIED");
			send(exchange, 403, "Permission denied.");
			return;
		}

		String contentType = exchange.getRequestHeaders().getFirst("Content-Type");

		if (contentType == null || !contentType.startsWith("application/x-www-form-urlencoded")) {
			send(exchange, 415, "Unsupported content type.");
			return;
		}

		byte[] body = exchange.getRequestBody().readNBytes(4097);

		if (body.length > 4096) {
			send(exchange, 413, "Request too large.");
			return;
		}

		Map<String, String> fields = parseForm(new String(body, StandardCharsets.UTF_8));

		String id = fields.getOrDefault("id", "").trim();
		String username = fields.getOrDefault("username", "").trim();

		if (id.isBlank() || !username.matches("[A-Za-z0-9._-]{3,30}")) {
			send(exchange, 400, "Invalid document ID or username.");
			return;
		}

		if (username.equals(user.getUsername())) {
			send(exchange, 400, "You already own this document.");
			return;
		}

		if (!userStore.userExists(username)) {
			send(exchange, 400, "Target user does not exist.");
			return;
		}

		try {
			documentStore.grantAccess(id, user.getUsername(), username);

			AuditLog.record(user.getUsername(), "SHARE_DOCUMENT", id, "SUCCESS");

			send(exchange, 200,
					"<h2>Document shared successfully!</h2>" + "<a href='/documents'>Back to Documents</a>");

		} catch (Exception e) {
			AuditLog.record(user.getUsername(), "SHARE_DOCUMENT", id, "FAILED");

			send(exchange, 400, "Could not share document. Check document ownership.");
		}
	}

	private static void handleRevokeDocument(HttpExchange exchange) throws IOException {

		User user = getLoggedInUser(exchange);

		if (user == null) {
			send(exchange, 401, "Please login first.");
			return;
		}

		if (!"OWNER".equals(user.getRole()) && !"ADMIN".equals(user.getRole())) {
			send(exchange, 403, "Permission denied.");
			return;
		}

		String contentType = exchange.getRequestHeaders().getFirst("Content-Type");

		if (contentType == null || !contentType.startsWith("application/x-www-form-urlencoded")) {
			send(exchange, 415, "Unsupported content type.");
			return;
		}

		byte[] body = exchange.getRequestBody().readNBytes(4097);

		if (body.length > 4096) {
			send(exchange, 413, "Request too large.");
			return;
		}

		Map<String, String> fields = parseForm(new String(body, StandardCharsets.UTF_8));

		String id = fields.getOrDefault("id", "").trim();
		String username = fields.getOrDefault("username", "").trim();

		if (id.isBlank() || !username.matches("[A-Za-z0-9._-]{3,30}")) {
			send(exchange, 400, "Invalid document ID or username.");
			return;
		}

		try {
			documentStore.revokeAccess(id, user.getUsername(), username);

			AuditLog.record(user.getUsername(), "REVOKE_ACCESS", id, "SUCCESS");

			send(exchange, 200, "<h2>Access revoked successfully!</h2>" + "<a href='/documents'>Back to Documents</a>");

		} catch (Exception e) {
			AuditLog.record(user.getUsername(), "REVOKE_ACCESS", id, "FAILED");

			send(exchange, 400, "Could not revoke access. Check ownership and username.");
		}
	}

}
