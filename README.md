TrustVault – Secure Document Management System

Project Overview

TrustVault is a secure document management system developed using Core Java 21. It allows authenticated users to manage PDF documents with session-based authentication and access control.

Technologies Used

- Java 21
- Core Java
- Java HTTP Server ("com.sun.net.httpserver")
- HTML
- Git and GitHub
- Eclipse IDE

Features

- User login and session authentication
- Secure PDF document upload
- PDF-only file validation
- Maximum upload size of 5 MB
- Owner-only document download
- My Documents page
- Logout and session invalidation
- Audit logging for important application activities

Security Features

- Session-based authentication
- Authentication checks for protected endpoints
- Access control for document operations
- PDF extension and file signature validation
- Empty file rejection
- File size validation
- Session invalidation after logout
- Audit logging for important actions

Project Structure

- "TrustVaultServer.java" – Starts the HTTP server and handles application requests.
- "UserStore.java" – Manages user information and authentication.
- "User.java" – Represents a user and their role.
- "DocumentStore.java" – Manages uploaded documents.
- "PasswordUtil.java" – Provides password-related utility functions.
- "AuditLog.java" – Records important application activities.
- "TrustVaultHttpSecurityTest.java" – Tests HTTP authentication requirements.
- "TrustVaultLoginSessionTest.java" – Tests login, session handling, and logout.
- "TrustVaultSecurityTest.java" – Tests document validation and access control.
- "module-info.java" – Defines the Java module configuration.

How to Run

1. Install JDK 21.
2. Clone or download this repository.
3. Open the project in Eclipse IDE.
4. Confirm that "module-info.java" includes the required modules.
5. Run "TrustVaultServer.java" as a Java Application.
6. Open the local URL displayed in the Eclipse Console in your browser.

Testing

The following automated test checks have been executed:

Test Class                  | Passed| Failed
"TrustVaultHttpSecurityTest"| 4     | 0
"TrustVaultLoginSessionTest"| 5     | 0
"TrustVaultSecurityTest"    | 5     | 0
Total                       | 14    | 0

Additional manual checks confirmed PDF upload and download, rejection of non-PDF files, and redirection to the login page after logout.

These results describe the tests currently executed and do not guarantee that every possible security issue has been eliminated.

Limitations

- The application currently runs on a local development server.
- Production deployment and additional security testing may be required depending on the project requirements.

Author

Sarada Dhulipalla
