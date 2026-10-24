TrustVault - Secure Document Management System

Project Overview

TrustVault is a secure document management system developed using Core Java. It helps users upload and manage PDF documents with authentication and access control.

Technologies Used

- Java 21
- Core Java
- Java HTTP Server
- HTML
- GitHub

Features

- User login and session authentication
- Secure document upload
- PDF-only file upload
- Maximum upload size of 5 MB
- Owner-only document download
- Logout and session invalidation
- Audit logging for important actions

Security Features

- Session-based authentication
- Access control for document downloads
- File type validation
- File size validation
- Audit logging

Project Structure

- "AuditLog.java" - Records important application activities.
- "DocumentStore.java" - Manages uploaded documents.
- "PasswordUtil.java" - Provides password-related utility functions.
- "TrustVaultServer.java" - Starts the application server.
- Security test files - Test security and authentication behavior.

How to Run

1. Install Java Development Kit (JDK) 21.
2. Open the project in Eclipse.
3. Check the "module-info.java" configuration, if present.
4. Run "TrustVaultServer.java".
5. Open the local address and port configured in the application in your browser.

Testing

Test login, logout, session authentication, PDF upload validation, file size limits, document access control, and audit logging.

Author

Sarada Dhulipalla
