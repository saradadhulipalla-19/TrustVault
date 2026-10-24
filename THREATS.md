TrustVault Security Threat Model

1. Project Overview

TrustVault is a document management application developed using Core Java 21. It supports user authentication and PDF document management.

2. Assets to Protect

- User credentials
- Login sessions
- Uploaded PDF documents
- Document ownership information
- Audit log records

3. Potential Threats and Mitigations

Threat 1: Unauthorized Access

Risk: A person without permission may try to access private documents.

Mitigation: Authenticate users and verify authorization on the server before allowing document downloads.

Threat 2: Session Misuse

Risk: An attacker may try to reuse a session or access the application after logout.

Mitigation: Validate sessions on protected requests and invalidate the session during logout.

Threat 3: Malicious File Upload

Risk: A user may upload an unexpected file instead of a PDF.

Mitigation: Validate uploaded file types on the server. Do not rely only on the filename or browser-side validation.

Threat 4: Oversized File Upload

Risk: Very large uploads may consume excessive disk space or memory.

Mitigation: Enforce the 5 MB upload limit on the server before storing the file.

Threat 5: Document Ownership Bypass

Risk: A user may attempt to download another user's document by changing a document identifier.

Mitigation: Check document ownership and authorization on every download request.

Threat 6: Sensitive Audit Information

Risk: Audit logs may expose passwords, session identifiers, or other sensitive information.

Mitigation: Do not log passwords or session tokens. Restrict access to audit logs and record relevant security events.

4. Security Testing

Test the following cases:

- Invalid login attempts
- Access to protected pages without a valid session
- Access after logout
- Uploading non-PDF files
- Uploading files larger than 5 MB
- Attempting to download documents without authorization
- Checking audit logs for important security events

5. Limitations

The mitigations described above must be verified against the actual implementation and test results. This document does not claim that every security control has already passed testing.
