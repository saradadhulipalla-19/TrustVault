package com.snovasys.trustvault;

public class User {

    private final String username;
    private final String role;
    private final byte[] salt;
    private final byte[] passwordHash;

    public User(String username, String role,
                byte[] salt, byte[] passwordHash) {
        this.username = username;
        this.role = role;
        this.salt = salt.clone();
        this.passwordHash = passwordHash.clone();
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public boolean verifyPassword(char[] password)
            throws Exception {
        return PasswordUtil.verifyPassword(
                password, salt, passwordHash);
    }
}