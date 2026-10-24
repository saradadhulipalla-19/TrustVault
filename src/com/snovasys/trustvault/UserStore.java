package com.snovasys.trustvault;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UserStore {

    private final Map<String, User> users =
            new ConcurrentHashMap<>();

    public UserStore() throws Exception {
        addDefaultUser("admin", "ADMIN", "TV_ADMIN_PASSWORD");
        addDefaultUser("owner", "OWNER", "TV_OWNER_PASSWORD");
        addDefaultUser("viewer", "VIEWER", "TV_VIEWER_PASSWORD");
    }

    private void addDefaultUser(
            String username, String role, String envName)
            throws Exception {

        String password = System.getenv(envName);

        if (password == null || password.length() < 12
                || password.length() > 128) {
            throw new IllegalStateException(
                    "Missing or invalid environment variable: " + envName);
        }

        byte[] salt = PasswordUtil.newSalt();
        byte[] hash = PasswordUtil.hashPassword(
                password.toCharArray(), salt);

        users.put(username,
                new User(username, role, salt, hash));
    }

    private void addUser(String username, String role,
                         String password) throws Exception {
        byte[] salt = PasswordUtil.newSalt();
        byte[] hash = PasswordUtil.hashPassword(
                password.toCharArray(), salt);

        users.put(username,
                new User(username, role, salt, hash));
    }


public User authenticate(String username, char[] password)
        throws Exception {

    User user = users.get(username);

    System.out.println("DEBUG usernameExists="
            + (user != null));

    if (user == null) {
        return null;
    }

    boolean passwordMatches = user.verifyPassword(password);

    System.out.println("DEBUG passwordMatches="
            + passwordMatches);

    return passwordMatches ? user : null;
}


public synchronized void registerViewer(
        String username, char[] password) throws Exception {

    if (username == null
            || !username.matches("[A-Za-z0-9._-]{3,30}")) {
        throw new IllegalArgumentException(
                "Username must be 3-30 valid characters.");
    }

    if (password == null || password.length < 12
            || password.length > 128) {
        throw new IllegalArgumentException(
                "Password must be 12-128 characters.");
    }

    if (users.containsKey(username)) {
        throw new IllegalArgumentException(
                "Username already exists.");
    }

    byte[] salt = PasswordUtil.newSalt();
    byte[] hash = PasswordUtil.hashPassword(password, salt);

    User newUser = new User(
            username, "VIEWER", salt, hash);

    if (users.putIfAbsent(username, newUser) != null) {
        throw new IllegalArgumentException(
                "Username already exists.");             
    }
}
public boolean userExists(String username) {
    return username != null
            && users.containsKey(username);
}
}
