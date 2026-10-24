package com.snovasys.trustvault;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class UserStore {

    private final Map<String, User> users =
            new ConcurrentHashMap<>();

    public UserStore() throws Exception {
        addUser("admin", "ADMIN", "ChangeAdmin123!");
        addUser("owner", "OWNER", "ChangeOwner123!");
        addUser("viewer", "VIEWER", "ChangeViewer123!");
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

        if (user == null) {
            return null;
        }

        return user.verifyPassword(password) ? user : null;
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