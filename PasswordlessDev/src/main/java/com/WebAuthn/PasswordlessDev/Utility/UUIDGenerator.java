package com.WebAuthn.PasswordlessDev.Utility;

import java.util.UUID;

import org.springframework.stereotype.Service;

// generates UUIDs for user ids
@Service
public class UUIDGenerator {
    private static final UUID uuid = UUID.randomUUID();

    public static String generateUUID() {
        return uuid.toString();
    }
}
