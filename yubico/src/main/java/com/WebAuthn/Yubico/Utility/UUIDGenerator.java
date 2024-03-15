package com.WebAuthn.Yubico.Utility;

import java.util.UUID;

import org.springframework.stereotype.Service;

import com.yubico.webauthn.data.ByteArray;

// generates UUIDs for user ids
@Service
public class UUIDGenerator {
    private static final UUID uuid = UUID.randomUUID();

    public static String generateUUID() {
        return uuid.toString();
    }

    public static ByteArray generateUUIDByteArray() {
        return new ByteArray(uuid.toString().getBytes());
    }
}
